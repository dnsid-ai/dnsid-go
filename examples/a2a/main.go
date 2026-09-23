package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/httpsig"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

const (
	a2aVersion    = "1.0"
	extensionURI  = "https://example-provider.example/a2a/extensions/dnsid-http-message-signatures/v1"
	signatureTag  = "a2a-dnsid-http-sig-v1"
	agentCardPath = "/.well-known/agent-card.json"
)

var requiredComponents = []string{
	"@method",
	"@target-uri",
	"content-type",
	"content-digest",
	"a2a-version",
	"a2a-extensions",
}

type application struct {
	identity   *dnsid.IdentityManager
	signatures *httpsig.Profile
	httpClient *http.Client
	card       map[string]any
	publicURL  string
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Method  string `json:"method"`
	Params  struct {
		Message message `json:"message"`
	} `json:"params"`
}

type message struct {
	MessageID string `json:"messageId"`
	ContextID string `json:"contextId,omitempty"`
	Role      string `json:"role"`
	Parts     []part `json:"parts"`
}

type part struct {
	Text      string `json:"text"`
	MediaType string `json:"mediaType,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "a2a:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app, port, err := newApplication(ctx)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	fmt.Printf("%s -> %s\n", app.identity.Domain(), app.publicURL)

	// Verification succeeds once the testnet has published this agent's DNS
	// record, JWKS, status document, and lifecycle-log entry.
	if err := poll(ctx, "self-verify "+app.identity.Domain(), func() error {
		_, err := app.identity.VerifyDomain(ctx, app.identity.Domain())
		return err
	}); err != nil {
		return err
	}

	// An argument switches the process into client mode after its server starts.
	if len(os.Args) > 1 {
		err = app.sendHello(ctx, os.Args[1])
		_ = server.Shutdown(context.Background())
		return err
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func newApplication(ctx context.Context) (*application, int, error) {
	port, err := strconv.Atoi(os.Getenv("DNSID_AGENT_PORT"))
	if err != nil || port < 1 {
		return nil, 0, fmt.Errorf("DNSID_AGENT_PORT is required; run with `dnsid testnet run`")
	}

	// The local testnet supplies its own DNS server and CA; the same transport
	// config drives DNS, HTTPS fetches, log reads, and the outbound A2A client.
	// Production applications leave it zero for SDK defaults.
	envConfig, err := dnsid.ConfigFromEnv()
	if err != nil {
		return nil, 0, err
	}
	transport := envConfig.Transport
	policyURL := os.Getenv("DNSID_LOG_POLICY_URL")
	if policyURL == "" {
		return nil, 0, fmt.Errorf("DNSID_LOG_POLICY_URL is required; run with `dnsid testnet run`")
	}
	logRegistry, err := c2sptlog.NewVerificationRegistry(ctx, c2sptlog.VerificationRegistryConfig{
		PolicyURL: policyURL,
		Transport: transport,
	})
	if err != nil {
		return nil, 0, err
	}
	identity, err := dnsid.NewIdentityManagerFromDnsid(
		"",
		dnsid.Config{Transport: transport},
		dnsid.WithLogRegistry(logRegistry),
	)
	if err != nil {
		return nil, 0, err
	}
	httpClient, err := dnsid.CreateDnsidHTTPClient(transport)
	if err != nil {
		return nil, 0, err
	}

	publicURL := "https://" + identity.Domain()
	card, err := signedAgentCard(identity, publicURL)
	if err != nil {
		return nil, 0, err
	}

	return &application{
		identity:   identity,
		signatures: httpsig.NewFromIdentityManagerKeyProvider(identity, httpsig.Config{}),
		httpClient: httpClient,
		card:       card,
		publicURL:  publicURL,
	}, port, nil
}

func (a *application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+agentCardPath, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, a.card)
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, a.identity.GetKeySet().Raw())
	})
	mux.HandleFunc("GET /.well-known/status.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, dnsid.AgentStatus{
			State:            dnsid.AgentStateActive,
			LastTransitionAt: time.Now().UTC(),
		})
	})
	mux.HandleFunc("POST /", a.handleMessage)
	return mux
}

func (a *application) handleMessage(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("A2A-Version") != a2aVersion {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "A2A-Version must be " + a2aVersion})
		return
	}
	if !containsCSV(req.Header.Get("A2A-Extensions"), extensionURI) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "A2A-Extensions must include " + extensionURI})
		return
	}
	if err := requireSignatureProfile(req); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	// The testnet proxy forwards plain HTTP to this process. Restore the public
	// URL before verifying the signature, since @target-uri covered the HTTPS URL.
	publicRequest := req.Clone(req.Context())
	publicRequest.URL.Scheme = "https"
	publicRequest.URL.Host = a.identity.Domain()
	publicRequest.Host = a.identity.Domain()

	verifiedSender, err := a.signatures.VerifyHTTPRequest(req.Context(), publicRequest)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	var rpc rpcRequest
	if err := json.NewDecoder(publicRequest.Body).Decode(&rpc); err != nil || rpc.JSONRPC != "2.0" || rpc.Method != "SendMessage" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid A2A SendMessage request"})
		return
	}

	text := messageText(rpc.Params.Message)
	fmt.Printf("[%s] verified message from %s: %q\n", a.identity.Domain(), verifiedSender.Domain(), text)
	reply := fmt.Sprintf("[from: %s; verified sender: %s] %s", a.identity.Domain(), verifiedSender.Domain(), text)
	writeJSON(w, http.StatusOK, map[string]any{
		"jsonrpc": "2.0",
		"id":      rpc.ID,
		"result": map[string]any{
			"message": message{
				MessageID: randomID(),
				Role:      "ROLE_AGENT",
				Parts:     []part{{Text: reply, MediaType: "text/plain"}},
			},
		},
	})
}

// requireSignatureProfile checks the A2A extension's requirements that are
// stricter than the generic HTTP Message Signatures profile.
func requireSignatureProfile(req *http.Request) error {
	inputs, err := httpsig.ParseSignatureInput(req.Header.Get("Signature-Input"))
	if err != nil {
		return err
	}
	if len(inputs) != 1 {
		return errors.New("exactly one HTTP signature is required")
	}

	params, ok := inputs["a2a"]
	if !ok || params.Tag != signatureTag || params.Expires == 0 {
		return errors.New("required A2A HTTP signature parameters are missing")
	}

	covered := make(map[string]bool, len(params.Components))
	for _, component := range params.Components {
		covered[component.Name] = true
	}
	for _, component := range requiredComponents {
		if !covered[component] {
			return fmt.Errorf("HTTP signature does not cover %s", component)
		}
	}
	return nil
}

func (a *application) sendHello(ctx context.Context, peer string) error {
	if err := poll(ctx, "verify "+peer, func() error {
		_, err := a.identity.VerifyDomain(ctx, peer)
		return err
	}); err != nil {
		return err
	}
	fmt.Printf("verified: %s -> %s\n\n", a.identity.Domain(), peer)

	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      randomID(),
		"method":  "SendMessage",
		"params": map[string]any{
			"tenant": "",
			"message": message{
				MessageID: randomID(),
				Role:      "ROLE_USER",
				Parts: []part{{
					Text:      "hello from " + a.identity.Domain(),
					MediaType: "text/plain",
				}},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+peer+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("A2A-Version", a2aVersion)
	req.Header.Set("A2A-Extensions", extensionURI)

	// The signing client adds Content-Digest, Signature-Input, and Signature.
	client := a.signatures.CreateSignedHTTPClient(a.httpClient, httpsig.SigningOptions{
		Label:                "a2a",
		ExpiresIn:            5 * time.Minute,
		Tag:                  signatureTag,
		AdditionalComponents: []string{"content-type", "a2a-version", "a2a-extensions"},
	})
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("peer returned HTTP %s: %s", resp.Status, responseBody)
	}

	var response struct {
		Result struct {
			Message message `json:"message"`
		} `json:"result"`
		Error any `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return err
	}
	if response.Error != nil {
		return fmt.Errorf("peer returned A2A error: %v", response.Error)
	}
	fmt.Printf("reply: %q\n", messageText(response.Result.Message))
	return nil
}

func poll(ctx context.Context, label string, fn func() error) error {
	var lastError error
	for range 60 {
		if err := fn(); err == nil {
			return nil
		} else {
			lastError = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("%s failed: %w", label, lastError)
}

func containsCSV(value, target string) bool {
	for item := range strings.SplitSeq(value, ",") {
		if strings.TrimSpace(item) == target {
			return true
		}
	}
	return false
}

func messageText(msg message) string {
	var text strings.Builder
	for _, part := range msg.Parts {
		text.WriteString(part.Text)
	}
	return text.String()
}

func randomID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(value[:])
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
