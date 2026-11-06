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
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/httpsig"
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
	return runWithDependencies(config.Dependencies{})
}

// handlerSlot publishes only fully initialized handlers. Holding the read lock
// through dispatch also lets shutdown drain requests before closing custody.
type handlerSlot struct {
	sync.RWMutex
	handler http.Handler
}

func (s *handlerSlot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.RLock()
	defer s.RUnlock()
	s.handler.ServeHTTP(w, r)
}

func runWithDependencies(deps config.Dependencies) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	loaded, port, err := loadApplicationConfig()
	if err != nil {
		return err
	}
	// Injection supplies only public setup material, never an application signer.
	provider, err := config.OperationalKeyProviderFrom(ctx, loaded.KeySource, loaded.Dnsid.Identity.Domain)
	if err != nil {
		return err
	}
	defer closeProvider(provider)
	setupDeps := deps
	setupDeps.KeyProvider = provider
	setup, err := config.Construct(ctx, loaded, setupDeps)
	if err != nil {
		return err
	}
	bootstrap := http.NewServeMux()
	bootstrap.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, setup.GetKeySet().Raw())
	})
	bootstrap.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "identity publication is not ready", http.StatusServiceUnavailable)
	})
	slot := &handlerSlot{handler: bootstrap}
	server := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           slot,
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	// Drain handlers before closing either caller-owned provider on every return.
	var authenticated dnsid.KeyProvider
	defer func() {
		cancel()
		shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
		}
		slot.Lock()
		defer slot.Unlock()
		closeProvider(authenticated)
	}()
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe(); cancel() }()
	var identity *dnsid.IdentityManager
	// Never inject operational custody here: retain Construct's fresh publication
	// verification AND selected kid, algorithm and thumbprint binding.
	deps.KeyProvider = nil
	err = poll(ctx, "self-publication "+setup.Domain(), func() error {
		var err error
		identity, err = config.Construct(ctx, loaded, deps)
		return err
	})
	if err != nil {
		select {
		case serveErr := <-errCh:
			if !errors.Is(serveErr, http.ErrServerClosed) {
				return serveErr
			}
		default:
		}
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	authenticated = identity.KeyProvider()
	if err := ctx.Err(); err != nil {
		return err
	}
	app, err := applicationFromIdentity(loaded, identity)
	if err != nil {
		return err
	}
	handler := app.publicRequests(app.signatures.ResponseSigningMiddleware(app.routes()))
	slot.Lock()
	slot.handler = handler
	slot.Unlock()
	fmt.Printf("%s -> %s\n", app.identity.Domain(), app.publicURL)
	if len(os.Args) > 1 {
		return app.sendHello(ctx, os.Args[1])
	}
	select {
	case <-ctx.Done():
		select {
		case err := <-errCh:
			if !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		default:
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func closeProvider(provider dnsid.KeyProvider) {
	if closer, ok := provider.(io.Closer); ok {
		_ = closer.Close()
	}
}

func loadApplicationConfig() (config.Loaded, int, error) {
	port, err := strconv.Atoi(os.Getenv("DNSID_AGENT_PORT"))
	if err != nil || port < 1 || port > 65535 {
		return config.Loaded{}, 0, fmt.Errorf("DNSID_AGENT_PORT is required; run with `dnsid local run`")
	}
	// Local run supplies identity, custody, explicit log trust, DNS and CA.
	loaded, err := config.LoadEnvironment(nil)
	if err != nil {
		return loaded, 0, err
	}
	if err := loaded.Dnsid.Validate(); err != nil {
		return loaded, 0, err
	}
	if loaded.Dnsid.Identity == nil {
		return loaded, 0, fmt.Errorf("A2A requires a local identity; run with `dnsid local run`")
	}
	return loaded, port, nil
}

func newApplication(ctx context.Context) (*application, int, error) {
	return newApplicationWithDependencies(ctx, config.Dependencies{})
}

func newApplicationWithDependencies(ctx context.Context, deps config.Dependencies) (*application, int, error) {
	loaded, port, err := loadApplicationConfig()
	if err != nil {
		return nil, 0, err
	}
	identity, err := config.Construct(ctx, loaded, deps)
	if err != nil {
		return nil, 0, err
	}
	app, err := applicationFromIdentity(loaded, identity)
	if err != nil {
		if deps.KeyProvider == nil {
			closeProvider(identity.KeyProvider())
		}
		return nil, 0, err
	}
	return app, port, nil
}

func applicationFromIdentity(loaded config.Loaded, identity *dnsid.IdentityManager) (*application, error) {
	httpClient, err := dnsid.CreateDnsidHTTPClient(loaded.Dnsid.Transport)
	if err != nil {
		return nil, err
	}
	publicURL := "https://" + identity.Domain()
	card, err := signedAgentCard(identity, publicURL)
	if err != nil {
		return nil, err
	}
	return &application{
		identity:   identity,
		signatures: httpsig.NewFromIdentityManagerKeyProvider(identity, httpsig.Config{}),
		httpClient: httpClient,
		card:       card,
		publicURL:  publicURL,
	}, nil
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

// publicRequests restores the public URL before request verification and
// response signing. The testnet proxy forwards plain HTTP to this process, but
// @target-uri and @authority cover the public HTTPS URL.
func (a *application) publicRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = a.identity.Domain()
		req.Host = a.identity.Domain()
		next.ServeHTTP(w, req)
	})
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

	verifiedSender, err := a.signatures.VerifyHTTPRequest(req.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	var rpc rpcRequest
	if err := json.NewDecoder(req.Body).Decode(&rpc); err != nil || rpc.JSONRPC != "2.0" || rpc.Method != "SendMessage" {
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
	peer, err := dnsid.NormalizeFQDN(peer)
	if err != nil {
		return err
	}
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+peer+"/", bytes.NewReader(body)) // #nosec G704 -- peer is a normalized, verified domain; the client uses the SDK safe dialer.
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("A2A-Version", a2aVersion)
	req.Header.Set("A2A-Extensions", extensionURI)

	// The signing client adds Content-Digest, Signature-Input, and Signature.
	// ResponseSignature also requires Bob to sign the response with peer's DNSid
	// key; the client rejects any response, including errors, that does not verify.
	client := a.signatures.CreateSignedHTTPClient(a.httpClient, httpsig.SigningOptions{
		Label:                "a2a",
		ExpiresIn:            5 * time.Minute,
		Tag:                  signatureTag,
		AdditionalComponents: []string{"content-type", "a2a-version", "a2a-extensions"},
		ResponseSignature: &httpsig.ResponseSignatureOptions{
			ExpectedDomain:       peer,
			AdditionalComponents: []httpsig.ComponentIdentifier{{Name: "content-type"}},
		},
	})
	resp, err := client.Do(req) // #nosec G704 -- CreateDnsidHTTPClient validates resolved IPs and rejects redirects; only configured testnet hosts can use private IPs.
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
	fmt.Printf("response signed by: %s\n", peer)
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
