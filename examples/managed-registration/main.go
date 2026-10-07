// This example creates and activates one sandbox identity on the hosted dev registry.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const entityKeyURL = "https://dnsid.dev.dnsid.ai/.well-known/dnsid-ek.json"

// Keep the original request, creation facts, and exact completed entry across retries.
// The private key lives in a separate file; the organization credential is never saved.
type state struct {
	RegistrationKey string                        `json:"registration_key"`
	IssuanceKey     string                        `json:"issuance_key"`
	Input           *dnsid.AgentRegistrationInput `json:"input"`
	Registration    *dnsid.AgentRegistration      `json:"registration,omitempty"`
	Creation        *dnsid.CreateAgentResponse    `json:"creation,omitempty"`
	Prepared        *dnsid.PreparedRegistryEvent  `json:"prepared,omitempty"`
	Entry           []byte                        `json:"entry,omitempty"`
	Submission      *dnsid.SubmissionResult       `json:"submission,omitempty"`
}

func main() {
	directory := flag.String("state-dir", "", "dedicated private directory for the key and recovery state (required)")
	keyFile := flag.String("api-key-file", "", "organization credential file; otherwise use DNSID_API_KEY")
	flag.Parse()
	if *directory == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	token := os.Getenv("DNSID_API_KEY")
	if *keyFile != "" {
		data, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot read API key file")
			os.Exit(1)
		}
		token = string(data)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := run(ctx, *directory, strings.TrimSpace(token)); err != nil {
		// Registry messages can contain workflow details; report only their status/code.
		var api *dnsid.RegistryAPIError
		if errors.As(err, &api) {
			fmt.Fprintf(os.Stderr, "registry failure: HTTP %d, code %s\n", api.StatusCode, api.Code)
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		fmt.Fprintln(os.Stderr, "Keep the state directory; rerun with the same directory to resume.")
		os.Exit(1)
	}
}

func run(ctx context.Context, directory, token string) error {
	if token == "" {
		return errors.New("set DNSID_API_KEY or pass -api-key-file")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Stat(directory)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be owner-only (chmod 700)")
	}
	// A single process owns recovery. After a hard crash, remove the stale lock only
	// after checking that no other copy of this example is running.
	lockPath := filepath.Join(directory, ".lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("cannot lock state directory: %w", err)
	}
	lock.Close()
	defer os.Remove(lockPath)

	s, provider, err := loadState(directory)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "recovery.json")
	registry, err := dnsid.NewRegistryClientWithOptions("https://api.dev.dnsid.ai", dnsid.WithAuthToken(token))
	if err != nil {
		return err
	}
	// This explicit factory selects reviewed dev log and witness keys bundled with
	// the SDK. Do not fetch trust policy from the registration or prepared event.
	logs, err := c2sptlog.NewDnsidManagedVerificationRegistry(ctx, c2sptlog.DnsidManagedVerificationConfig{})
	if err != nil {
		return err
	}
	entityKey, err := fetchEntityKey(ctx)
	if err != nil {
		return err
	}

	// 1. Register. Replaying the saved request/key also recovers a failed detail read.
	if s.Registration == nil {
		fmt.Println("Registering sandbox identity...")
		s.Registration, err = registry.RegisterAgent(ctx, s.Input, s.RegistrationKey)
		if err != nil {
			var recovery *dnsid.RegistrationError
			if errors.As(err, &recovery) {
				s.Creation = recovery.Creation
			}
		}
		if saveErr := saveState(path, s); saveErr != nil {
			return saveErr
		}
		if err != nil {
			return err
		}
	}
	r := s.Registration
	if r.PublicationAuthority != dnsid.PublicationAuthorityRegistry || r.PublicationConfig.GovernanceID != "dev.dnsid.ai" || r.PublicationConfig.EntityKeyURL != entityKeyURL || r.PublicationConfig.LogRef != "c2sp-tlog:public:https://log.dev.dnsid.ai#"+r.ID {
		return errors.New("unexpected registration authority or dev log binding")
	}
	fmt.Println("Identity:", r.Domain, "ID:", r.ID)
	reader, err := logs.NewReader(r.PublicationConfig.LogRef)
	if err != nil {
		return err
	}
	client, ok := reader.(*c2sptlog.Client)
	if !ok {
		return errors.New("no trusted dev log client")
	}

	// 2. Validate and countersign one ISSUANCE, then submit its saved exact bytes.
	if err := issue(ctx, registry, client, entityKey, provider, path, s); err != nil {
		return err
	}

	// 3. Wait for managed publication, then verify independently through public DNS.
	detail, err := registry.WaitForStatus(ctx, r.Domain, []string{"READY"}, nil)
	if err != nil {
		return err
	}
	if detail.ID != r.ID || !detail.DNSPublished {
		return errors.New("READY response did not confirm this identity's DNS publication")
	}
	verifier, err := dnsid.NewVerifier(dnsid.WithLogRegistry(logs))
	if err != nil {
		return err
	}
	return verify(ctx, verifier, r)
}

func issue(ctx context.Context, registry *dnsid.HTTPRegistryClient, client *c2sptlog.Client, entity jwk.Key, provider dnsid.KeyProvider, path string, s *state) error {
	r := s.Registration
	if len(s.Entry) == 0 {
		detail, err := registry.WaitForStatus(ctx, r.Domain, []string{"VERIFIED"}, nil)
		if err != nil {
			return err
		}
		if detail.ID != r.ID {
			return errors.New("identity instance changed")
		}
		if s.Prepared == nil {
			s.Prepared, err = registry.PrepareIssuance(ctx, r.Domain, s.IssuanceKey)
			if err != nil {
				return err
			}
			if err := saveState(path, s); err != nil {
				return err
			}
		}
		if s.Prepared.LogReference != r.PublicationConfig.LogRef {
			return errors.New("prepared log reference mismatch")
		}
		prepared, err := parseIssuance(client, s.Prepared.EntryBytes, r, entity, provider.JWK())
		if err != nil {
			return err
		}
		// The SDK checks the existing entity signature before adding ours.
		prepared, err = client.SignPreparedEvent(ctx, prepared, c2sptlog.SignerOperationalCountersignature, provider)
		if err != nil {
			return err
		}
		s.Entry, err = client.PreparedEntryBytes(ctx, prepared)
		if err != nil {
			return err
		}
		// Never submit before the completed bytes are durable. On rerun, do not re-sign.
		if err := saveState(path, s); err != nil {
			return err
		}
	}
	prepared, err := parseIssuance(client, s.Entry, r, entity, provider.JWK())
	if err != nil {
		return err
	}
	if _, err := client.PreparedEntryBytes(ctx, prepared); err != nil {
		return err
	}
	if s.Submission == nil || s.Submission.State != dnsid.SubmissionStateAccepted && s.Submission.State != dnsid.SubmissionStateRejected {
		s.Submission, err = registry.SubmitPreparedEvent(ctx, r.Domain, s.Entry, s.IssuanceKey)
		if err != nil {
			// A malformed success response also leaves the append outcome unknown.
			s.Submission = &dnsid.SubmissionResult{State: dnsid.SubmissionStateIndeterminate}
			var api *dnsid.RegistryAPIError
			if errors.As(err, &api) {
				s.Submission.State, s.Submission.ErrorCode = api.SubmissionState(), api.Code
			}
		}
		if saveErr := saveState(path, s); saveErr != nil {
			return saveErr
		}
		if err != nil {
			return err
		}
	}
	sum := sha256.Sum256(s.Entry)
	result := s.Submission
	if result == nil || result.State != dnsid.SubmissionStateAccepted || result.Index == nil || result.EntryHash != hex.EncodeToString(sum[:]) || result.LogRef != string(prepared.Reference().FinalEventRef(*result.Index)) {
		return errors.New("ISSUANCE not accepted with the expected hash and final reference; inspect recovery state")
	}
	fmt.Println("ISSUANCE accepted:", result.LogRef)
	return nil
}

func parseIssuance(client *c2sptlog.Client, entry []byte, r *dnsid.AgentRegistration, entity, operational jwk.Key) (*c2sptlog.PreparedEvent, error) {
	prepared, err := client.ParsePreparedEvent(entry)
	if err != nil {
		return nil, err
	}
	event, err := prepared.Event()
	if err != nil {
		return nil, err
	}
	if event.Type != dnsidlog.LogEventIssuance || event.Domain != r.Domain || event.GovernanceID != r.PublicationConfig.GovernanceID {
		return nil, errors.New("prepared ISSUANCE identity mismatch")
	}
	for _, pair := range [][2]jwk.Key{{entity, event.InitialEntityPublicKey}, {operational, event.InitialOperationalPublicKey}} {
		if pair[0] == nil || pair[1] == nil {
			return nil, errors.New("missing ISSUANCE key")
		}
		expected, err := pair[0].Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, err
		}
		actual, err := pair[1].Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(expected, actual) {
			return nil, errors.New("prepared ISSUANCE key mismatch")
		}
	}
	return prepared, nil
}

func verify(ctx context.Context, verifier *dnsid.IdentityManager, r *dnsid.AgentRegistration) error {
	// DNS may lag the management API. Retry public reads, never issuance writes.
	for {
		verified, err := verifier.VerifyDomain(ctx, r.Domain)
		if err == nil {
			if verified.Record().LogRef != r.PublicationConfig.LogRef || verified.Record().GovernanceID != r.PublicationConfig.GovernanceID || verified.Status().State != dnsid.AgentStateActive {
				return errors.New("published record is not the expected active identity")
			}
			_, err = verified.VerifyLogEvidence(ctx, time.Now())
			if err == nil {
				fmt.Printf("Verified: %s status=%s DNSSEC=%s\n", verified.Domain(), verified.Status().State, verified.DNSSECState())
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("public verification: %w", errors.Join(ctx.Err(), err))
		case <-time.After(5 * time.Second):
		}
	}
}

func loadState(directory string) (*state, *dnsid.LocalKeyProvider, error) {
	path := filepath.Join(directory, "recovery.json")
	keyPath := filepath.Join(directory, "operational-key.json")
	data, err := os.ReadFile(path)
	if err == nil {
		var s state
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, nil, err
		}
		if s.Input == nil || s.RegistrationKey == "" || s.IssuanceKey == "" {
			return nil, nil, errors.New("incomplete recovery state")
		}
		// Never replace a missing private key once a registration may exist.
		provider, err := dnsid.NewLocalKeyProvider(keyPath)
		return &s, provider, err
	}
	if !os.IsNotExist(err) {
		return nil, nil, err
	}
	provider, err := dnsid.LoadOrCreateLocalKeyProvider(keyPath, dnsid.JoseAlgEdDSA)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	id := hex.EncodeToString(nonce)
	s := &state{RegistrationKey: "go-example-register-" + id, IssuanceKey: "go-example-issuance-" + id,
		Input: &dnsid.AgentRegistrationInput{Name: "Go SDK managed registration example", PublicKeyJWK: provider.JWK()}}
	return s, provider, saveState(path, s)
}

func saveState(path string, s *state) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func fetchEntityKey(ctx context.Context) (jwk.Key, error) {
	// Bootstrap from this fixed, independently selected HTTPS endpoint, not a URL
	// supplied in an untrusted prepared event. Reject redirects and bound the body.
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("entity JWKS redirect rejected") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, entityKeyURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("entity JWKS HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("entity JWKS exceeds 1 MiB")
	}
	keys, err := dnsid.ParseJWKS(data)
	if err != nil {
		return nil, err
	}
	key, err := keys.CurrentRecordSigningKey(dnsid.DefaultPublishProfile)
	if err != nil {
		return nil, err
	}
	return key.Raw(), nil
}
