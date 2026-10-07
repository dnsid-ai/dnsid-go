// Register, issue, publish, and independently verify one managed dev identity.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"unicode"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const registryURL = "https://api.dev.dnsid.ai"
const governanceID = "dev.dnsid.ai"
const entityKeyURL = "https://dnsid.dev.dnsid.ai/.well-known/dnsid-ek.json"

// Credentials and the private operational key never enter recovery.json.
type state struct {
	RegistryURL     string                         `json:"registry_url"`
	RegistrationKey string                         `json:"registration_key"`
	IssuanceKey     string                         `json:"issuance_key"`
	Input           *dnsid.AgentRegistrationInput  `json:"input"`
	Registration    *dnsid.AgentRegistration       `json:"registration,omitempty"`
	Creation        *dnsid.CreateAgentResponse     `json:"creation,omitempty"`
	EntityKey       json.RawMessage                `json:"entity_key,omitempty"`
	Issuance        *c2sptlog.ManagedIssuanceState `json:"issuance,omitempty"`
	// Retained only to import recovery from the original example.
	Prepared   *dnsid.PreparedRegistryEvent `json:"prepared,omitempty"`
	Entry      []byte                       `json:"entry,omitempty"`
	Submission *dnsid.SubmissionResult      `json:"submission,omitempty"`
}

func main() {
	directory := flag.String("state-dir", "", "dedicated private state directory (required)")
	keyFile := flag.String("api-key-file", "", "API token file; otherwise use DNSID_API_KEY")
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
	token = strings.TrimSpace(token)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := run(ctx, *directory, token); err != nil {
		message := err.Error()
		if token != "" {
			message = strings.ReplaceAll(message, token, "[REDACTED]")
		}
		fmt.Fprintln(os.Stderr, message)
		fmt.Fprintln(os.Stderr, "Keep the state directory; rerun with the same directory to resume.")
		os.Exit(1)
	}
}

func run(ctx context.Context, directory, token string) error {
	if token == "" || strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return errors.New("provide one API token through DNSID_API_KEY or --api-key-file")
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
	if s.RegistryURL == "" {
		s.RegistryURL = registryURL
	}
	if s.RegistryURL != registryURL {
		return errors.New("recovery state belongs to another registry")
	}
	requestKey, err := json.Marshal(s.Input.PublicKeyJWK)
	if err != nil {
		return err
	}
	original, err := jwk.ParseKey(requestKey)
	if err != nil {
		return err
	}
	originalPin, err := original.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	operationalPin, err := provider.JWK().Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	if !bytes.Equal(originalPin, operationalPin) {
		return errors.New("saved registration and operational key do not match")
	}
	if err := saveState(path, s); err != nil {
		return err
	}

	getenv := func(name string) string {
		if name == "DNSID_API_KEY" {
			return token
		}
		if name == "DNSID_REGISTRY_URL" && os.Getenv(name) == "" {
			return registryURL
		}
		return os.Getenv(name)
	}
	loaded, err := config.LoadEnvironment(getenv)
	if err != nil {
		return err
	}
	if loaded.Registry.RegistryURL != registryURL {
		return errors.New("this example supports only the dev registry")
	}
	loaded.Dnsid.Identity = nil
	loaded.KeySource = config.KeySource{}
	loaded.LogTrust = config.LogTrust{Managed: true}
	registry, err := config.RegistryClientFromEnvironment(getenv)
	if err != nil {
		return err
	}
	if s.Registration == nil {
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
	p := r.PublicationConfig
	if r.PublicationAuthority != dnsid.PublicationAuthorityRegistry || !strings.HasSuffix(r.Domain, ".sandbox.dev.dnsid.ai") || p.GovernanceID != governanceID || p.EntityKeyURL != entityKeyURL || p.LogRef != "c2sp-tlog:public:https://log.dev.dnsid.ai#"+r.ID {
		return errors.New("unexpected registration authority or dev sandbox binding")
	}
	fmt.Println("Registered:", r.Domain)
	current, err := registry.WaitForStatus(ctx, r.Domain, []string{"VERIFIED", "READY"}, nil)
	if err != nil {
		return err
	}
	if current.ID != r.ID {
		return errors.New("identity instance changed")
	}
	var entity jwk.Key
	if len(s.EntityKey) == 0 {
		entity, err = fetchEntityKey(ctx)
		if err != nil {
			return err
		}
		s.EntityKey, err = json.Marshal(entity)
		if err != nil {
			return err
		}
		if err := saveState(path, s); err != nil {
			return err
		}
	} else {
		entity, err = jwk.ParseKey(s.EntityKey)
		if err != nil {
			return err
		}
	}
	entityPin, err := entity.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	loaded.Dnsid.Verification.TrustedEntities = []dnsid.TrustedEntity{{GovernanceID: governanceID, EntityKeyThumbprints: []string{base64.RawURLEncoding.EncodeToString(entityPin)}}}
	local := config.Merge(loaded, config.Loaded{Dnsid: dnsid.Config{Identity: &dnsid.IdentityConfig{
		Domain: r.Domain, GovernanceID: p.GovernanceID, LogRef: p.LogRef, StatusURL: p.StatusURL,
		KeyURL: p.KeyURL, EntityKeyURL: p.EntityKeyURL, PublishProfile: p.PublishProfile,
		CapabilitiesURL: p.CapabilitiesURL, MaxKeyAge: dnsid.KeyAge(p.MaxKeyAge),
	}}})
	manager, err := config.Construct(ctx, local, config.Dependencies{KeyProvider: provider})
	if err != nil {
		return err
	}
	// Import the original exact bytes/outcome without a second submission.
	if s.Issuance == nil && len(s.Entry) != 0 {
		kid, _ := provider.JWK().KeyID()
		sum := sha256.Sum256(s.Entry)
		s.Issuance = &c2sptlog.ManagedIssuanceState{
			Domain: r.Domain, GovernanceID: governanceID, LogReference: p.LogRef, IdempotencyKey: s.IssuanceKey,
			EntityThumbprint:      base64.RawURLEncoding.EncodeToString(entityPin),
			OperationalThumbprint: base64.RawURLEncoding.EncodeToString(operationalPin), OperationalKid: kid,
			EntryBytes: s.Entry, EntryHash: hex.EncodeToString(sum[:]), Submission: s.Submission, ActivationBlocked: true,
		}
		if err := saveState(path, s); err != nil {
			return err
		}
	}
	client, err := c2sptlog.New(p.LogRef)
	if err != nil {
		return err
	}
	store := &issuanceStore{path: path, state: s}
	// This CLI serves no application. The durable activation block gates setup
	// completion; registry publication is observed, not controlled by this CLI.
	activation := c2sptlog.ManagedIssuanceActivationControllerFunc(func(context.Context, bool) error { return nil })
	var issuance *c2sptlog.ManagedIssuanceState
	if s.Issuance == nil {
		issuance, err = c2sptlog.BeginManagedIssuance(ctx, c2sptlog.ManagedIssuanceOptions{
			Domain: r.Domain, GovernanceID: governanceID, Client: client, IdempotencyKey: s.IssuanceKey,
			EntityPublicKey: entity, KeyProvider: provider, RegistryClient: registry, Store: store, ActivationControl: activation,
		})
	} else {
		issuance, err = c2sptlog.ResumeManagedIssuance(ctx, c2sptlog.ResumeManagedIssuanceOptions{
			Domain: r.Domain, Client: client, EntityPublicKey: entity, KeyProvider: provider,
			RegistryClient: registry, Store: store, ActivationControl: activation,
		})
	}
	if err != nil {
		return err
	}
	if issuance.Submission == nil || issuance.Submission.State != dnsid.SubmissionStateAccepted {
		return errors.New("issuance pending; rerun with the same state directory")
	}
	if err := retryRead(ctx, func() error { _, err := manager.AwaitRegistryManagedPublication(ctx, registry, nil); return err }); err != nil {
		return err
	}
	// A fresh verifier has no local identity, private key, or owner credential.
	verifier, err := config.Construct(ctx, loaded, config.Dependencies{})
	if err != nil {
		return err
	}
	return retryRead(ctx, func() error {
		verified, err := verifier.VerifyDomain(ctx, r.Domain)
		if err != nil {
			return err
		}
		if verified.Record().LogRef != p.LogRef || verified.Status().State != dnsid.AgentStateActive {
			return errors.New("published identity is not the expected active instance")
		}
		if _, err := verified.VerifyLogEvidence(ctx, time.Now()); err != nil {
			return err
		}
		if !issuance.Complete {
			if _, err := c2sptlog.CompleteManagedIssuance(ctx, r.Domain, store, activation); err != nil {
				return err
			}
		}
		fmt.Printf("Verified: %s status=ACTIVE DNSSEC=%s\n", verified.Domain(), verified.DNSSECState())
		return nil
	})
}

func retryRead(ctx context.Context, read func() error) error {
	for {
		err := read()
		if err == nil {
			return nil
		}
		var verification *dnsid.VerificationError
		if !errors.As(err, &verification) || (!verification.Transient() && verification.Code() != dnsid.VerificationCodeDNSResolution) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), err)
		case <-time.After(5 * time.Second):
		}
	}
}

// The directory lock makes this store exclusive; all transitions use atomic writes.
type issuanceStore struct {
	path  string
	state *state
}

func (s *issuanceStore) CreateManagedIssuance(ctx context.Context, initial *c2sptlog.ManagedIssuanceState) (*c2sptlog.ManagedIssuanceState, error) {
	if s.state.Issuance != nil {
		return s.state.Issuance, nil
	}
	return nil, s.PersistManagedIssuance(ctx, initial)
}

func (s *issuanceStore) LoadManagedIssuance(_ context.Context, domain string) (*c2sptlog.ManagedIssuanceState, error) {
	if s.state.Issuance != nil && s.state.Issuance.Domain != domain {
		return nil, errors.New("saved issuance domain changed")
	}
	return s.state.Issuance, nil
}

func (s *issuanceStore) PersistManagedIssuance(_ context.Context, issuance *c2sptlog.ManagedIssuanceState) error {
	s.state.Issuance = issuance
	s.state.Prepared, s.state.Entry, s.state.Submission = nil, nil, nil
	return saveState(s.path, s.state)
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
		Input: &dnsid.AgentRegistrationInput{Environment: "sandbox", PublicKeyJWK: provider.JWK()}}
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
	data, err := io.ReadAll(io.LimitReader(response.Body, 65_537))
	if err != nil {
		return nil, err
	}
	if len(data) > 65_536 {
		return nil, errors.New("entity JWKS exceeds 64 KiB")
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
