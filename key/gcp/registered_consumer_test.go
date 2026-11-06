package gcpkms_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/jose"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// External-package analogues: jose/testManagersWithVerification and
// httpsig/testManagersWithPolicy. Only publication DNS/HTTP/status/log transports
// are fixtures; real managers parse and verify owner-signed records and JWKS.
// Contract: compliance 3e5d4d7, SDK design 01 KeyProvider and 12 key selection;
// Go reference key-gcp/config/jose. No durable rotation orchestration is claimed.

type consumerKMS struct {
	kmspb.UnimplementedKeyManagementServiceServer
	t       *testing.T
	keys    *lifecycleKMS
	mode    string
	creates atomic.Int32
}

func (s *consumerKMS) GetPublicKey(ctx context.Context, r *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	if r.GetName() == successorVersion && s.creates.Load() > 0 {
		if s.mode == "read denied" {
			return nil, status.Error(codes.PermissionDenied, "fixture successor read denied")
		}
		if s.mode == "invalid successor" {
			result, err := s.keys.GetPublicKey(ctx, r)
			if err != nil {
				return nil, err
			}
			result.PemCrc32C.Value++
			return result, nil
		}
	}
	return s.keys.GetPublicKey(ctx, r)
}
func (s *consumerKMS) AsymmetricSign(_ context.Context, r *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	var key ed25519.PrivateKey
	switch r.GetName() {
	case version:
		key = s.keys.private
	case successorVersion:
		key = s.keys.successor
	default:
		return nil, status.Error(codes.NotFound, "unknown version")
	}
	if r.GetDigest() != nil || r.GetDataCrc32C() == nil || r.GetDataCrc32C().Value != checksum(r.GetData()).Value {
		s.t.Error("sign must use RAW bytes with CRC32C")
		return nil, status.Error(codes.InvalidArgument, "RAW integrity")
	}
	sig := ed25519.Sign(key, r.GetData())
	return &kmspb.AsymmetricSignResponse{Name: r.GetName(), Signature: sig, SignatureCrc32C: checksum(sig), VerifiedDataCrc32C: true, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}
func (s *consumerKMS) CreateCryptoKeyVersion(ctx context.Context, r *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	s.creates.Add(1)
	if s.mode == "create denied" {
		return nil, status.Error(codes.PermissionDenied, "fixture creation denied")
	}
	return s.keys.CreateCryptoKeyVersion(ctx, r)
}

type consumerDNS struct{ record string }

func (d consumerDNS) FetchTXT(_ context.Context, name string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	if name != "_dnsid.agent.example.com" {
		return nil, dnsid.DNSSECStateUnsigned, errors.New("unexpected DNS name")
	}
	return []dnsid.TXTRecordRData{{Value: d.record, TTL: time.Minute}}, dnsid.DNSSECStateUnsigned, nil
}

type consumerHTTP map[string]json.RawMessage

func (f consumerHTTP) FetchJSON(_ context.Context, url string, _ dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	b, ok := f[url]
	if !ok {
		return nil, nil, errors.New("unexpected publication URL: " + url)
	}
	return b, nil, nil
}

type consumerLog struct{}

func (*consumerLog) Canonical(dnsidlog.LogEvent) ([]byte, error) { return nil, nil }
func (*consumerLog) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now(), nil
}
func (*consumerLog) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{}, nil
}
func (*consumerLog) VerifyOperationalContinuity(context.Context, string, string, string) error {
	return nil
}
func (*consumerLog) VerifyGovernanceRelationship(context.Context, string, string) error { return nil }
func (r *consumerLog) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	return dnsidlog.LoggedStateEvidence{}, nil
}
func (*consumerLog) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (*consumerLog) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	return nil, nil
}

func consumerManager(t *testing.T, ref string, deps config.Dependencies) *dnsid.IdentityManager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deployment.json")
	document := `{"dnsid":{"identity":{"domain":"agent.example.com","governanceId":"example.com","logRef":"algorand:ADDR","statusUrl":"https://agent.example.com/status.json","keyUrl":"https://agent.example.com/ku.json","entityKeyUrl":"https://example.com/ek.json","policyFlags":["logchk"]}},"keySource":{"provider":"google-kms","keyRef":"` + ref + `","settings":{"project":"test-project","location":"global","algorithm":"EdDSA"}}}`
	if err := os.WriteFile(path, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.LoadDeploymentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Only entity custody is injected; operational provider MUST come from init's factory.
	deps.EntityKeyProvider = dnsid.GenerateES256KeyProvider()
	m, err := config.Construct(context.Background(), loaded, deps)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := m.KeyProvider().(*gcpkms.Provider)
	if !ok {
		t.Fatalf("registered factory returned %T", m.KeyProvider())
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return m
}
func publication(t *testing.T, m *dnsid.IdentityManager) (config.Dependencies, *consumerLog) {
	t.Helper()
	record, err := m.CreateTXTRecord()
	if err != nil {
		t.Fatal(err)
	}
	marshal := func(v any) json.RawMessage {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	reader := &consumerLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("algorand", func(string) dnsidlog.LogReader { return reader }); err != nil {
		t.Fatal(err)
	}
	return config.Dependencies{DNSResolver: consumerDNS{record.Serialize()}, HTTPSFetcher: consumerHTTP{record.KeyURI: marshal(m.GetKeySet().Raw()), record.EntityKeyURI: marshal(m.GetEntityKeySet().Raw()), record.StatusURI: json.RawMessage(`{"state":"ACTIVE","lastTransitionAt":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`)}, LogRegistry: registry}, reader
}
func publicationVerifier(t *testing.T, deps config.Dependencies) *jose.Profile {
	t.Helper()
	m, err := config.Construct(context.Background(), config.Loaded{}, deps)
	if err != nil {
		t.Fatal(err)
	}
	return jose.NewFromIdentityManagerKeyProvider(m, jose.Config{})
}
func runRegisteredConsumer(t *testing.T) {
	// Given independent publication A, verify via real record/JWKS/profile processing.
	a := consumerManager(t, version, config.Dependencies{})
	signer := jose.NewFromIdentityManagerKeyProvider(a, jose.Config{})
	deps, _ := publication(t, a)
	verifier := publicationVerifier(t, deps)
	localA := consumerManager(t, version, deps)
	published, err := localA.VerifyLocalPublication(context.Background())
	if err != nil || published == nil {
		t.Fatalf("matching local publication: %v %v", published, err)
	}
	payload := []byte("opaque consumer payload\x00\xff")
	token, err := signer.CreateJWS(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, vd, err := verifier.VerifyJWS(context.Background(), token)
	if err != nil || vd == nil || vd.Domain() != a.Domain() || !bytes.Equal(got, payload) {
		t.Fatalf("matching publication: %x %v %v", got, vd, err)
	}
	parts := strings.Split(token, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte("tampered"))
	if _, _, err := verifier.VerifyJWS(context.Background(), strings.Join(parts, ".")); err == nil {
		t.Fatal("tampered payload accepted")
	} else {
		var verification *dnsid.VerificationError
		if !errors.As(err, &verification) || verification.Code() != dnsid.VerificationCodeSignatureInvalid {
			t.Fatalf("tamper rejected for wrong reason: %v", err)
		}
	}
	// Construction and VerifyLocalPublication authenticate evidence, NOT custody
	// binding. B is not expected to fail construction. Cryptographic verification
	// against valid A must reject B's signature without substituting a signer.
	b := consumerManager(t, successorVersion, deps)
	if _, err := b.VerifyLocalPublication(context.Background()); err != nil {
		t.Fatalf("valid A evidence must authenticate independently of B custody: %v", err)
	}
	bToken, err := jose.NewFromIdentityManagerKeyProvider(b, jose.Config{}).CreateJWS(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifier.VerifyJWS(context.Background(), bToken); err == nil {
		t.Fatal("configured B accepted against valid publication A")
	} else {
		var verification *dnsid.VerificationError
		if !errors.As(err, &verification) || verification.Code() != dnsid.VerificationCodeKeyNotFound {
			t.Fatalf("B rejected for wrong reason: %v", err)
		}
	}
	if lifecycleKid(t, b.KeyProvider()) == lifecycleKid(t, a.KeyProvider()) {
		t.Fatal("configured B fell back to A")
	}
	// Provider-local transitions compose through the real manager, not invented APIs.
	p := a.KeyProvider()
	old := lifecycleKid(t, p)
	pending, err := p.GenerateKey(dnsid.JoseAlgEdDSA)
	if os.Getenv("DNSID_TEST_GCP_MODE") != "success" {
		if err == nil || pending != "" {
			t.Fatalf("failed generation returned key %q, err %v", pending, err)
		}
		if lifecycleKid(t, p) != old || !reflect.DeepEqual(p.ListKeyIds(), []string{old}) {
			t.Fatal("failure changed active signer")
		}
		// B was opened before the failing generation; its public ID must not
		// become a phantom pending entry in A after a failed read/validation.
		phantom := lifecycleKid(t, b.KeyProvider())
		if p.JWK(phantom) != nil {
			t.Fatal("failed successor installed phantom public key")
		}
		if _, err := p.SignKey(phantom, payload); err == nil {
			t.Fatal("failed successor became proof-signable")
		}
		if err := p.Activate(phantom); err == nil {
			t.Fatal("failed successor became activatable")
		}
		current, err := a.GetKeySet().CurrentOperationalSigningKey(dnsid.DefaultPublishProfile)
		if err != nil || current.Kid() != old {
			t.Fatalf("failure changed publication: %v %v", current, err)
		}
		preserved, err := signer.CreateJWS(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := verifier.VerifyJWS(context.Background(), preserved); err != nil {
			t.Fatalf("failure broke old signature: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	current, err := a.GetKeySet().CurrentOperationalSigningKey(dnsid.DefaultPublishProfile)
	if err != nil || current.Kid() != old || !reflect.DeepEqual(p.ListKeyIds(), []string{old}) {
		t.Fatalf("pending changed live publication: %v %v", current, err)
	}
	proof, err := p.SignKey(pending, payload)
	seed := lifecycleFake(t)
	lifecycleSignature(t, proof, err, pending, payload, seed.successor.Public().(ed25519.PublicKey))
	stillOld, err := signer.CreateJWS(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifier.VerifyJWS(context.Background(), stillOld); err != nil {
		t.Fatalf("pending interrupted old signing: %v", err)
	}
	if err := p.Activate(pending); err != nil {
		t.Fatal(err)
	}
	nextDeps, _ := publication(t, a)
	newVerifier := publicationVerifier(t, nextDeps)
	newToken, err := signer.CreateJWS(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := newVerifier.VerifyJWS(context.Background(), newToken); err != nil {
		t.Fatalf("activated successor: %v", err)
	}
	if _, err := p.SignKey(old, payload); err == nil {
		t.Fatal("retained old key still signs")
	}
	if err := p.Supersede(old); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.ListKeyIds(), []string{pending}) {
		t.Fatal("supersession cleared successor")
	}
}
