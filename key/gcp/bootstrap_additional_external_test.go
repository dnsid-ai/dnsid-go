package gcpkms_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// External #62 contract cases 6–8; companion to bootstrap_external_test.go.
// Wrappers alter responses, never the base fake or its fixed identity.
type additionalResponses struct {
	*bootstrapFakeKMS
	key     func(*kmspb.CryptoKey) *kmspb.CryptoKey
	version func(*kmspb.CryptoKeyVersion) *kmspb.CryptoKeyVersion
	public  func(*kmspb.PublicKey) *kmspb.PublicKey
	winner  bool
	events  []string
}

func (f *additionalResponses) GetCryptoKey(ctx context.Context, r *kmspb.GetCryptoKeyRequest, o ...gax.CallOption) (*kmspb.CryptoKey, error) {
	f.events = append(f.events, "lookup")
	k, err := f.bootstrapFakeKMS.GetCryptoKey(ctx, r, o...)
	if err == nil && f.key != nil {
		k = f.key(k)
	}
	return k, err
}
func (f *additionalResponses) CreateCryptoKey(ctx context.Context, r *kmspb.CreateCryptoKeyRequest, o ...gax.CallOption) (*kmspb.CryptoKey, error) {
	f.events = append(f.events, "create")
	// A competing caller commits between our initial absence and atomic create.
	// Delegate request/count checks; the base then returns AlreadyExists.
	if f.winner {
		f.bootstrapFakeKMS.mu.Lock()
		f.bootstrapFakeKMS.exists = true
		f.bootstrapFakeKMS.mu.Unlock()
	}
	k, err := f.bootstrapFakeKMS.CreateCryptoKey(ctx, r, o...)
	if err == nil && f.key != nil {
		k = f.key(k)
	}
	return k, err
}
func (f *additionalResponses) GetCryptoKeyVersion(ctx context.Context, r *kmspb.GetCryptoKeyVersionRequest, o ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.events = append(f.events, "version")
	v, err := f.bootstrapFakeKMS.GetCryptoKeyVersion(ctx, r, o...)
	if err == nil && f.version != nil {
		v = f.version(v)
	}
	return v, err
}
func (f *additionalResponses) GetPublicKey(ctx context.Context, r *kmspb.GetPublicKeyRequest, o ...gax.CallOption) (*kmspb.PublicKey, error) {
	f.events = append(f.events, "public")
	p, err := f.bootstrapFakeKMS.GetPublicKey(ctx, r, o...)
	if err == nil && f.public != nil {
		p = f.public(p)
	}
	return p, err
}
func additionalCall(t *testing.T, client gcpkms.BootstrapClient, config gcpkms.BootstrapConfig) (*gcpkms.BootstrapResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := gcpkms.CreateOrReuse(ctx, client, config)
	if r != nil {
		ownProvider(t, r.Provider)
	} // Ownership before any assertion.
	return r, err
}
func additionalReject(t *testing.T, r *gcpkms.BootstrapResult, err error) {
	t.Helper()
	if r != nil || err == nil {
		t.Fatalf("must reject with nil result and error; result=%v error=%v", r, err)
	}
}
func additionalPEM(p *kmspb.PublicKey, text string) *kmspb.PublicKey {
	p.Pem = text
	p.PemCrc32C = wrapperspb.Int64(bootstrapChecksum([]byte(text)))
	return p
}
func additionalNonEdPEM(t *testing.T) string {
	t.Helper()
	// Fixed P-256 generator, not product output or randomness. Valid non-Ed25519 SPKI.
	x, y := elliptic.P256().ScalarBaseMult(big.NewInt(1).Bytes())
	der, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	if err != nil {
		t.Fatalf("independent P-256 bootstrapFixture: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestCreateOrReuse_Case6_RejectUntrustedResponses(t *testing.T) {
	// Mode: fake-only (deliberately corrupt KMS responses).
	nonEd := additionalNonEdPEM(t)
	rows := []struct {
		name, boundary string
		key            func(*kmspb.CryptoKey) *kmspb.CryptoKey
		version        func(*kmspb.CryptoKeyVersion) *kmspb.CryptoKeyVersion
		public         func(*kmspb.PublicKey) *kmspb.PublicKey
	}{
		{name: "key/nil", boundary: "key", key: func(*kmspb.CryptoKey) *kmspb.CryptoKey { return nil }},
		{name: "key/wrong-name", boundary: "key", key: func(k *kmspb.CryptoKey) *kmspb.CryptoKey { k.Name = keyName + "-other"; return k }},
		{name: "key/wrong-purpose", boundary: "key", key: func(k *kmspb.CryptoKey) *kmspb.CryptoKey { k.Purpose = kmspb.CryptoKey_ENCRYPT_DECRYPT; return k }},
		{name: "key/missing-template", boundary: "key", key: func(k *kmspb.CryptoKey) *kmspb.CryptoKey { k.VersionTemplate = nil; return k }},
		{name: "key/wrong-template-algorithm", boundary: "key", key: func(k *kmspb.CryptoKey) *kmspb.CryptoKey {
			k.VersionTemplate.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
			return k
		}},
		{name: "key/wrong-template-protection", boundary: "key", key: func(k *kmspb.CryptoKey) *kmspb.CryptoKey {
			k.VersionTemplate.ProtectionLevel = kmspb.ProtectionLevel_HSM
			return k
		}},
		{name: "version/nil", boundary: "version", version: func(*kmspb.CryptoKeyVersion) *kmspb.CryptoKeyVersion { return nil }},
		{name: "version/wrong-name", boundary: "version", version: func(v *kmspb.CryptoKeyVersion) *kmspb.CryptoKeyVersion {
			v.Name = keyName + "/cryptoKeyVersions/2"
			return v
		}},
		{name: "version/nonsoftware", boundary: "version", version: func(v *kmspb.CryptoKeyVersion) *kmspb.CryptoKeyVersion {
			v.ProtectionLevel = kmspb.ProtectionLevel_HSM
			return v
		}},
		{name: "version/nonEd25519", boundary: "version", version: func(v *kmspb.CryptoKeyVersion) *kmspb.CryptoKeyVersion {
			v.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
			return v
		}},
		{name: "public/nil", boundary: "public", public: func(*kmspb.PublicKey) *kmspb.PublicKey { return nil }},
		{name: "public/wrong-name", boundary: "public", public: func(p *kmspb.PublicKey) *kmspb.PublicKey { p.Name = keyName + "/cryptoKeyVersions/2"; return p }},
		{name: "public/wrong-algorithm", boundary: "public", public: func(p *kmspb.PublicKey) *kmspb.PublicKey {
			p.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
			return p
		}},
		{name: "public/wrong-protection", boundary: "public", public: func(p *kmspb.PublicKey) *kmspb.PublicKey { p.ProtectionLevel = kmspb.ProtectionLevel_HSM; return p }},
		{name: "public/missing-CRC32C", boundary: "public", public: func(p *kmspb.PublicKey) *kmspb.PublicKey { p.PemCrc32C = nil; return p }},
		{name: "public/bad-CRC32C", boundary: "public", public: func(p *kmspb.PublicKey) *kmspb.PublicKey {
			p.PemCrc32C = wrapperspb.Int64(p.PemCrc32C.Value ^ 1)
			return p
		}},
		{name: "public/invalid-PEM", boundary: "public", public: func(p *kmspb.PublicKey) *kmspb.PublicKey { return additionalPEM(p, "not PEM") }},
		{name: "public/invalid-SPKI", boundary: "public", public: func(p *kmspb.PublicKey) *kmspb.PublicKey {
			return additionalPEM(p, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}})))
		}},
		{name: "public/nonEd25519-SPKI", boundary: "public", public: func(p *kmspb.PublicKey) *kmspb.PublicKey { return additionalPEM(p, nonEd) }},
	}
	for _, state := range []kmspb.CryptoKeyVersion_CryptoKeyVersionState{
		kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_STATE_UNSPECIFIED,
		kmspb.CryptoKeyVersion_PENDING_GENERATION, kmspb.CryptoKeyVersion_DISABLED,
		kmspb.CryptoKeyVersion_DESTROY_SCHEDULED, kmspb.CryptoKeyVersion_DESTROYED,
		kmspb.CryptoKeyVersion_PENDING_IMPORT, kmspb.CryptoKeyVersion_IMPORT_FAILED,
		kmspb.CryptoKeyVersion_GENERATION_FAILED, kmspb.CryptoKeyVersion_PENDING_EXTERNAL_DESTRUCTION,
		kmspb.CryptoKeyVersion_EXTERNAL_DESTRUCTION_FAILED,
		// Test-owned value outside the reviewed public declaration; ENABLED only.
		kmspb.CryptoKeyVersion_CryptoKeyVersionState(123456789),
	} {
		rows = append(rows, struct {
			name, boundary string
			key            func(*kmspb.CryptoKey) *kmspb.CryptoKey
			version        func(*kmspb.CryptoKeyVersion) *kmspb.CryptoKeyVersion
			public         func(*kmspb.PublicKey) *kmspb.PublicKey
		}{name: "version/state-" + state.String(), boundary: "version", version: func(v *kmspb.CryptoKeyVersion) *kmspb.CryptoKeyVersion { v.State = state; return v }})
	}
	for _, path := range []string{"reuse", "create", "winner"} {
		existing := path == "reuse"
		for _, row := range rows {
			t.Run(path+"/"+row.name, func(t *testing.T) {
				// GIVEN one untrusted field against otherwise independent valid fixtures.
				base := newBootstrapFake(t, existing)
				client := &additionalResponses{bootstrapFakeKMS: base, key: row.key, version: row.version, public: row.public, winner: path == "winner"}
				// WHEN bootstrapping, THEN no provider escapes and no replacement is generated.
				r, err := additionalCall(t, client, cfg())
				additionalReject(t, r, err)
				creates := 1
				if existing {
					creates = 0
				}
				c := assertTrace(t, base, creates)
				lookups := 1
				wantEvents := "lookup"
				if path == "create" {
					wantEvents += ",create"
				}
				if path == "winner" {
					lookups = 2
					wantEvents += ",create,lookup"
				}
				if row.boundary != "key" {
					wantEvents += ",version"
				}
				if row.boundary == "public" {
					wantEvents += ",public"
				}
				if strings.Join(client.events, ",") != wantEvents {
					t.Fatalf("boundary order=%v, want %s", client.events, wantEvents)
				}
				if c.lookups != lookups || c.versions > 1 || c.publics > 1 || c.signs != 0 {
					t.Fatalf("retry/extra work after rejection: %+v", c)
				}
				if row.boundary == "key" && (c.versions != 0 || c.publics != 0) {
					t.Fatalf("continued past invalid key: %+v", c)
				}
				if row.boundary == "version" && (c.versions != 1 || c.publics != 0) {
					t.Fatalf("invalid version boundary: %+v", c)
				}
				if row.boundary == "public" && (c.versions != 1 || c.publics != 1) {
					t.Fatalf("invalid public boundary: %+v", c)
				}
			})
		}
	}
}

func TestCreateOrReuse_Case7_LocalScopeGuards(t *testing.T) {
	// Mode: real-capable behavior; fake call-accounting harness, no live client.
	rows := []struct{ name, parent, id string }{
		{"empty-parent", "", keyID}, {"project-only", "projects/p", keyID},
		{"missing-project", "projects//locations/l/keyRings/r", keyID},
		{"missing-location", "projects/p/locations//keyRings/r", keyID},
		{"missing-ring", "projects/p/locations/l/keyRings/", keyID},
		{"wrong-collection", "projects/p/locations/l/keys/r", keyID},
		{"leading-slash", "/" + parent, keyID}, {"trailing-slash", parent + "/", keyID},
		{"extra-child", keyName, keyID}, {"URI", "https://cloudkms.googleapis.com/" + parent, keyID},
		{"empty-id", parent, ""}, {"long-id", parent, strings.Repeat("a", 64)},
		{"slash-id", parent, "a/b"}, {"dot-id", parent, "a.b"},
		{"space-id", parent, "a b"}, {"unicode-id", parent, "é"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			// GIVEN invalid scope, WHEN called, THEN caller sees rejection before remote work.
			f := newBootstrapFake(t, false)
			r, err := additionalCall(t, f, gcpkms.BootstrapConfig{Parent: row.parent, CryptoKeyID: row.id})
			additionalReject(t, r, err)
			c, _ := f.snapshot()
			if c != (trace{}) {
				t.Fatalf("invalid input reached KMS: %+v", c)
			}
		})
	}
	t.Run("nil-client", func(t *testing.T) {
		// GIVEN no client, WHEN called with valid scope, THEN error/nil, not panic.
		r, err := additionalCall(t, nil, cfg())
		additionalReject(t, r, err)
	})
}
func TestCreateOrReuse_Case7_MissingAncestorNativeFailure(t *testing.T) {
	// Mode: real-capable behavior; fake native service failure in this harness.
	// GIVEN the named key is absent and its key ring does not exist.
	f := newBootstrapFake(t, false)
	native := status.Error(codes.NotFound, "parent key ring missing")
	f.faultAt, f.fault = "create", native
	// WHEN create fails, THEN preserve native failure, without another generation.
	r, err := additionalCall(t, f, cfg())
	additionalReject(t, r, err)
	if !errors.Is(err, native) || status.Code(err) != codes.NotFound {
		t.Fatalf("lost native ancestor error: %v", err)
	}
	c := assertTrace(t, f, 1)
	if c.lookups != 1 || c.versions != 0 || c.publics != 0 || c.signs != 0 {
		t.Fatalf("ancestor recovery/retry attempted: %+v", c)
	}
}

// Test-local application composition, NOT an invented registry SDK API.
func additionalKeyFirst(t *testing.T, f *bootstrapFakeKMS, events *[]string, agent func(string) error) (*gcpkms.BootstrapResult, error) {
	t.Helper()
	r, err := additionalCall(t, f, cfg())
	if err != nil {
		return r, err
	}
	if r == nil || r.Provider == nil {
		t.Fatal("KEYFIRST requires successful nonnil bootstrap result/provider")
	}
	*events = append(*events, "KEYFIRST")
	return r, agent(r.KeyVersionName)
}
func TestCreateOrReuse_Case8_KeyFirstApplicationComposition(t *testing.T) {
	// Mode: fake-only (test-local agent callback and instrumented KMS).
	t.Run("application-explicitly-calls-agent-after-key", func(t *testing.T) {
		// GIVEN no key and a separate application-owned agent callback.
		f := newBootstrapFake(t, false)
		events := []string{}
		var refs []string
		agent := func(ref string) error { events = append(events, "AGENT"); refs = append(refs, ref); return nil }
		// WHEN the application chooses KEYFIRST and then calls that callback.
		r, err := additionalKeyFirst(t, f, &events, agent)
		// THEN the application has a usable identity and passes its exact immutable ref.
		assertResult(t, r, err)
		if len(refs) != 1 || refs[0] != versionName || refs[0] != r.KeyVersionName {
			t.Fatalf("agent refs=%v, returned=%q", refs, r.KeyVersionName)
		}
		if strings.Join(events, ",") != "KEYFIRST,AGENT" {
			t.Fatalf("application order=%v", events)
		}
		assertTrace(t, f, 1)
	})
	t.Run("failure-never-calls-agent", func(t *testing.T) {
		f := newBootstrapFake(t, false)
		native := status.Error(codes.PermissionDenied, "key permission denied")
		f.faultAt, f.fault = "lookup", native
		events := []string{}
		calls := 0
		// GIVEN failed key bootstrap, WHEN composed, THEN no downstream agent action.
		r, err := additionalKeyFirst(t, f, &events, func(string) error { calls++; return nil })
		additionalReject(t, r, err)
		if !errors.Is(err, native) || status.Code(err) != codes.PermissionDenied {
			t.Fatalf("lost native failure: %v", err)
		}
		if calls != 0 || len(events) != 0 {
			t.Fatalf("agent action despite key failure: calls=%d events=%v", calls, events)
		}
		assertTrace(t, f, 0)
	})
	t.Run("bootstrap-alone-and-injected-client-ownership", func(t *testing.T) {
		f := newBootstrapFake(t, false)
		// GIVEN bootstrap alone, with no agent invocation by the application.
		agentCalls := 0
		agent := func(string) { agentCalls++ }
		_ = agent // Kept separate deliberately: CreateOrReuse receives no callback.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		r, err := gcpkms.CreateOrReuse(ctx, f, cfg())
		// Acquire immediately, including an unexpected provider accompanying an error.
		var closeOnce sync.Once
		closeOwned := func() {
			closeOnce.Do(func() {
				if r != nil && r.Provider != nil {
					if closeErr := r.Provider.Close(); closeErr != nil {
						t.Errorf("provider Close: %v", closeErr)
					}
				}
			})
		}
		t.Cleanup(closeOwned)
		// WHEN key bootstrap returns and provider ownership ends.
		assertResult(t, r, err)
		closeOwned()
		// THEN bootstrap did not invoke a local agent; injected KMS remains caller-owned.
		if agentCalls != 0 {
			t.Fatalf("bootstrap-alone agent calls=%d", agentCalls)
		}
		c := assertTrace(t, f, 1)
		if c.closes != 0 {
			t.Fatal("Provider.Close closed injected KMS client")
		}
	})
}

// Separate scope-aware bootstrapFixture: never relabel the frozen base identity.
// Names and seeds are test-owned inputs, not values learned from a provider.
type additionalScope struct {
	config       gcpkms.BootstrapConfig
	key, version string
	seed         [ed25519.SeedSize]byte
}

func additionalScopes() []additionalScope {
	return []additionalScope{
		{gcpkms.BootstrapConfig{Parent: "projects/scope-project-a/locations/us-central1/keyRings/scope-ring-a", CryptoKeyID: "scope-key-a"},
			"projects/scope-project-a/locations/us-central1/keyRings/scope-ring-a/cryptoKeys/scope-key-a",
			"projects/scope-project-a/locations/us-central1/keyRings/scope-ring-a/cryptoKeys/scope-key-a/cryptoKeyVersions/1", [32]byte{0x41, 0x11, 0x21}},
		{gcpkms.BootstrapConfig{Parent: "projects/scope-project-b/locations/us-central1/keyRings/scope-ring-a", CryptoKeyID: "scope-key-a"},
			"projects/scope-project-b/locations/us-central1/keyRings/scope-ring-a/cryptoKeys/scope-key-a",
			"projects/scope-project-b/locations/us-central1/keyRings/scope-ring-a/cryptoKeys/scope-key-a/cryptoKeyVersions/1", [32]byte{0x52, 0x12, 0x22}},
		{gcpkms.BootstrapConfig{Parent: "projects/scope-project-a/locations/europe-west1/keyRings/scope-ring-a", CryptoKeyID: "scope-key-a"},
			"projects/scope-project-a/locations/europe-west1/keyRings/scope-ring-a/cryptoKeys/scope-key-a",
			"projects/scope-project-a/locations/europe-west1/keyRings/scope-ring-a/cryptoKeys/scope-key-a/cryptoKeyVersions/1", [32]byte{0x63, 0x13, 0x23}},
		{gcpkms.BootstrapConfig{Parent: "projects/scope-project-a/locations/us-central1/keyRings/scope-ring-b", CryptoKeyID: "scope-key-a"},
			"projects/scope-project-a/locations/us-central1/keyRings/scope-ring-b/cryptoKeys/scope-key-a",
			"projects/scope-project-a/locations/us-central1/keyRings/scope-ring-b/cryptoKeys/scope-key-a/cryptoKeyVersions/1", [32]byte{0x74, 0x14, 0x24}},
		{gcpkms.BootstrapConfig{Parent: "projects/scope-project-a/locations/us-central1/keyRings/scope-ring-a", CryptoKeyID: "scope-key-b"},
			"projects/scope-project-a/locations/us-central1/keyRings/scope-ring-a/cryptoKeys/scope-key-b",
			"projects/scope-project-a/locations/us-central1/keyRings/scope-ring-a/cryptoKeys/scope-key-b/cryptoKeyVersions/1", [32]byte{0x85, 0x15, 0x25}},
	}
}

type additionalScopeFake struct {
	mu         sync.Mutex
	scopes     []additionalScope
	exists     []bool
	counts     []trace
	requestsOK bool
	closes     int
}

func newAdditionalScopeFake(t *testing.T, scopes []additionalScope) *additionalScopeFake {
	t.Helper()
	f := &additionalScopeFake{scopes: scopes, exists: make([]bool, len(scopes)), counts: make([]trace, len(scopes)), requestsOK: true}
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.closes != 0 {
			t.Errorf("scope providers closed injected client %d times", f.closes)
		}
		if !f.requestsOK {
			t.Error("scope fake saw invalid request")
		}
	})
	return f
}
func (f *additionalScopeFake) find(name string, version bool) int {
	for i, scope := range f.scopes {
		want := scope.key
		if version {
			want = scope.version
		}
		if name == want {
			return i
		}
	}
	f.requestsOK = false
	return -1
}
func additionalScopeKey(scope additionalScope) *kmspb.CryptoKey {
	return &kmspb.CryptoKey{Name: scope.key, Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}}
}
func (f *additionalScopeFake) GetCryptoKey(_ context.Context, r *kmspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r == nil {
		f.requestsOK = false
		return nil, status.Error(codes.InvalidArgument, "nil lookup")
	}
	i := f.find(r.Name, false)
	if i < 0 {
		return nil, status.Error(codes.InvalidArgument, "unknown exact key")
	}
	f.counts[i].lookups++
	if !f.exists[i] {
		return nil, status.Error(codes.NotFound, "scope absent")
	}
	return additionalScopeKey(f.scopes[i]), nil
}
func (f *additionalScopeFake) CreateCryptoKey(_ context.Context, r *kmspb.CreateCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := -1
	if r != nil {
		for j, scope := range f.scopes {
			if r.Parent == scope.config.Parent && r.CryptoKeyId == scope.config.CryptoKeyID {
				i = j
				break
			}
		}
	}
	if i < 0 {
		f.requestsOK = false
		return nil, status.Error(codes.InvalidArgument, "unknown explicit scope")
	}
	f.counts[i].creates++
	valid := !r.SkipInitialVersionCreation && r.CryptoKey != nil
	if valid {
		k := r.CryptoKey
		valid = k.Purpose == kmspb.CryptoKey_ASYMMETRIC_SIGN && k.VersionTemplate != nil && k.RotationSchedule == nil && k.NextRotationTime == nil
		if valid {
			valid = k.VersionTemplate.Algorithm == kmspb.CryptoKeyVersion_EC_SIGN_ED25519 && k.VersionTemplate.ProtectionLevel == kmspb.ProtectionLevel_SOFTWARE
		}
	}
	if !valid {
		f.requestsOK = false
		return nil, status.Error(codes.InvalidArgument, "wrong scope create template")
	}
	if f.exists[i] {
		return nil, status.Error(codes.AlreadyExists, "scope already exists")
	}
	f.exists[i] = true
	return additionalScopeKey(f.scopes[i]), nil
}
func (f *additionalScopeFake) GetCryptoKeyVersion(_ context.Context, r *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r == nil {
		f.requestsOK = false
		return nil, status.Error(codes.InvalidArgument, "nil version")
	}
	i := f.find(r.Name, true)
	if i < 0 {
		return nil, status.Error(codes.InvalidArgument, "unknown immutable version")
	}
	f.counts[i].versions++
	if !f.exists[i] {
		return nil, status.Error(codes.NotFound, "version absent")
	}
	return &kmspb.CryptoKeyVersion{Name: f.scopes[i].version, State: kmspb.CryptoKeyVersion_ENABLED,
		Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}
func (f *additionalScopeFake) GetPublicKey(_ context.Context, r *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r == nil {
		f.requestsOK = false
		return nil, status.Error(codes.InvalidArgument, "nil public")
	}
	i := f.find(r.Name, true)
	if i < 0 {
		return nil, status.Error(codes.InvalidArgument, "unknown public reference")
	}
	f.counts[i].publics++
	if !f.exists[i] {
		return nil, status.Error(codes.NotFound, "public absent")
	}
	scope := f.scopes[i]
	der, err := x509.MarshalPKIXPublicKey(ed25519.NewKeyFromSeed(scope.seed[:]).Public())
	if err != nil {
		return nil, err
	}
	text := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return &kmspb.PublicKey{Name: scope.version, Pem: text, PemCrc32C: wrapperspb.Int64(bootstrapChecksum([]byte(text))),
		Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}
func (f *additionalScopeFake) AsymmetricSign(_ context.Context, r *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r == nil {
		f.requestsOK = false
		return nil, status.Error(codes.InvalidArgument, "nil sign")
	}
	i := f.find(r.Name, true)
	if i < 0 {
		return nil, status.Error(codes.InvalidArgument, "unknown sign reference")
	}
	f.counts[i].signs++
	if !f.exists[i] {
		return nil, status.Error(codes.NotFound, "sign version absent")
	}
	if r.Digest != nil || r.DigestCrc32C != nil || r.DataCrc32C == nil || r.DataCrc32C.Value != bootstrapChecksum(r.Data) {
		f.requestsOK = false
		return nil, status.Error(codes.InvalidArgument, "expected raw Ed25519 data and CRC")
	}
	scope := f.scopes[i]
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(scope.seed[:]), r.Data)
	return &kmspb.AsymmetricSignResponse{Name: scope.version, Signature: sig, SignatureCrc32C: wrapperspb.Int64(bootstrapChecksum(sig)),
		VerifiedDataCrc32C: true, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}
func (f *additionalScopeFake) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	return nil
}
func (f *additionalScopeFake) snapshot() ([]trace, []bool, bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]trace(nil), f.counts...), append([]bool(nil), f.exists...), f.requestsOK, f.closes
}
func additionalAssertScope(t *testing.T, scope additionalScope, r *gcpkms.BootstrapResult, err error) string {
	t.Helper()
	if err != nil {
		t.Fatalf("scope bootstrap: %v", err)
	}
	if r == nil || r.Provider == nil {
		t.Fatal("scope bootstrap requires result and provider")
	}
	if r.KeyVersionName != scope.version {
		t.Fatalf("scope ref=%q want literal %q", r.KeyVersionName, scope.version)
	}
	p := r.Provider
	key := p.JWK()
	if key == nil {
		t.Fatal("nil scoped JWK")
	}
	// Independent fixed seed oracle, never p.JWK as the signature verifier.
	pub := ed25519.NewKeyFromSeed(scope.seed[:]).Public().(ed25519.PublicKey)
	for name, want := range map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)} {
		var got any
		if err := key.Get(name, &got); err != nil {
			t.Fatalf("scope JWK %s: %v", name, err)
		}
		text := fmt.Sprint(got)
		if b, ok := got.([]byte); ok {
			text = base64.RawURLEncoding.EncodeToString(b)
		}
		if text != want {
			t.Fatalf("scope JWK %s=%q want %q", name, text, want)
		}
	}
	ids := p.ListKeyIds()
	if len(ids) != 1 || ids[0] == "" {
		t.Fatalf("scope kids=%v", ids)
	}
	kid := ids[0]
	if kid == scope.key || kid == scope.version {
		t.Fatal("scope reference used as kid")
	}
	var jwkKid string
	if err := key.Get("kid", &jwkKid); err != nil {
		t.Fatalf("scope JWK kid: %v", err)
	}
	if jwkKid != kid {
		t.Fatal("scope JWK/listed kid mismatch")
	}
	payload := []byte("#62 distinct scope identity: " + scope.version)
	sig, err := p.Sign(payload)
	if err != nil {
		t.Fatalf("scope Sign: %v", err)
	}
	if !ed25519.Verify(pub, payload, signatureBytes(t, sig)) {
		t.Fatal("scope Sign failed independent verification")
	}
	selected, err := p.SignKey(kid, payload)
	if err != nil {
		t.Fatalf("scope SignKey: %v", err)
	}
	if !ed25519.Verify(pub, payload, signatureBytes(t, selected)) {
		t.Fatal("scope SignKey failed independent verification")
	}
	return kid
}
func TestCreateOrReuse_Case7_DistinctValidScopesStableReuse(t *testing.T) {
	// Mode: fake-only (fixed multi-scope identities and cross-scope accounting).
	// GIVEN independently varied project/location/ring/ID and five fixed seeds.
	scopes := additionalScopes()
	f := newAdditionalScopeFake(t, scopes)
	kids := make([]string, len(scopes))
	// WHEN each absent scope is bootstrapped, then reused twice in reverse order.
	for round := 0; round < 3; round++ {
		for step := range scopes {
			i := step
			if round > 0 {
				i = len(scopes) - 1 - step
			}
			before, existed, _, _ := f.snapshot()
			r, err := additionalCall(t, f, scopes[i].config)
			// THEN exact immutable reference, expected public identity, usable signatures.
			kid := additionalAssertScope(t, scopes[i], r, err)
			if round == 0 {
				kids[i] = kid
			} else if kid != kids[i] {
				t.Fatalf("scope %d kid changed", i)
			}
			after, exists, ok, closes := f.snapshot()
			if !ok || closes != 0 {
				t.Fatal("invalid scoped request or injected client closed")
			}
			for j := range scopes {
				if j != i {
					if after[j] != before[j] || exists[j] != existed[j] {
						t.Fatalf("scope %d mutated/called scope %d", i, j)
					}
					continue
				}
				wantCreates := 0
				if round == 0 {
					wantCreates = 1
				}
				if !exists[j] || after[j].creates-before[j].creates != wantCreates || after[j].creates != 1 {
					t.Fatalf("scope %d generation/reuse mismatch: before=%+v after=%+v", i, before[j], after[j])
				}
				if after[j].signs-before[j].signs != 2 {
					t.Fatalf("scope %d unexpected signing count", i)
				}
			}
		}
	}
}
