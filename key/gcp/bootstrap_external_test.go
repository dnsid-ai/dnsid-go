package gcpkms_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"sync"
	"testing"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	dnsid "github.com/dnsid-ai/dnsid-go"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// External acceptance tests for #62, cases 1–5 only. All KMS calls
// are fake; cryptographic and CRC32C oracles use independent standard APIs.
const parent = "projects/test-project/locations/us-central1/keyRings/test-ring"
const keyID = "explicit_key-62"
const keyName = parent + "/cryptoKeys/" + keyID
const versionName = keyName + "/cryptoKeyVersions/1"

var message = []byte("#62 caller-owned explicit key bootstrap")

func bootstrapFixture() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}
func bootstrapChecksum(b []byte) int64 {
	return int64(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)))
}
func cfg() gcpkms.BootstrapConfig { return gcpkms.BootstrapConfig{Parent: parent, CryptoKeyID: keyID} }
func goodKey() *kmspb.CryptoKey {
	return &kmspb.CryptoKey{Name: keyName, Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}}
}
func goodVersion() *kmspb.CryptoKeyVersion {
	return &kmspb.CryptoKeyVersion{Name: versionName, State: kmspb.CryptoKeyVersion_ENABLED,
		Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}
}
func publicResponse() *kmspb.PublicKey {
	der, err := x509.MarshalPKIXPublicKey(bootstrapFixture().Public())
	if err != nil {
		panic(err)
	} // Fixed standard-library fixture, not a product result.
	text := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return &kmspb.PublicKey{Name: versionName, Pem: text, PemCrc32C: wrapperspb.Int64(bootstrapChecksum([]byte(text))),
		Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}
}

type callerIdentity struct{}

type trace struct{ lookups, creates, versions, publics, signs, closes int }
type bootstrapFakeKMS struct {
	mu            sync.Mutex
	exists        bool
	counts        trace
	requestsOK    bool
	faultAt       string
	fault         error
	commitTimeout bool
	// A deterministic initial-lookup barrier; initial calls all observe absence.
	initial      int
	callerEvents map[int][]string
	entered      chan struct{}
	release      chan struct{}
}

func newBootstrapFake(t *testing.T, exists bool) *bootstrapFakeKMS {
	t.Helper()
	f := &bootstrapFakeKMS{exists: exists, requestsOK: true, callerEvents: make(map[int][]string)}
	// Registered before provider cleanups, so checked after those cleanups run.
	t.Cleanup(func() {
		c, _ := f.snapshot()
		if c.closes != 0 {
			t.Errorf("provider closed caller-owned client %d times", c.closes)
		}
	})
	return f
}
func (f *bootstrapFakeKMS) snapshot() (trace, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts, f.requestsOK
}
func (f *bootstrapFakeKMS) check(ok bool) { f.requestsOK = f.requestsOK && ok }
func (f *bootstrapFakeKMS) GetCryptoKey(ctx context.Context, r *kmspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
	f.mu.Lock()
	f.counts.lookups++
	n := f.counts.lookups
	f.check(r != nil && r.Name == keyName)
	id, _ := ctx.Value(callerIdentity{}).(int)
	if f.initial > 0 && id > 0 && id <= f.initial && len(f.callerEvents[id]) == 0 {
		f.callerEvents[id] = append(f.callerEvents[id], "initial-absence")
		f.mu.Unlock()
		f.entered <- struct{}{}
		select {
		case <-f.release:
			return nil, status.Error(codes.NotFound, "initial absence")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	defer f.mu.Unlock()
	if f.faultAt == "lookup" || (f.faultAt == "winner" && n > 1) {
		return nil, f.fault
	}
	if !f.exists {
		return nil, status.Error(codes.NotFound, "named key absent")
	}
	if id > 0 {
		event := "wrong-name-read"
		if r != nil && r.Name == keyName {
			event = "exact-winner-read"
		}
		f.callerEvents[id] = append(f.callerEvents[id], event)
	}
	return goodKey(), nil
}
func (f *bootstrapFakeKMS) CreateCryptoKey(ctx context.Context, r *kmspb.CreateCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts.creates++
	valid := r != nil && r.Parent == parent && r.CryptoKeyId == keyID && !r.SkipInitialVersionCreation && r.CryptoKey != nil
	if valid {
		k := r.CryptoKey
		valid = k.Purpose == kmspb.CryptoKey_ASYMMETRIC_SIGN && k.VersionTemplate != nil && k.RotationSchedule == nil && k.NextRotationTime == nil
		if valid {
			valid = k.VersionTemplate.Algorithm == kmspb.CryptoKeyVersion_EC_SIGN_ED25519 && k.VersionTemplate.ProtectionLevel == kmspb.ProtectionLevel_SOFTWARE
		}
	}
	f.check(valid)
	if f.faultAt == "create" {
		return nil, f.fault
	}
	if f.faultAt == "winner" {
		return nil, status.Error(codes.AlreadyExists, "winner committed")
	}
	id, _ := ctx.Value(callerIdentity{}).(int)
	if f.exists {
		if id > 0 {
			f.callerEvents[id] = append(f.callerEvents[id], "create-already-exists")
		}
		return nil, status.Error(codes.AlreadyExists, "atomic loser")
	}
	if id > 0 {
		f.callerEvents[id] = append(f.callerEvents[id], "create-winner")
	}
	f.exists = true
	if f.commitTimeout {
		return nil, status.Error(codes.DeadlineExceeded, "committed but response lost")
	}
	return goodKey(), nil
}
func (f *bootstrapFakeKMS) GetCryptoKeyVersion(_ context.Context, r *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts.versions++
	f.check(r != nil && r.Name == versionName)
	if f.faultAt == "version" {
		return nil, f.fault
	}
	return goodVersion(), nil
}
func (f *bootstrapFakeKMS) GetPublicKey(_ context.Context, r *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts.publics++
	f.check(r != nil && r.Name == versionName)
	if f.faultAt == "public" {
		return nil, f.fault
	}
	return publicResponse(), nil
}
func (f *bootstrapFakeKMS) AsymmetricSign(_ context.Context, r *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts.signs++
	if r == nil || r.Name != versionName || r.Digest != nil || r.DigestCrc32C != nil || r.DataCrc32C == nil || r.DataCrc32C.Value != bootstrapChecksum(r.Data) {
		f.requestsOK = false
		return nil, status.Error(codes.InvalidArgument, "expected Ed25519 data and CRC32C")
	}
	signature := ed25519.Sign(bootstrapFixture(), r.Data)
	return &kmspb.AsymmetricSignResponse{Name: versionName, Signature: signature,
		SignatureCrc32C: wrapperspb.Int64(bootstrapChecksum(signature)), VerifiedDataCrc32C: true,
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}

// Extra method detects accidental ownership transfer of an injected client.
func (f *bootstrapFakeKMS) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts.closes++
	return nil
}

// Public declaration supplied by independent review: KeySignature has
// Kid string, Alg JoseAlg, and Signature []byte. Verify raw bytes only.
func signatureBytes(t *testing.T, signature *dnsid.KeySignature) []byte {
	t.Helper()
	if signature == nil {
		t.Fatal("successful Sign returned nil signature")
	}
	return signature.Signature
}

// Register synchronous results before inspecting either the error or payload.
func ownProvider(t *testing.T, p *gcpkms.Provider) {
	t.Helper()
	if p != nil {
		t.Cleanup(func() {
			if err := p.Close(); err != nil {
				t.Errorf("provider Close: %v", err)
			}
		})
	}
}
func bootstrap(t *testing.T, ctx context.Context, f *bootstrapFakeKMS, config gcpkms.BootstrapConfig) (*gcpkms.BootstrapResult, error) {
	t.Helper()
	r, err := gcpkms.CreateOrReuse(ctx, f, config)
	if r != nil {
		ownProvider(t, r.Provider)
	}
	return r, err
}

// Workers register ownership before publishing any outcome. Shutdown closes
// buffered/uncollected providers; registrations after shutdown close immediately.
// No testing.T calls occur in late workers.
type concurrentOwners struct {
	mu        sync.Mutex
	closing   bool
	providers []*gcpkms.Provider
	errors    []error
}

func (o *concurrentOwners) acquire(r *gcpkms.BootstrapResult) {
	if r == nil || r.Provider == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closing {
		if err := r.Provider.Close(); err != nil {
			o.errors = append(o.errors, err)
		}
		return
	}
	o.providers = append(o.providers, r.Provider)
}
func (o *concurrentOwners) shutdown(t *testing.T) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closing = true
	for _, p := range o.providers {
		if err := p.Close(); err != nil {
			o.errors = append(o.errors, err)
		}
	}
	o.providers = nil
	for _, err := range o.errors {
		t.Errorf("concurrent provider Close: %v", err)
	}
}
func assertProvider(t *testing.T, p *gcpkms.Provider) string {
	t.Helper()
	if p == nil {
		t.Fatal("successful bootstrap/open must return a non-nil Provider")
	}
	key := p.JWK()
	if key == nil {
		t.Fatal("provider returned nil JWK")
	}
	// Independently expected RFC 8037 OKP public members: cloud resource is NOT kid.
	wantX := base64.RawURLEncoding.EncodeToString(bootstrapFixture().Public().(ed25519.PublicKey))
	for name, want := range map[string]string{"kty": "OKP", "crv": "Ed25519", "x": wantX} {
		var got any
		if err := key.Get(name, &got); err != nil {
			t.Fatalf("JWK %s: %v", name, err)
		}
		// jwx represents x as decoded bytes and kty/crv as named string values.
		text := fmt.Sprint(got)
		if b, ok := got.([]byte); ok {
			text = base64.RawURLEncoding.EncodeToString(b)
		}
		if text != want {
			t.Fatalf("JWK %s = %q, want %q", name, text, want)
		}
	}
	ids := p.ListKeyIds()
	if len(ids) != 1 || ids[0] == "" {
		t.Fatalf("expected one nonempty kid, got %v", ids)
	}
	kid := ids[0]
	if kid == versionName || kid == keyName {
		t.Fatal("cloud resource reference was used as JWK kid")
	}
	var jwkKid string
	if err := key.Get("kid", &jwkKid); err != nil {
		t.Fatalf("JWK kid: %v", err)
	}
	if jwkKid != kid {
		t.Fatalf("JWK kid %q != listed kid %q", jwkKid, kid)
	}
	// An explicit kid selects an existing key; it does not relabel the active key.
	selectedKey := p.JWK(kid)
	if selectedKey == nil {
		t.Fatal("JWK(listed kid) is nil")
	}
	var selectedKid string
	if err := selectedKey.Get("kid", &selectedKid); err != nil {
		t.Fatalf("selected JWK kid: %v", err)
	}
	if selectedKid != kid {
		t.Fatalf("selected JWK kid %q != listed kid %q", selectedKid, kid)
	}
	unknownKid := kid + "-unknown"
	if p.JWK(unknownKid) != nil {
		t.Fatal("JWK(unknown kid) must be nil")
	}
	sig, err := p.Sign(message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(bootstrapFixture().Public().(ed25519.PublicKey), message, signatureBytes(t, sig)) {
		t.Fatal("Sign did not verify with expected fixture key")
	}
	selected, err := p.SignKey(kid, message)
	if err != nil {
		t.Fatalf("SignKey(listed kid): %v", err)
	}
	if !ed25519.Verify(bootstrapFixture().Public().(ed25519.PublicKey), message, signatureBytes(t, selected)) {
		t.Fatal("SignKey did not verify with expected fixture key")
	}
	return kid
}
func assertResult(t *testing.T, r *gcpkms.BootstrapResult, err error) string {
	t.Helper()
	if err != nil {
		t.Fatalf("CreateOrReuse must succeed, got %v", err)
	}
	if r == nil {
		t.Fatal("CreateOrReuse succeeded with nil result (unimplemented scaffold is not success)")
	}
	if r.KeyVersionName != versionName {
		t.Fatalf("version ref = %q, want %q", r.KeyVersionName, versionName)
	}
	return assertProvider(t, r.Provider)
}
func assertTrace(t *testing.T, f *bootstrapFakeKMS, creates int) trace {
	t.Helper()
	c, ok := f.snapshot()
	if !ok {
		t.Fatal("KMS request did not use exact supplied name/version, Ed25519 SOFTWARE create template, or signing CRC32C")
	}
	if c.creates != creates {
		t.Fatalf("create count = %d, want %d", c.creates, creates)
	}
	if c.closes != 0 {
		t.Fatalf("provider closed caller-owned client %d times", c.closes)
	}
	return c
}

func TestCreateOrReuse_Case1_AbsentThenRepeatAndOpen(t *testing.T) {
	// GIVEN an explicit named key absent from KMS.
	f := newBootstrapFake(t, false)
	// WHEN bootstrapping, repeating, and opening the exact returned version.
	r, err := bootstrap(t, context.Background(), f, cfg())
	kid := assertResult(t, r, err)
	again, err := bootstrap(t, context.Background(), f, cfg())
	if got := assertResult(t, again, err); got != kid {
		t.Fatalf("repeat kid = %q, want %q", got, kid)
	}
	p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: versionName})
	ownProvider(t, p)
	if err != nil {
		t.Fatalf("ordinary New of returned reference: %v", err)
	}
	// THEN every caller sees the expected public key and usable identical identity.
	if got := assertProvider(t, p); got != kid {
		t.Fatalf("ordinary New kid = %q, want %q", got, kid)
	}
	assertTrace(t, f, 1)
}
func TestCreateOrReuse_Case2_ExistingNeverCreates(t *testing.T) {
	// GIVEN a valid existing deterministic named key/version 1.
	f := newBootstrapFake(t, true)
	var kid string
	for i := 0; i < 3; i++ {
		// WHEN separate callers bootstrap the same explicit configuration.
		r, err := bootstrap(t, context.Background(), f, cfg())
		got := assertResult(t, r, err)
		// THEN signatures verify against the known public identity on every call.
		if i > 0 && got != kid {
			t.Fatalf("identity changed from %q to %q", kid, got)
		}
		kid = got
	}
	assertTrace(t, f, 0)
}
func TestCreateOrReuse_Case3_ConcurrentAtomicWinner(t *testing.T) {
	// GIVEN all initial lookups deterministically observe absence.
	const callers = 6
	f := newBootstrapFake(t, false)
	f.initial = callers
	f.entered = make(chan struct{}, callers)
	f.release = make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var release sync.Once
	unblock := func() { release.Do(func() { close(f.release) }) }
	type outcome struct {
		result *gcpkms.BootstrapResult
		err    error
	}
	results := make(chan outcome, callers)
	var wg sync.WaitGroup
	owners := &concurrentOwners{}
	// Cleanup always releases and cancels before a bounded join. Buffered sends
	// keep late completions from blocking if an earlier assertion fails.
	t.Cleanup(func() {
		unblock()
		cancel()
		joined := make(chan struct{})
		go func() { wg.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("bootstrap workers failed bounded cleanup join")
		}
		owners.shutdown(t)
	})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		callerCtx := context.WithValue(ctx, callerIdentity{}, i+1)
		go func() {
			defer wg.Done()
			r, err := gcpkms.CreateOrReuse(callerCtx, f, cfg())
			owners.acquire(r)
			results <- outcome{r, err}
		}()
	}
	for i := 0; i < callers; i++ {
		select {
		case <-f.entered:
		case <-ctx.Done():
			t.Fatal("not every caller reached initial absence barrier")
		}
	}
	// WHEN released together, one atomic create succeeds, all others AlreadyExists.
	unblock()
	var kid string
	for i := 0; i < callers; i++ {
		var o outcome
		select {
		case o = <-results:
		case <-ctx.Done():
			t.Fatal("concurrent bootstrap did not finish within bound")
		}
		got := assertResult(t, o.result, o.err)
		if i > 0 && got != kid {
			t.Fatalf("concurrent identity %q != winner %q", got, kid)
		}
		kid = got
	}
	// THEN a fresh caller also converges, without another create.
	r, err := bootstrap(t, ctx, f, cfg())
	if got := assertResult(t, r, err); got != kid {
		t.Fatalf("fresh caller kid %q != winner %q", got, kid)
	}
	assertTrace(t, f, callers)
	// Caller-local order cannot be satisfied by surplus reads from other callers.
	f.mu.Lock()
	events := make(map[int][]string, callers)
	for id, sequence := range f.callerEvents {
		events[id] = append([]string(nil), sequence...)
	}
	f.mu.Unlock()
	winners, losers := 0, 0
	for id := 1; id <= callers; id++ {
		sequence := events[id]
		if len(sequence) == 2 && sequence[0] == "initial-absence" && sequence[1] == "create-winner" {
			winners++
		} else if len(sequence) == 3 && sequence[0] == "initial-absence" && sequence[1] == "create-already-exists" && sequence[2] == "exact-winner-read" {
			losers++
		} else {
			t.Fatalf("caller %d did not follow initial absence -> atomic create -> own exact winner read if loser: %v", id, sequence)
		}
	}
	if winners != 1 || losers != callers-1 {
		t.Fatalf("atomic outcomes: winners=%d losers=%d", winners, losers)
	}
}
func TestCreateOrReuse_Case4_NativeFailuresNoRecovery(t *testing.T) {
	sentinel := errors.New("plain caller-visible sentinel")
	failures := []struct {
		name string
		err  error
	}{
		{"PermissionDenied", status.Error(codes.PermissionDenied, "denied")},
		{"Unauthenticated", status.Error(codes.Unauthenticated, "unauthenticated")},
		{"Unavailable", status.Error(codes.Unavailable, "unavailable")},
		{"DeadlineExceeded", status.Error(codes.DeadlineExceeded, "deadline")},
		{"Internal", status.Error(codes.Internal, "internal")},
		{"Canceled", status.Error(codes.Canceled, "canceled")},
		{"sentinel", sentinel}, {"contextCanceled", context.Canceled}, {"contextDeadline", context.DeadlineExceeded},
	}
	for _, stage := range []string{"lookup", "create", "winner", "version", "public"} {
		for _, failure := range failures {
			t.Run(stage+"/"+failure.name, func(t *testing.T) {
				// GIVEN a native dependency failure at exactly one boundary.
				f := newBootstrapFake(t, stage == "version" || stage == "public")
				f.faultAt, f.fault = stage, failure.err
				// WHEN called once, THEN nil result and preserved native status/identity.
				r, err := bootstrap(t, context.Background(), f, cfg())
				if r != nil || err == nil {
					t.Fatalf("failure must return nil result and error, got result=%v error=%v", r, err)
				}
				if !errors.Is(err, failure.err) {
					t.Fatalf("error lost native errors.Is identity: got %v, want %v", err, failure.err)
				}
				if status.Code(err) != status.Code(failure.err) {
					t.Fatalf("native status changed: got %v want %v", status.Code(err), status.Code(failure.err))
				}
				wantCreates := 0
				if stage == "create" || stage == "winner" {
					wantCreates = 1
				}
				c := assertTrace(t, f, wantCreates)
				wantLookups := 1
				if stage == "winner" {
					wantLookups = 2
				}
				if c.lookups != wantLookups {
					t.Fatalf("unauthorized retry/recovery: %d lookups, want %d", c.lookups, wantLookups)
				}
				wantVersions, wantPublics := 0, 0
				if stage == "version" || stage == "public" {
					wantVersions = 1
				}
				if stage == "public" {
					wantPublics = 1
				}
				if c.versions != wantVersions || c.publics != wantPublics || c.signs != 0 {
					t.Fatalf("calls continued across failed boundary: %+v", c)
				}
			})
		}
	}
	// NotFound on the winner/version/public boundary is NOT permission to create.
	for _, stage := range []string{"winner", "version", "public"} {
		t.Run(stage+"/NotFound", func(t *testing.T) {
			f := newBootstrapFake(t, stage != "winner")
			f.faultAt, f.fault = stage, status.Error(codes.NotFound, "missing dependent resource")
			r, err := bootstrap(t, context.Background(), f, cfg())
			if r != nil || status.Code(err) != codes.NotFound {
				t.Fatalf("expected nil/NotFound, got %v / %v", r, err)
			}
			wantCreates, wantLookups := 0, 1
			if stage == "winner" {
				wantCreates, wantLookups = 1, 2
			}
			c := assertTrace(t, f, wantCreates)
			if c.lookups != wantLookups || c.signs != 0 {
				t.Fatalf("unexpected recovery after dependent NotFound: %+v", c)
			}
		})
	}
}
func TestCreateOrReuse_Case5_CommittedTimeoutFreshCallRecovers(t *testing.T) {
	// GIVEN an absent key whose create commits but loses its response.
	f := newBootstrapFake(t, false)
	f.commitTimeout = true
	// WHEN the first bootstrap gets DeadlineExceeded, it must not claim success.
	r, err := bootstrap(t, context.Background(), f, cfg())
	if r != nil || status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("committed timeout must be nil/DeadlineExceeded, got %v / %v", r, err)
	}
	c := assertTrace(t, f, 1)
	if c.lookups != 1 || c.versions != 0 || c.publics != 0 {
		t.Fatalf("first call recovered after ambiguous commit: %+v", c)
	}
	// THEN a separate invocation discovers and verifies the committed winner.
	recovered, err := bootstrap(t, context.Background(), f, cfg())
	kid := assertResult(t, recovered, err)
	repeated, err := bootstrap(t, context.Background(), f, cfg())
	if got := assertResult(t, repeated, err); got != kid {
		t.Fatalf("recovered identity changed: %q != %q", got, kid)
	}
	assertTrace(t, f, 1)
}
