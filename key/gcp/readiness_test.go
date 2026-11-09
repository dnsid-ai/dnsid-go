package gcpkms_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	dnsid "github.com/dnsid-ai/dnsid-go"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/proto"
)

type readinessKMS struct {
	*gatedGenerationKMS
	mu                               sync.Mutex
	initial                          *kmspb.CryptoKeyVersion
	responses                        []*kmspb.CryptoKeyVersion
	metadataErr                      error
	creates, gets, publicReads       int
	enabled                          bool
	metadataEntered, metadataRelease chan struct{}
}

func readyMetadata(state kmspb.CryptoKeyVersion_CryptoKeyVersionState) *kmspb.CryptoKeyVersion {
	return &kmspb.CryptoKeyVersion{Name: successorVersion, Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, State: state, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}
}
func readinessFake(t *testing.T) *readinessKMS {
	return &readinessKMS{gatedGenerationKMS: newGatedGenerationKMS(t, ""), initial: readyMetadata(kmspb.CryptoKeyVersion_PENDING_GENERATION), responses: []*kmspb.CryptoKeyVersion{readyMetadata(kmspb.CryptoKeyVersion_PENDING_GENERATION), readyMetadata(kmspb.CryptoKeyVersion_ENABLED)}}
}
func (f *readinessKMS) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	if req.GetParent() != "projects/test-project/locations/global/keyRings/agents/cryptoKeys/signing" {
		return nil, errors.New("wrong create parent")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.initial == nil {
		return nil, nil
	}
	f.enabled = f.initial.State == kmspb.CryptoKeyVersion_ENABLED
	return proto.Clone(f.initial).(*kmspb.CryptoKeyVersion), nil
}
func (f *readinessKMS) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	if req.GetName() != successorVersion {
		return nil, errors.New("metadata request changed immutable version")
	}
	if f.metadataEntered != nil {
		select {
		case f.metadataEntered <- struct{}{}:
		default:
		}
		select {
		case <-f.metadataRelease:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	if f.metadataErr != nil {
		return nil, f.metadataErr
	}
	if len(f.responses) == 0 {
		return nil, errors.New("unexpected extra metadata read")
	}
	response := f.responses[0]
	f.responses = f.responses[1:]
	if response == nil {
		return nil, nil
	}
	f.enabled = response.State == kmspb.CryptoKeyVersion_ENABLED
	return proto.Clone(response).(*kmspb.CryptoKeyVersion), nil
}
func (f *readinessKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	if req.GetName() == successorVersion {
		f.mu.Lock()
		f.publicReads++
		enabled := f.enabled
		f.mu.Unlock()
		if !enabled {
			return nil, errors.New("public key read before metadata ENABLED")
		}
	}
	return f.gatedGenerationKMS.GetPublicKey(ctx, req, opts...)
}
func (f *readinessKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	signer := lifecycleFake(f.t)
	signer.fakeKMS = f.fakeKMS
	return signer.AsymmetricSign(ctx, req, opts...)
}
func (f *readinessKMS) counts() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.creates, f.gets, f.publicReads
}

// Mode: fake-only (scripted normal KMS readiness transition, real cryptography).
// Given cloud PENDING_GENERATION, When exact metadata remains pending then is
// enabled, Then one create yields a usable locally pending key, never activates.
func TestGenerateKeyPendingReadinessSucceeds(t *testing.T) {
	f := readinessFake(t)
	p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
	if err != nil {
		t.Fatal(err)
	}
	old := lifecycleKid(t, p)
	pending, err := p.GenerateKey(dnsid.JoseAlgEdDSA)
	if err != nil || pending == "" {
		t.Fatalf("normal pending-to-enabled generation must succeed: kid=%q err=%v", pending, err)
	}
	if c, g, r := f.counts(); c != 1 || g != 2 || r != 1 {
		t.Fatalf("create/metadata/public reads=%d/%d/%d want 1/2/1", c, g, r)
	}
	if lifecycleKid(t, p) != old || !reflect.DeepEqual(p.ListKeyIds(), []string{old}) {
		t.Fatal("readiness changed active inventory")
	}
	// The lifecycle fake independently signs with the known successor private key.
	signer := lifecycleFake(t)
	signer.want = []byte("ready successor proof")
	// Use the same scripted service's actual signing route for pending proof.
	f.want = signer.want
	sig, err := p.SignKey(pending, f.want)
	lifecycleSignature(t, sig, err, pending, f.want, signer.successor.Public().(ed25519.PublicKey))
}

// Mode: fake-only (immediately enabled metadata and optional-getter detector).
// Given ENABLED at creation, When generating, Then no metadata getter is needed.
func TestGenerateKeyEnabledSkipsReadinessGet(t *testing.T) {
	f := readinessFake(t)
	f.initial.State = kmspb.CryptoKeyVersion_ENABLED
	p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
	if err != nil {
		t.Fatal(err)
	}
	if kid, err := p.GenerateKey(dnsid.JoseAlgEdDSA); err != nil || kid == "" {
		t.Fatalf("immediate enabled: kid=%q err=%v", kid, err)
	}
	if c, g, r := f.counts(); c != 1 || g != 0 || r != 1 {
		t.Fatalf("create/metadata/public=%d/%d/%d want 1/0/1", c, g, r)
	}
}

// Mode: fake-only (terminal/invalid metadata and native RPC failures).
// Given an active signer, When readiness cannot be authenticated, Then no
// candidate escapes, no public read occurs and active signing remains valid.
func TestGenerateKeyReadinessFailurePreservesState(t *testing.T) {
	native := errors.New("metadata permission denied")
	cases := []string{"nil initial", "wrong initial name", "wrong initial parent", "mutable initial name", "wrong initial algorithm", "wrong initial protection", "initial disabled", "nil fetched", "wrong fetched name", "wrong fetched algorithm", "wrong fetched protection", "native error", "disabled", "destroyed", "destroy scheduled", "import failed", "pending import", "generation failed", "unspecified"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			f := readinessFake(t)
			fetched := readyMetadata(kmspb.CryptoKeyVersion_ENABLED)
			f.responses = []*kmspb.CryptoKeyVersion{fetched}
			switch name {
			case "nil initial":
				f.initial = nil
			case "wrong initial name":
				f.initial.Name = version
			case "wrong initial parent":
				f.initial.Name = "projects/other/locations/global/keyRings/agents/cryptoKeys/signing/cryptoKeyVersions/2"
			case "mutable initial name":
				f.initial.Name = "projects/test-project/locations/global/keyRings/agents/cryptoKeys/signing/cryptoKeyVersions/latest"
			case "wrong initial algorithm":
				f.initial.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
			case "wrong initial protection":
				f.initial.ProtectionLevel = kmspb.ProtectionLevel_HSM
			case "initial disabled":
				f.initial.State = kmspb.CryptoKeyVersion_DISABLED
			case "nil fetched":
				f.responses = []*kmspb.CryptoKeyVersion{nil}
			case "wrong fetched name":
				fetched.Name = version
			case "wrong fetched algorithm":
				fetched.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
			case "wrong fetched protection":
				fetched.ProtectionLevel = kmspb.ProtectionLevel_HSM
			case "native error":
				f.metadataErr = native
			case "disabled":
				fetched.State = kmspb.CryptoKeyVersion_DISABLED
			case "destroyed":
				fetched.State = kmspb.CryptoKeyVersion_DESTROYED
			case "destroy scheduled":
				fetched.State = kmspb.CryptoKeyVersion_DESTROY_SCHEDULED
			case "import failed":
				fetched.State = kmspb.CryptoKeyVersion_IMPORT_FAILED
			case "pending import":
				fetched.State = kmspb.CryptoKeyVersion_PENDING_IMPORT
			case "generation failed":
				fetched.State = kmspb.CryptoKeyVersion_GENERATION_FAILED
			case "unspecified":
				fetched.State = kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_STATE_UNSPECIFIED
			}
			f.want = []byte("still active after readiness failure")
			p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
			if err != nil {
				t.Fatal(err)
			}
			old := lifecycleKid(t, p)
			kid, err := p.GenerateKey(dnsid.JoseAlgEdDSA)
			if err == nil || kid != "" {
				t.Fatalf("invalid readiness accepted: kid=%q err=%v", kid, err)
			}
			if name == "native error" && !errors.Is(err, native) {
				t.Errorf("native metadata error lost: %v", err)
			}
			_, gets, reads := f.counts()
			if name != "nil initial" && name != "wrong initial name" && name != "wrong initial parent" && name != "mutable initial name" && name != "wrong initial algorithm" && name != "wrong initial protection" && name != "initial disabled" && gets != 1 {
				t.Errorf("fetched readiness case made %d metadata reads, want 1", gets)
			}
			if reads != 0 {
				t.Error("failed readiness read candidate public key")
			}
			if lifecycleKid(t, p) != old || !reflect.DeepEqual(p.ListKeyIds(), []string{old}) {
				t.Fatal("failed readiness changed active inventory")
			}
			sig, err := p.Sign(f.want)
			_, public := fixture(t)
			lifecycleSignature(t, sig, err, old, f.want, public)
		})
	}
}

// Mode: fake-only (held metadata RPC, real active Ed25519 signature).
// Given a normal pending version, When metadata I/O waits, Then active Sign
// completes before release and generation subsequently succeeds without activation.
func TestGenerateKeyReadinessWaitDoesNotBlockSign(t *testing.T) {
	f := readinessFake(t)
	f.metadataEntered = make(chan struct{}, 1)
	f.metadataRelease = make(chan struct{})
	f.want = []byte("active during readiness")
	p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
	if err != nil {
		t.Fatal(err)
	}
	old := lifecycleKid(t, p)
	generated := make(chan generationResult, 1)
	go func() { kid, err := p.GenerateKey(dnsid.JoseAlgEdDSA); generated <- generationResult{kid, err} }()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(f.metadataRelease) }) }
	defer release()
	select {
	case <-f.metadataEntered:
	case result := <-generated:
		t.Fatalf("generation returned before readiness metadata: kid=%q err=%v", result.kid, result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("readiness never entered metadata RPC")
	}
	signed := make(chan signingResult, 1)
	go func() { sig, err := p.Sign(f.want); signed <- signingResult{sig, err} }()
	select {
	case result := <-signed:
		_, public := fixture(t)
		lifecycleSignature(t, result.sig, result.err, old, f.want, public)
	case <-time.After(2 * time.Second):
		t.Error("readiness metadata I/O blocked active Sign")
	}
	// Close through a helper so deferred cleanup and normal completion share ownership.
	release()
	select {
	case result := <-generated:
		if result.err != nil || result.kid == "" {
			t.Fatalf("released readiness failed: %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("released readiness did not finish")
	}
}

// Deliberately exposes only the original runtime client methods: opening and
// immediately enabled generation must not acquire a mandatory metadata method.
type pendingWithoutGetter struct{ *gatedGenerationKMS }

func (f *pendingWithoutGetter) CreateCryptoKeyVersion(context.Context, *kmspb.CreateCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	return readyMetadata(kmspb.CryptoKeyVersion_PENDING_GENERATION), nil
}

// Mode: fake-only (runtime client lacking the optional generation getter).
// Given no metadata capability, When creation is pending, Then fail clearly
// without inserting a key or disturbing active signing.
func TestGenerateKeyPendingWithoutGetterFailsClosed(t *testing.T) {
	f := &pendingWithoutGetter{newGatedGenerationKMS(t, "")}
	f.want = []byte("missing optional getter")
	p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
	if err != nil {
		t.Fatal(err)
	}
	old := lifecycleKid(t, p)
	kid, err := p.GenerateKey(dnsid.JoseAlgEdDSA)
	if err == nil || kid != "" {
		t.Fatalf("pending without getter accepted: kid=%q err=%v", kid, err)
	}
	if lifecycleKid(t, p) != old || !reflect.DeepEqual(p.ListKeyIds(), []string{old}) {
		t.Fatal("missing getter changed active inventory")
	}
	sig, err := p.Sign(f.want)
	_, public := fixture(t)
	lifecycleSignature(t, sig, err, old, f.want, public)
}

// Mode: fake-only (normal readiness followed by corrupt public response).
// Given valid enabled metadata but corrupt public integrity evidence, When
// generation opens the candidate, Then no insertion or activation occurs.
func TestGenerateKeyReadinessPublicIntegrityFailure(t *testing.T) {
	f := readinessFake(t)
	f.candidate.PemCrc32C.Value ^= 1
	p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
	if err != nil {
		t.Fatal(err)
	}
	old := lifecycleKid(t, p)
	kid, err := p.GenerateKey(dnsid.JoseAlgEdDSA)
	if err == nil || kid != "" {
		t.Fatalf("corrupt ready candidate accepted: kid=%q err=%v", kid, err)
	}
	if c, g, r := f.counts(); c != 1 || g != 2 || r != 1 {
		t.Fatalf("integrity case did not reach ready public validation: %d/%d/%d", c, g, r)
	}
	if lifecycleKid(t, p) != old || !reflect.DeepEqual(p.ListKeyIds(), []string{old}) {
		t.Fatal("corrupt ready candidate changed active inventory")
	}
}
