package gcpkms

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"reflect"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const contextVersion = "projects/test-project/locations/global/keyRings/agents/cryptoKeys/signing/cryptoKeyVersions/1"
const contextCandidate = "projects/test-project/locations/global/keyRings/agents/cryptoKeys/signing/cryptoKeyVersions/2"

type contextRPC struct {
	stage string
	ctx   context.Context
}
type contextKMS struct {
	mu      sync.Mutex
	calls   []contextRPC
	mode    string
	entered chan struct{}
	pending chan struct{}
	gets    int
}

func contextMetadata(state kmspb.CryptoKeyVersion_CryptoKeyVersionState) *kmspb.CryptoKeyVersion {
	return &kmspb.CryptoKeyVersion{Name: contextCandidate, Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE, State: state}
}
func (f *contextKMS) record(stage string, ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, contextRPC{stage, ctx})
}
func contextPrivate(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("independent readiness context fixture " + name))
	return ed25519.NewKeyFromSeed(seed[:])
}
func contextCRC(b []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))))
}
func (f *contextKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	f.record("public:"+req.GetName(), ctx)
	if req.GetName() != contextVersion && req.GetName() != contextCandidate {
		return nil, errors.New("unexpected version")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(contextPrivate(req.GetName()).Public())
	if err != nil {
		return nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &kmspb.PublicKey{Name: req.GetName(), Pem: string(encoded), PemCrc32C: contextCRC(encoded), Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}
func (f *contextKMS) CreateCryptoKeyVersion(ctx context.Context, _ *kmspb.CreateCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.record("create", ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return contextMetadata(kmspb.CryptoKeyVersion_PENDING_GENERATION), nil
}
func (f *contextKMS) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.record("metadata", ctx)
	if req.GetName() != contextCandidate {
		return nil, errors.New("metadata changed exact version")
	}
	if f.mode == "get" {
		close(f.entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.gets++
	if f.gets == 1 {
		if f.pending != nil {
			close(f.pending)
		}
		return contextMetadata(kmspb.CryptoKeyVersion_PENDING_GENERATION), nil
	}
	return contextMetadata(kmspb.CryptoKeyVersion_ENABLED), nil
}
func (f *contextKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sig := ed25519.Sign(contextPrivate(req.GetName()), req.GetData())
	return &kmspb.AsymmetricSignResponse{Name: req.GetName(), Signature: sig, SignatureCrc32C: contextCRC(sig), VerifiedDataCrc32C: true, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}
func contextProvider(t *testing.T, f *contextKMS) (*Provider, string) {
	t.Helper()
	p, err := New(context.Background(), f, Config{KeyVersionName: contextVersion})
	if err != nil {
		t.Fatal(err)
	}
	old, _ := p.JWK().KeyID()
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
	return p, old
}
func assertContextFailureState(t *testing.T, p *Provider, old string) {
	t.Helper()
	active, _ := p.JWK().KeyID()
	if active != old || !reflect.DeepEqual(p.ListKeyIds(), []string{old}) {
		t.Fatal("cancel/deadline changed active inventory")
	}
	payload := []byte("active after cancelled generation")
	sig, err := p.Sign(payload)
	if err != nil || sig == nil || sig.Kid != old || !ed25519.Verify(contextPrivate(contextVersion).Public().(ed25519.PublicKey), payload, sig.Signature) {
		t.Fatalf("active signature invalid after cancellation: %+v %v", sig, err)
	}
}

type contextResult struct {
	kid string
	err error
}

func awaitContextResult(t *testing.T, result <-chan contextResult) contextResult {
	t.Helper()
	select {
	case r := <-result:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("generation ignored context while RPC/delay held")
		return contextResult{}
	}
}

// Mode: fake-only (cancel-aware held metadata RPC; real Ed25519 provider).
// Given a pending cloud version, When cancellation or the existing budget
// expires inside metadata get, Then native context error survives and no insert.
func TestGenerateKeyContextDuringMetadataGet(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			f := &contextKMS{mode: "get", entered: make(chan struct{})}
			p, old := contextProvider(t, f)
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			result := make(chan contextResult, 1)
			go func() {
				kid, err := p.generateKey(ctx, dnsid.JoseAlgEdDSA, time.Hour)
				result <- contextResult{kid, err}
			}()
			select {
			case <-f.entered:
			case <-time.After(time.Second):
				t.Fatal("metadata get not reached")
			}
			if !deadline {
				cancel()
			}
			r := awaitContextResult(t, result)
			want := context.Canceled
			if deadline {
				want = context.DeadlineExceeded
			}
			if r.kid != "" || !errors.Is(r.err, want) {
				t.Fatalf("context error lost: kid=%q err=%v want %v", r.kid, r.err, want)
			}
			assertContextFailureState(t, p, old)
			assertOperationContexts(t, f, ctx, false)
		})
	}
}

// Mode: fake-only (pending observation plus hour-long interval, short context).
// Given a repeated pending observation, When cancelled/deadlined during the
// context-aware interval, Then return promptly without another get/public read.
func TestGenerateKeyContextDuringReadinessDelay(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			f := &contextKMS{pending: make(chan struct{})}
			p, old := contextProvider(t, f)
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			result := make(chan contextResult, 1)
			go func() {
				kid, err := p.generateKey(ctx, dnsid.JoseAlgEdDSA, time.Hour)
				result <- contextResult{kid, err}
			}()
			select {
			case <-f.pending:
			case <-time.After(time.Second):
				t.Fatal("pending metadata not observed")
			}
			if !deadline {
				cancel()
			}
			r := awaitContextResult(t, result)
			want := context.Canceled
			if deadline {
				want = context.DeadlineExceeded
			}
			if r.kid != "" || !errors.Is(r.err, want) {
				t.Fatalf("delay lost context error: kid=%q err=%v want %v", r.kid, r.err, want)
			}
			if f.gets != 1 {
				t.Fatalf("delay cancellation made %d metadata reads want 1", f.gets)
			}
			assertContextFailureState(t, p, old)
			assertOperationContexts(t, f, ctx, false)
		})
	}
}
func assertOperationContexts(t *testing.T, f *contextKMS, want context.Context, public bool) {
	t.Helper()
	f.mu.Lock()
	calls := append([]contextRPC(nil), f.calls...)
	f.mu.Unlock()
	stages := []string{}
	for _, call := range calls {
		stages = append(stages, call.stage)
		if call.ctx != want {
			t.Errorf("%s replaced operation context/budget", call.stage)
		}
		gotDeadline, gotOK := call.ctx.Deadline()
		wantDeadline, wantOK := want.Deadline()
		if gotOK != wantOK || !gotDeadline.Equal(wantDeadline) {
			t.Errorf("%s renewed operation deadline", call.stage)
		}
	}
	expected := []string{"create", "metadata"}
	if public {
		expected = append(expected, "metadata", "public:"+contextCandidate)
	}
	if !reflect.DeepEqual(stages, expected) {
		t.Fatalf("operation stages=%v want %v", stages, expected)
	}
}

// Mode: fake-only (scripted metadata, real public-key validation and crypto).
// Given one context/deadline, When readiness completes, Then create, every get
// and candidate public opening use that identical context with no renewed budget.
// This private helper proof does not establish public GenerateKey wiring alone.
func TestGenerateKeyOneContextThroughPublicOpening(t *testing.T) {
	f := &contextKMS{}
	p, old := contextProvider(t, f)
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), struct{}{}, "operation"), time.Second)
	defer cancel()
	kid, err := p.generateKey(ctx, dnsid.JoseAlgEdDSA, time.Nanosecond)
	if err != nil || kid == "" || kid == old {
		t.Fatalf("ready candidate failed: kid=%q err=%v", kid, err)
	}
	assertOperationContexts(t, f, ctx, true)
	assertContextFailureState(t, p, old)
}
