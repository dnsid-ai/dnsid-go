package awskms_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	awskms "github.com/dnsid-ai/dnsid-go/key/aws"
)

// Native create is allowed to return a bare key ID. Only metadata's reference
// differs between cases; the public key, algorithm and usage remain valid.
type createBindingService struct {
	*firstService
	canonical string
}

func (f createBindingService) GetPublicKey(ctx context.Context, in awskms.GetPublicKeyInput) (awskms.GetPublicKeyOutput, error) {
	bare := strings.TrimPrefix(firstARN, "arn:aws:kms:us-east-1:111122223333:key/")
	if in.KeyID != bare && in.KeyID != f.canonical {
		f.t.Errorf("unexpected lookup %q", in.KeyID)
	}
	in.KeyID = firstARN
	out, err := f.firstService.GetPublicKey(ctx, in)
	out.KeyID = f.canonical
	return out, err
}

// Mode: fake-only (malformed native resource binding, real independent crypto).
// Guards: a bare created key ID must match the key ID in its canonical ARN.
// Given a native bare create ID, When metadata reports another canonical key,
// Then Create fails with no provider, duplicate create, signing or deletion.
// Given empty metadata KeyID instead, Then the final immutable-ARN guard rejects
// the bare ID, preserves its recovery reference and leaves caller state unchanged.
// Given its matching canonical ARN instead, Then creation remains legitimate,
// pending and independently proof-signable, not globally rejected as an alias.
func TestCreate_BareIDCanonicalResourceBinding(t *testing.T) {
	for _, tc := range []struct {
		name, canonical string
		reject          bool
	}{
		{"matching", firstARN, false},
		{"empty-public-key-id", "", true},
		{"mismatched", "arn:aws:kms:us-east-1:111122223333:key/22222222-2222-4222-8222-222222222222", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			firstNoFiles(t)
			f := newFirstService(t)
			f.createRef = "11111111-1111-4111-8111-111111111111"
			cfg := firstConfig()
			before := cfg.State
			p, err := awskms.Create(context.Background(), createBindingService{f, tc.canonical}, cfg)
			if !reflect.DeepEqual(cfg.State, before) {
				t.Fatalf("caller state changed: %+v, want %+v", cfg.State, before)
			}
			if tc.reject {
				if err == nil {
					t.Fatalf("accepted bare created ID %q as unrelated canonical ARN %q; provider state=%+v", f.createRef, tc.canonical, p.State())
				}
				if tc.canonical == "" && !strings.Contains(err.Error(), "has no immutable KMS key ARN") {
					t.Fatalf("want final immutable-ARN guard rejection, got %v", err)
				}
				if !strings.Contains(err.Error(), f.createRef) {
					t.Fatalf("error lost original bare created key recovery reference %q: %v", f.createRef, err)
				}
				if p != nil {
					t.Fatal("binding failure returned provider")
				}
				if f.signs != 0 {
					t.Fatal("binding failure signed with substituted key")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if p == nil {
					t.Fatal("matching bare ID returned no provider")
				}
				state := p.State()
				if state.ActiveKeyID != "" || len(state.PendingKeyIDs) != 1 || state.PendingKeyIDs[0] != firstARN {
					t.Fatalf("matching key not canonical pending: %+v", state)
				}
				_, pub := firstFixture(t)
				firstJWK(t, p.JWK(firstARN), firstARN, pub)
				payload := []byte("legitimate matching bare resource")
				sig, e := p.SignKey(firstARN, payload)
				firstSignature(t, sig, e, firstARN, payload, pub)
			}
			if f.creates != 1 || f.deletes != 0 {
				t.Fatalf("creates=%d deletions=%d", f.creates, f.deletes)
			}
		})
	}
}

// Reuse the binding fixture while allowing an established active/retained state
// and recording the exact cleanup target rather than rejecting all deletion.
type generateBindingService struct {
	createBindingService
	deleted []string
}

func (f *generateBindingService) GetPublicKey(ctx context.Context, in awskms.GetPublicKeyInput) (awskms.GetPublicKeyOutput, error) {
	if in.KeyID == "active" || in.KeyID == "retained" || in.KeyID == "pending" {
		out, err := f.firstService.GetPublicKey(ctx, awskms.GetPublicKeyInput{KeyID: firstARN})
		out.KeyID = in.KeyID
		return out, err
	}
	return f.createBindingService.GetPublicKey(ctx, in)
}

func (f *generateBindingService) ScheduleKeyDeletion(_ context.Context, in awskms.ScheduleKeyDeletionInput) error {
	f.deleted = append(f.deleted, in.KeyID)
	return nil
}

// Mode: fake-only (substituted native public metadata).
// Given an established signer and opt-in failed-generation cleanup,
// When a bare created ID resolves to valid metadata for another canonical ARN,
// Then return and delete only the original ID once, preserving lifecycle state.
func TestGenerateKey_BareIDBindingMismatchDeletesOriginal(t *testing.T) {
	base := newFirstService(t)
	base.created = true // The active and retained fixture keys already exist.
	base.createRef = "11111111-1111-4111-8111-111111111111"
	f := &generateBindingService{createBindingService: createBindingService{
		firstService: base,
		canonical:    "arn:aws:kms:us-east-1:111122223333:key/22222222-2222-4222-8222-222222222222",
	}}
	cfg := firstConfig()
	cfg.State = awskms.State{ActiveKeyID: "active", RetainedKeyIDs: []string{"retained"}}
	cfg.ScheduleDeletionOnPurge = true
	p, err := awskms.Load(context.Background(), f, cfg)
	if err != nil {
		t.Fatal(err)
	}
	before := p.State()
	kid, err := p.GenerateKey(dnsid.JoseAlgEdDSA)
	if err == nil || !strings.Contains(err.Error(), "created key binding mismatch") || kid != base.createRef {
		t.Fatalf("GenerateKey = (%q, %v), want original created ID and binding mismatch", kid, err)
	}
	if base.creates != 1 {
		t.Fatalf("creates = %d, want exactly one", base.creates)
	}
	if !reflect.DeepEqual(f.deleted, []string{base.createRef}) {
		t.Fatalf("deleted = %v, want only original created ID %q once", f.deleted, base.createRef)
	}
	if after := p.State(); !reflect.DeepEqual(after, before) || len(after.PendingKeyIDs) != 0 {
		t.Fatalf("state = %+v, want unchanged %+v and no phantom pending key", after, before)
	}
}

// Only the uncached newly created key waits. Load's existing-key reads remain
// immediate; the valid output is prepared before synchronizing on the real
// operation deadline. Returning nil error leaves the late verdict to production.
type lateDeadlineService struct {
	*generateBindingService
	expiredOperation context.Context
}

func (f *lateDeadlineService) GetPublicKey(ctx context.Context, in awskms.GetPublicKeyInput) (awskms.GetPublicKeyOutput, error) {
	out, err := f.generateBindingService.GetPublicKey(ctx, in)
	if err != nil || in.KeyID != f.createRef {
		return out, err
	}
	f.expiredOperation = ctx
	// Bound a broken fixture independently of the configured operation timeout.
	outer := time.NewTimer(2 * time.Second)
	defer outer.Stop()
	select {
	case <-ctx.Done():
	case <-outer.C:
		f.t.Fatal("new-key public read did not observe the operation deadline")
	}
	return out, nil
}

func (f *lateDeadlineService) ScheduleKeyDeletion(ctx context.Context, in awskms.ScheduleKeyDeletionInput) error {
	if f.expiredOperation == nil || !errors.Is(f.expiredOperation.Err(), context.DeadlineExceeded) {
		f.t.Error("cleanup did not follow the expired generation operation")
	}
	if ctx == f.expiredOperation || ctx.Err() != nil {
		f.t.Error("cleanup reused expired generation context")
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) {
		f.t.Error("cleanup context has no fresh unexpired deadline")
	}
	return f.generateBindingService.ScheduleKeyDeletion(ctx, in)
}

// Mode: fake-only (successful native public read after operation expiry).
// Given active, retained and pending keys and opt-in rotation cleanup, When a
// distinct new key validates after its deadline, Then return and delete only
// its original ID once without changing lifecycle state. Cache rollback is not
// required: validated public material is separate from lifecycle registration.
func TestGenerateKey_LateDeadlineDeletesOriginal(t *testing.T) {
	base := newFirstService(t)
	base.created = true
	base.createRef = "11111111-1111-4111-8111-111111111111"
	f := &lateDeadlineService{generateBindingService: &generateBindingService{
		createBindingService: createBindingService{firstService: base, canonical: firstARN},
	}}
	cfg := firstConfig()
	cfg.State = awskms.State{ActiveKeyID: "active", RetainedKeyIDs: []string{"retained"}, PendingKeyIDs: []string{"pending"}}
	cfg.ScheduleDeletionOnPurge = true
	cfg.OperationTimeout = 100 * time.Millisecond
	p, err := awskms.Load(context.Background(), f, cfg)
	if err != nil {
		t.Fatal(err)
	}
	before := p.State()
	readsBefore := base.reads
	kid, err := p.GenerateKey(dnsid.JoseAlgEdDSA)
	if kid != base.createRef || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GenerateKey = (%q, %v), want original created ID and deadline exceeded", kid, err)
	}
	if base.creates != 1 || base.reads != readsBefore+1 || base.signs != 0 {
		t.Fatalf("creates=%d new reads=%d signs=%d, want 1/1/0", base.creates, base.reads-readsBefore, base.signs)
	}
	if !reflect.DeepEqual(f.deleted, []string{base.createRef}) {
		t.Fatalf("deleted = %v, want only original created ID %q once", f.deleted, base.createRef)
	}
	if after := p.State(); !reflect.DeepEqual(after, before) {
		t.Fatalf("state = %+v, want unchanged %+v", after, before)
	}
}
