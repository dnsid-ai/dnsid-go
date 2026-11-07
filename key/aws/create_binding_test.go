package awskms_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

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
// Given its matching canonical ARN instead, Then creation remains legitimate,
// pending and independently proof-signable, not globally rejected as an alias.
func TestCreate_BareIDCanonicalResourceBinding(t *testing.T) {
	for _, tc := range []struct {
		name, canonical string
		reject          bool
	}{
		{"matching", firstARN, false},
		{"mismatched", "arn:aws:kms:us-east-1:111122223333:key/22222222-2222-4222-8222-222222222222", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			firstNoFiles(t)
			f := newFirstService(t)
			f.createRef = "11111111-1111-4111-8111-111111111111"
			p, err := awskms.Create(context.Background(), createBindingService{f, tc.canonical}, firstConfig())
			if tc.reject {
				if err == nil {
					t.Fatalf("accepted bare created ID %q as unrelated canonical ARN %q; provider state=%+v", f.createRef, tc.canonical, p.State())
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
	if in.KeyID == "active" || in.KeyID == "retained" {
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
