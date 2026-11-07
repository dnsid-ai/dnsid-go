package awskms_test

import (
	"context"
	"strings"
	"testing"

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
// Guards: independent review F1, created bare ID bound to unrelated canonical ARN.
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
