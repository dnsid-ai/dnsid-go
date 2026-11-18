package gcpkms_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type recoveryReadinessService struct {
	*firstService
	cause  error
	cancel context.CancelFunc
}

func (f *recoveryReadinessService) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.gets++
	if req.GetName() != firstVersion {
		f.t.Error("readiness substituted version")
	}
	if f.cancel != nil {
		f.cancel()
		return nil, ctx.Err()
	}
	return nil, f.cause
}

// Mode: fake-only (native service faults and cancellation, no cloud resources).
// Given create returned a known first immutable version, when later readiness or
// public validation fails, then the caller's error retains that recovery binding
// and original cause without recreating, activating, deleting or substituting.
func TestCreate_PostCreateErrorRetainsRecoveryReference(t *testing.T) {
	denied := status.Error(codes.PermissionDenied, "fixture metadata/public permission denied")
	for _, fault := range []string{"readiness-permission", "readiness-canceled", "public-permission", "public-binding", "public-crc"} {
		t.Run(fault, func(t *testing.T) {
			firstNoFiles(t)
			base := newFirstService(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := &recoveryReadinessService{firstService: base, cause: denied}
			var cause error
			switch fault {
			case "readiness-permission":
				base.pending = true
				cause = denied
			case "readiness-canceled":
				base.pending = true
				f.cancel = cancel
				cause = context.Canceled
			case "public-permission":
				base.publicErr = denied
				cause = denied
			case "public-binding":
				base.mutatePublic = func(v *kmspb.PublicKey) { v.Name = firstVersion + "9" }
			case "public-crc":
				base.mutatePublic = func(v *kmspb.PublicKey) { v.PemCrc32C.Value ^= 1 }
			}
			p, _, _, err := gcpkms.Create(ctx, f, firstParent)
			if err == nil {
				t.Fatal("post-create failure returned success")
			}
			if cause != nil && !errors.Is(err, cause) {
				t.Errorf("lost original cause: %v", err)
			}
			if errors.Is(cause, denied) && status.Code(err) != codes.PermissionDenied {
				t.Errorf("lost permission status: %v", err)
			}
			if p != nil {
				if len(p.ListKeyIds()) != 0 || p.JWK() != nil {
					t.Error("failure exposed active signer")
				}
				if _, signErr := p.Sign([]byte("no fallback")); signErr == nil {
					t.Error("failure substituted signer")
				}
			}
			if base.creates != 1 || !base.created || base.signs != 0 || base.closes != 0 {
				t.Errorf("unexpected create/sign/close: %+v", base)
			}
			if base.pending && (base.gets != 1 || base.publics != 0) {
				t.Error("readiness failure opened public key or retried")
			}
			if !strings.Contains(err.Error(), firstVersion) {
				t.Errorf("post-create error omitted known recovery version %q: %v", firstVersion, err)
			}
		})
	}
}
