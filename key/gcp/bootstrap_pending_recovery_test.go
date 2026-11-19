package gcpkms_test

import (
	"reflect"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
)

// Mode: fake-only (service readiness changes between explicit invocations).
// Contract: key/gcp/README.md, pending version 1 and later separate invocation.
func TestCreateOrReuse_PendingThenEnabledSeparateCalls(t *testing.T) {
	// GIVEN an absent named key whose successful create commits compatible
	// version 1, initially pending. Readiness never advances inside an RPC.
	base := newBootstrapFake(t, false)
	enabled := false
	client := &additionalResponses{
		bootstrapFakeKMS: base,
		version: func(v *kmspb.CryptoKeyVersion) *kmspb.CryptoKeyVersion {
			if !enabled {
				v.State = kmspb.CryptoKeyVersion_PENDING_GENERATION
			}
			return v
		},
	}
	config := cfg()

	// WHEN the first explicit call returns while that version is pending,
	// THEN no signer escapes, and no polling, public read or signing occurs.
	r, err := additionalCall(t, client, config)
	additionalReject(t, r, err) // No error class, message or retryability promise.
	first := assertTrace(t, base, 1)
	if first != (trace{lookups: 1, creates: 1, versions: 1}) {
		t.Fatalf("pending call did extra work: %+v", first)
	}
	if !reflect.DeepEqual(client.events, []string{"lookup", "create", "version"}) {
		t.Fatalf("pending call order: %v", client.events)
	}
	base.mu.Lock()
	committed := base.exists
	base.mu.Unlock()
	if !committed {
		t.Fatal("fake create did not commit the named key")
	}

	// Only AFTER the first call returned, the fake service independently
	// enables the SAME version. Its fixed public material comes from the
	// standard-library seed fixture, never from a returned provider.
	enabled = true
	client.events = nil
	// WHEN the caller explicitly invokes the identical scope a second time,
	recovered, err := additionalCall(t, client, config)
	// THEN exact version 1 is reused, with independently expected public JWK
	// and signatures verified against the fixed public oracle (assertResult).
	assertResult(t, recovered, err)
	if !reflect.DeepEqual(client.events, []string{"lookup", "version", "public"}) {
		t.Fatalf("second call did not reuse exact winner: %v", client.events)
	}
	second := assertTrace(t, base, 1)
	if second != (trace{lookups: 2, creates: 1, versions: 2, publics: 1, signs: 2}) {
		t.Fatalf("second call replaced key or did unexpected work: %+v", second)
	}
}
