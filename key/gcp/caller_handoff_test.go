package gcpkms_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Mode: real-capable (GCP fake here). Creation counts, client ownership, and
// setup-directory no-file checks are separate fake-only invariants.
// Given a parent with no prior version and separate caller-owned entity custody,
// When Create hands the caller a provider, pending kid, and immutable reference,
// Then only those returned handoff values drive pending proof, explicit Activate
// on the SAME provider, real manager composition, and saved-reference reopen.
// Fixture keys/thumbprints are independent oracles, never discovery inputs.
// This is local provider activation, not protocol issuance or publication.
func TestCreate_CallerHandoff(t *testing.T) {
	// Independent entity fixture, no SDK private-key generation/import helpers.
	seed := sha256.Sum256([]byte("Go58 caller-owned entity custody independent of RFC8032 service fixture"))
	entityPrivate := ed25519.NewKeyFromSeed(seed[:])
	entityPublic := entityPrivate.Public().(ed25519.PublicKey)
	entityKey, err := jwk.Import(entityPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err = entityKey.Set("kid", firstThumb(entityPublic)); err != nil {
		t.Fatal(err)
	}
	if err = entityKey.Set("alg", "EdDSA"); err != nil {
		t.Fatal(err)
	}
	entity := &firstSetupEntity{key: entityKey, private: entityPrivate}
	f := newFirstService(t)
	_, pub := firstFixture(t)
	firstNoFiles(t)
	p, kid, ref, err := gcpkms.Create(context.Background(), f, firstParent)
	if err != nil {
		t.Fatal(err)
	}
	if kid != firstThumb(pub) {
		t.Fatalf("returned pending kid=%q want independent thumbprint %q", kid, firstThumb(pub))
	}
	if ref != firstVersion {
		t.Fatalf("not immutable first version: %q", ref)
	}
	if len(p.ListKeyIds()) != 0 || p.JWK() != nil {
		t.Fatal("create implicitly activated")
	}
	if _, err := p.Sign([]byte("pending")); err == nil {
		t.Fatal("pending application signing allowed")
	}
	firstJWK(t, p.JWK(kid), kid, pub)
	payload := []byte("caller handoff possession, not protocol issuance")
	sig, err := p.SignKey(kid, payload)
	firstSignature(t, sig, err, kid, payload, pub)
	if len(p.ListKeyIds()) != 0 || p.JWK() != nil {
		t.Fatal("pending proof implicitly activated the provider")
	}
	if _, err := p.Sign(payload); err == nil {
		t.Fatal("pending proof enabled ordinary application signing")
	}
	if err := p.Activate(kid); err != nil {
		t.Fatal(err)
	}
	if ids := p.ListKeyIds(); len(ids) != 1 || ids[0] != kid {
		t.Fatalf("same-provider activation listing=%v want [%s]", ids, kid)
	}
	firstJWK(t, p.JWK(), kid, pub)
	sig, err = p.Sign(payload)
	firstSignature(t, sig, err, kid, payload, pub)
	cfg := dnsid.Config{Identity: &dnsid.IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", StatusURL: "https://agent.example.com/status", KeyURL: "https://agent.example.com/jwks", EntityKeyURL: "https://example.com/entity-jwks", LogRef: "c2sp-tlog:public:https://log.example.com#issuance_AAAAAAAAAAAAAAAAAAAAAA"}}
	manager, err := dnsid.NewIdentityManager(cfg, p, dnsid.WithEntityKeyProvider(entity))
	if err != nil {
		t.Fatal(err)
	}
	check := func(set *dnsid.JWKS, want ed25519.PublicKey, wantKid string) string {
		t.Helper()
		if set == nil {
			t.Fatal("missing manager public JWKS")
		}
		raw, e := json.Marshal(set.Raw())
		if e != nil {
			t.Fatal(e)
		}
		var doc struct {
			Keys []map[string]any `json:"keys"`
		}
		if e = json.Unmarshal(raw, &doc); e != nil {
			t.Fatal(e)
		}
		if len(doc.Keys) != 1 {
			t.Fatalf("expected one public key: %s", raw)
		}
		k := doc.Keys[0]
		if k["kty"] != "OKP" || k["crv"] != "Ed25519" || k["alg"] != "EdDSA" || k["kid"] != wantKid || k["x"] != base64.RawURLEncoding.EncodeToString(want) {
			t.Fatalf("wrong public JWK: %s", raw)
		}
		if _, ok := k["d"]; ok {
			t.Fatal("private JWKS field")
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, k["x"])))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	operationalThumb := check(manager.GetKeySet(), pub, kid)
	entityThumb := check(manager.GetEntityKeySet(), entityPublic, firstThumb(entityPublic))
	if operationalThumb != kid || entityThumb == kid {
		t.Fatal("manager custody binding incorrect")
	}
	savedReference := ref // caller-owned memory, not SDK persistence
	reopened, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: savedReference})
	if err != nil {
		t.Fatal(err)
	}
	firstJWK(t, reopened.JWK(), kid, pub)
	sig, err = reopened.Sign(payload)
	firstSignature(t, sig, err, kid, payload, pub)
	again, err := dnsid.NewIdentityManager(cfg, reopened, dnsid.WithEntityKeyProvider(entity))
	if err != nil {
		t.Fatal(err)
	}
	if check(again.GetKeySet(), pub, kid) != operationalThumb || check(again.GetEntityKeySet(), entityPublic, firstThumb(entityPublic)) != entityThumb {
		t.Fatal("reopen changed setup identity")
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if f.creates != 1 || f.closes != 0 || entity.signs != 0 {
		t.Fatalf("recreated/closed caller client/fabricated entity signature: creates=%d closes=%d entity signs=%d", f.creates, f.closes, entity.signs)
	}
}
