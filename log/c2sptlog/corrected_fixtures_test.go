package c2sptlog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

// Disposable published method-vector seeds. Regenerate signatures over the
// corrected context and logical chain; never relabel old signed evidence.
var issuanceEntry = correctedFixture(legacyIssuanceEntry, "", "", 0)
var keyRotationEntry = correctedFixture(legacyKeyRotationEntry, issuanceEntry, op1JWK, 1)
var revocationEntry = correctedFixture(legacyRevocationEntry, keyRotationEntry, op2JWK, 2)

func correctedFixture(legacy, previous, operational string, seq int) string {
	payload, err := decodeJSONObject([]byte(legacy))
	if err != nil {
		panic(err)
	}
	payload["method"] = Method
	payload["log_origin"] = "dnsid-ledger:8080/log"
	payload["stream_id"] = "identity-01"
	payload["lr"] = "c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01"
	payload["seq"] = seq
	if previous != "" {
		signed, err := CanonicalFromEntry([]byte(previous))
		if err != nil {
			panic(err)
		}
		payload["prev_event_id"] = EventID(signed)
		payload["prev_state_hash"] = lifecycleStateHash(activeLifecycleState("agent.example", fixtureThumb(aeJWK), fixtureThumb(operational)))
	}
	return signFixturePayload(payload)
}

func fixtureThumb(raw string) string {
	var key map[string]any
	if err := json.Unmarshal([]byte(raw), &key); err != nil {
		panic(err)
	}
	k, _, err := optionalJWK(map[string]any{"key": key}, "key")
	if err != nil {
		panic(err)
	}
	thumb, err := thumbprint(k)
	if err != nil {
		panic(err)
	}
	return thumb
}

func signFixturePayload(payload map[string]any) string {
	sigs := payload["sigs"].(map[string]any)
	delete(payload, "sigs")
	signed, err := canonicalJSON(payload)
	if err != nil {
		panic(err)
	}
	for _, value := range sigs {
		sig := value.(map[string]any)
		seed := map[string]byte{"ae-test-1": 1, "op-test-1": 2, "op-test-2": 4}[sig["kid"].(string)]
		if seed == 0 {
			panic("unknown fixture signing key")
		}
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
		sig["sig"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, signed))
	}
	payload["sigs"] = sigs
	entry, err := canonicalJSON(payload)
	if err != nil {
		panic(err)
	}
	return string(entry)
}
