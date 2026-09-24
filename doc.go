// Package dnsid implements DNSid, domain-anchored identity for agents:
// verify who an agent is, who governs it, and whether it is still live,
// straight from DNS.
//
// A DNSid identity is published as a signed _dnsid TXT record on the agent's
// domain. The record names the agent's governing organization (gi), the
// accountable-entity record-signing key set (ek), and the agent runtime key
// set (ku); a status endpoint (su) reports the agent's lifecycle state
// (PENDING, PROVISIONING, VERIFYING, ACTIVE, RETIRED, or REVOKED —
// verification requires ACTIVE). This package resolves that record, verifies the record signature
// against the entity JWKS, checks lifecycle evidence through the bound
// transparency log, enforces the status endpoint, and signs on the agent's
// behalf — all over SSRF-safe, DNS-rebinding-resistant transport.
//
// # IdentityManager
//
// IdentityManager is the facade for the SDK. A verify-only manager needs no
// key material; the minimal flow mirrors the README:
//
//	idm, err := dnsid.NewVerifier()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	verified, err := idm.VerifyDomain(ctx, "your-agent.example.com")
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println(verified.Domain(), verified.Record().GovernanceID, verified.Status().State)
//
// A manager constructed with Config.Identity and a KeyProvider can
// also act as an agent: build and sign its own _dnsid record
// (CreateTXTRecord), publish its operational and entity JWKS documents
// (GetKeySet, GetEntityKeySet), write lifecycle log events, and drive registry
// workflows. The config package loads such a manager from DNSID_* environment
// variables or an identity created by the DNSid CLI.
//
// # Main entry types
//
//   - IdentityManager — the facade: domain verification, record creation, and
//     registry workflows.
//   - Config (IdentityConfig, VerificationConfig, TransportConfig) — local
//     publication settings, verification policy including the optional
//     TrustedEntities counterparty allowlist, and SDK-managed transport.
//     IdentityManagerOption injects runtime dependencies.
//   - VerifiedDomain — the immutable result of successful verification:
//     record, key sets, status, and expiry.
//   - TXTRecord — a parsed _dnsid identity record (ParseTXTRecord, Serialize,
//     CanonicalContent).
//   - KeyProvider / LocalKeyProvider — signing-key storage, generation, and
//     rotation.
//   - JWKS / JWK — typed wrappers over JWK sets and keys.
//   - RegistryClient / HTTPRegistryClient — the DNSid registry control-plane
//     API.
//   - ParseError, ValidationError, ArgumentError, VerificationError — the
//     typed error taxonomy; VerificationError carries a VerificationCode and a
//     transient flag.
//
// # Subpackages
//
// The application profiles build on this core: jose creates and verifies
// DNSid JWTs and compact JWS, oidc mints and verifies DNSid OIDC tokens, and
// httpsig and webbotauth implement RFC 9421 HTTP Message Signatures and the
// Web Bot Auth profile. The log subpackage defines the lifecycle-event and
// transparency-log model that verification builds on.
//
// Guides and account setup live at https://docs.dnsid.ai; full API reference
// is on pkg.go.dev.
package dnsid
