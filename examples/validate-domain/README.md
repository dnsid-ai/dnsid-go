# DNSid validate-domain example

Verifies a DNSid domain with an `IdentityManager` built entirely from the
`DNSID_*` environment via `config.IdentityManagerFromEnvironment`. Prefer an
independently distributed trust profile containing the exact log policy and all
accepted stream-bundle signer keys:

```sh
DNSID_LOG_TRUST_PROFILE_FILE=/etc/dnsid/production-trust.json \
  go run ./examples/validate-domain your-agent.example
```

The version 1 JSON profile contains `version`, `scope`, `log_prefix`,
`tlog_policy`, and `bundle_verifier_keys`. The key array permits old and new
signers to overlap during rotation. A profile enables verified stream bundles
with raw-log scan fallback; the bundle signer keys come only from the profile,
never from the log origin.

A bare policy is also accepted, as a file or an HTTPS URL. Exactly one trust
input may be set:

```sh
DNSID_LOG_POLICY_URL=https://log.dnsid.ai/dnsid-policy \
  go run ./examples/validate-domain your-agent.example
```

Replace `your-agent.example` with a published DNSid-enabled domain.

Against the local registry, provision `bob.test` and its ISSUANCE, then evaluate
`dnsid local env bob`. The agent-specific form includes the identity and key
paths as well as `DNSID_DNS_SERVER`, `DNSID_CA_BUNDLE`, `DNSID_PRIVATE_HOSTS`, and
`DNSID_LOG_POLICY_URL`; the loader passes the transport settings to both the
log registry and the `IdentityManager`, and verifies by raw-log scan since the
local registry serves no stream bundles:

```sh
dnsid local up --zone test
dnsid local agent ensure bob --upstream http://localhost:3002 -- \
  dnsid log issue --domain bob.test
eval "$(dnsid local env bob)"
go run ./examples/validate-domain bob.test
```

The example uses the default `auto` DNSSEC policy unless `DNSID_DNSSEC_MODE` is
set. Go's built-in resolver cannot expose DNSSEC validation results, so
successful output normally reports `dnssec: UNKNOWN`. Applications requiring
definitive DNSSEC validation should inject a DNSSEC-aware resolver and select
`validated` or `required`.
