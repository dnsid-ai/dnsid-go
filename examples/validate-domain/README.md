# DNSid validate-domain example

Verifies a DNSid domain with an `IdentityManager` built entirely from the
`DNSID_*` environment via `config.IdentityManagerFromEnvironment`. Prefer an
independently distributed trust profile containing the exact log policy and all
accepted stream-bundle signer keys:

```sh
DNSID_LOG_TRUST_PROFILE_FILE=/etc/dnsid/production-trust.json \
  go run ./examples/validate-domain your-agent.example.com
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
  go run ./examples/validate-domain your-agent.example.com
```

Against the local registry, evaluate `dnsid local env` first. It sets
`DNSID_DNS_SERVER`, `DNSID_CA_BUNDLE`, `DNSID_PRIVATE_HOSTS`, and
`DNSID_LOG_POLICY_URL`; the loader passes the transport settings to both the
log registry and the `IdentityManager`, and verifies by raw-log scan since the
local registry serves no stream bundles:

```sh
eval "$(dnsid local env)"
go run ./examples/validate-domain bob.dev.dnsid.test
```

The example uses the default `auto` DNSSEC policy unless `DNSID_DNSSEC_MODE` is
set. Go's built-in resolver cannot expose DNSSEC validation results, so
successful output normally reports `dnssec: UNKNOWN`. Applications requiring
definitive DNSSEC validation should inject a DNSSEC-aware resolver and select
`validated` or `required`.
