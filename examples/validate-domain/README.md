# DNSid validate-domain example

Verifies a DNSid domain through its signed C2SP stream bundle. Prefer an
independently distributed trust profile containing the exact log policy and all
accepted bundle signer keys:

```sh
DNSID_TRUST_PROFILE=/etc/dnsid/production-trust.json \
  go run ./examples/validate-domain your-agent.example.com
```

The version 1 JSON profile contains `version`, `scope`, `log_prefix`,
`tlog_policy`, and `bundle_verifier_keys`. The key array permits old and new
signers to overlap during rotation.

For deployment bootstrapping, the individual trusted inputs remain supported:

```sh
DNSID_BUNDLE_VERIFIER_KEY='dnsid-stream-bundle+<keyhash>+<base64-public-key>' \
  go run ./examples/validate-domain your-agent.example.com
```

Without a profile, the example defaults to the dev policy at
`https://log.dnsid.dev/dnsid-policy`. Override it for another environment:

```sh
DNSID_POLICY_URL=https://log.dnsid.ai/dnsid-policy \
DNSID_BUNDLE_VERIFIER_KEY='dnsid-stream-bundle+<keyhash>+<base64-public-key>' \
  go run ./examples/validate-domain your-agent.example.com
```

`RequireStreamBundle` disables raw-log fallback, so success confirms the
canonical `{lr log-prefix}/streams/{fqdn}?format=bundle` deployment path and the
independently pinned signer both work. The log origin's
`dnsid-bundle-signer` object is discovery only; compare it with the key obtained
from the trusted deployment/release channel rather than trusting it directly.

The example uses the default `auto` DNSSEC policy. Go's built-in resolver cannot
expose DNSSEC validation results, so successful output normally reports
`dnssec: UNKNOWN`. Applications requiring definitive DNSSEC validation should
inject a DNSSEC-aware resolver and select `DNSSECModeValidated` or
`DNSSECModeRequired`.
