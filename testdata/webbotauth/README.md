# Shared Web Bot Auth vectors

`web-bot-auth.json` is copied without modification from
`dnsid-sdk-compliance/docs/sdk-design/conformance/web-bot-auth.json` at design
commit `6752d10c7b85b4d5ac7bfeaacabb28c9ac1a7c1f`.

The fixture key is public test material, not a production credential.

`webbotauth/conformance_test.go` runs the real verifier with a fixed signature
clock, an actual core identity manager, and local TLS discovery through the safe
transport's injected DNS and dial dependencies. Scenario flags configure those
dependencies or repeated operations; they do not supply acceptance verdicts.

Go does not cache directories. Cache-hit identity and acceptance cases instead
exercise repeated fresh discovery. The HTTP-stale cache case is explicitly
skipped because no directory evidence is reused. Native contract tests cover the
additional validation matrix introduced by the source design commit.
