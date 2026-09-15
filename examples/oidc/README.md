# DNSid OIDC example

Mints a DNSid OIDC token: signs a short-lived JWT-bearer assertion with the agent's operational key
from `dnsid.NewIdentityManagerFromDnsid("", dnsid.Config{})`, then exchanges it at the issuer's token endpoint for
an access token.

```sh
go run ./examples/oidc https://issuer.example.com my-audience
```

Uses the current identity selected by `~/.dnsid/config.json` and its
`~/.dnsid/<fqdn>/private.jwk` — create one with `dnsid auth login` + `dnsid init` (see
[QUICKSTART.md](../../QUICKSTART.md)). The issuer must be an HTTPS OIDC issuer URL without a
trailing slash whose token endpoint accepts the `urn:ietf:params:oauth:grant-type:jwt-bearer`
grant for DNSid agents.
