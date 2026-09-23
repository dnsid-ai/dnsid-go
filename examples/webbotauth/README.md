# Web Bot Auth example

Signs an HTTP request with the Web Bot Auth profile derived from `config.IdentityManagerFromDnsid`, then prints the signed request headers and signed key directory response.

```sh
go run ./examples/webbotauth
```

Uses the current identity selected by `~/.dnsid/config.json` and its
`~/.dnsid/<fqdn>/private.jwk`. Web Bot Auth requires that operational key to be Ed25519.
