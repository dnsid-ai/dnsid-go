# Public Release Preparation

The repository is technically close to release, but it should not be made public until the remaining blockers below are resolved.

## Release blockers

### 1. Audit the complete Git history

Making the existing repository public exposes old commits, tags, branches, release assets, and author email addresses.

Before changing visibility:

- Run Gitleaks or an equivalent scanner over all history and refs.
- Review removed scripts, configuration, private endpoints, customer data, and credentials.
- Confirm historical private JWK fixtures were deterministic test material and were never used outside tests.
- Remove unnecessary branches and other refs.

If the history cannot safely be exposed, publish a clean snapshot repository instead.

### 2. Decide what “first public release” means

The private repository already has releases and tags through `v0.24.0`, including `key/aws/v0.24.0`. Those tags contain the former evaluation agreement; replacing the license on the current branch does not change tagged source. Making the repository public will expose those releases and their bundled terms.

Choose one approach:

- retain the history, leave historical tags unchanged, and publish the next version as the first Apache-licensed public release; or
- recreate the public history and tags before changing visibility.

## Release pipeline

### 3. Dry-run the release process

Before the public release:

- Exercise the release workflow without publishing another release.
- Confirm the release notes and `CHANGELOG.md` describe the current public API changes.

## GitHub publication setup

Before changing repository visibility:

- Add a repository description; it is currently blank.
- Verify branch protection or rulesets require review and passing CI.
- Enable private vulnerability reporting.
- Enable Dependabot alerts and security updates.
- Enable secret scanning and push protection.
- Review issue access and public contribution expectations.
- Confirm `docs.dnsid.ai` is ready for public traffic.

A code of conduct, governance document, and additional issue templates are optional and should only be added if the project needs them.

## External consumer smoke test

After changing visibility, test the new Apache-licensed release from a clean machine or module cache, replacing `vNEXT` with its version:

```sh
GOPROXY=proxy.golang.org go get github.com/dnsid-ai/dnsid-go@vNEXT
GOPROXY=proxy.golang.org go get github.com/dnsid-ai/dnsid-go/key/aws@vNEXT
```

Then verify:

- both modules appear correctly on pkg.go.dev;
- package documentation is visible;
- examples compile outside this repository;
- no local `replace` directive is required by consumers; and
- the published checksums and release notes match the tagged source.

## Recommended release order

1. Audit history and all refs for secrets and private information.
2. Decide whether to retain the existing tags and releases.
3. Dry-run the complete release process.
4. Configure GitHub publication and security settings.
5. Publish the first Apache-licensed root and AWS module release.
6. Change repository visibility.
7. Run clean external proxy and pkg.go.dev smoke tests.
