---
title: "Go: dnsid — key providers"
description: "KeyProvider implementations, key metadata, and log-event signing."
---

> Generated from the Go source by scripts/gen-docs.sh — do not edit; run it to regenerate.
> Canonical deep reference: [pkg.go.dev/github.com/dnsid-ai/dnsid-go](https://pkg.go.dev/github.com/dnsid-ai/dnsid-go).
> Guides and account setup: [https://docs.dnsid.ai](https://docs.dnsid.ai).

Part of the root package `github.com/dnsid-ai/dnsid-go` — see [Core: IdentityManager](https://docs.dnsid.ai/reference/go/dnsid) for the package overview.

## func [SignLogEventWithKey](<https://github.com/dnsid-ai/dnsid-go/blob/main/log.go#L85>)

```go
func SignLogEventWithKey(event dnsidlog.LogEvent, role LogSignerRole, kp KeyProvider, canonicalizer LogEventCanonicalizer) (dnsidlog.LogEvent, error)
```

SignLogEventWithKey adds one lifecycle signature using an explicitly supplied key provider and bound log canonicalizer. It is suitable for accountable entity services that do not possess the operational private key.

<a name="Tags"></a>
## type [KeyAge](<https://github.com/dnsid-ai/dnsid-go/blob/main/identity_manager.go#L35>)

KeyAge is a DNSid key\-age policy value.

```go
type KeyAge string
```

<a name="KeyProvider"></a>
## type [KeyProvider](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L29-L53>)

KeyProvider abstracts key storage for the SDK.

```go
type KeyProvider interface {
    // JWK returns one public JWK. With no kid it returns the active key.
    JWK(kid ...string) jwk.Key

    // ListKeyIds returns the active kid first, followed by retained kids.
    ListKeyIds() []string

    // Sign signs payload with the active key.
    Sign(payload []byte) (*KeySignature, error)

    // SignKey signs payload with a specific active or pending key.
    SignKey(kid string, payload []byte) (*KeySignature, error)

    // GenerateKey creates a pending key for alg and returns its kid.
    GenerateKey(alg JoseAlg) (string, error)

    // Activate promotes kid to active and retains the previous active key.
    Activate(kid string) error

    // Supersede removes a retained key after a completed rotation.
    Supersede(kid string) error

    // Purge removes a pending or retained key.
    Purge(kid string) error
}
```

<a name="KeyRotationPreparationRequest"></a>
## type [KeySignature](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L22-L26>)

KeySignature is the result of signing with a KeyProvider's active key.

```go
type KeySignature struct {
    Kid       string
    Alg       JoseAlg
    Signature []byte
}
```

<a name="LifecycleResponse"></a>
## type [LocalKeyProvider](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L98-L105>)

LocalKeyProvider loads a JWK keypair from disk or holds in\-memory keys. Only one provider instance may write a given file; there is no file locking.

```go
type LocalKeyProvider struct {
    // contains filtered or unexported fields
}
```

<a name="GenerateES256KeyProvider"></a>
### func [GenerateES256KeyProvider](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L219>)

```go
func GenerateES256KeyProvider() *LocalKeyProvider
```

GenerateES256KeyProvider creates an ephemeral in\-memory ES256 keypair.

<a name="GenerateEd25519KeyProvider"></a>
### func [GenerateEd25519KeyProvider](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L206>)

```go
func GenerateEd25519KeyProvider() *LocalKeyProvider
```

GenerateEd25519KeyProvider creates an ephemeral in\-memory Ed25519 keypair.

<a name="LoadOrCreateLocalKeyProvider"></a>
### func [LoadOrCreateLocalKeyProvider](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L141>)

```go
func LoadOrCreateLocalKeyProvider(path string, alg JoseAlg) (*LocalKeyProvider, error)
```

LoadOrCreateLocalKeyProvider loads a JWK keypair from disk, or creates one if path does not exist.

<a name="NewLocalKeyProvider"></a>
### func [NewLocalKeyProvider](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L109>)

```go
func NewLocalKeyProvider(path string) (*LocalKeyProvider, error)
```

NewLocalKeyProvider loads a key store file. It accepts the current active/retained/pending store shape and the older flat private JWK shape.

<a name="LocalKeyProvider.Activate"></a>
### func \(\*LocalKeyProvider\) [Activate](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L659>)

```go
func (p *LocalKeyProvider) Activate(kid string) error
```

Activate promotes the named pending or retained key to active and retains the previously active key. It returns an \*ArgumentError for unknown kids. Even when kid is already active, the store is persisted again so callers can retry a durability failure. On failure before publication the previous state is restored; ErrKeyStoreDurability leaves the new state in memory and on disk.

<a name="LocalKeyProvider.GenerateKey"></a>
### func \(\*LocalKeyProvider\) [GenerateKey](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L618>)

```go
func (p *LocalKeyProvider) GenerateKey(alg JoseAlg) (string, error)
```

GenerateKey creates a new pending key for alg and returns its kid \(the key's RFC 7638 thumbprint\). The new key is persisted to the provider's key store file, when one is configured, before the kid is returned; the active key is unchanged until Activate is called. On ErrKeyStoreDurability, the pending key is retained and its kid is returned alongside the error.

<a name="LocalKeyProvider.JWK"></a>
### func \(\*LocalKeyProvider\) [JWK](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L527>)

```go
func (p *LocalKeyProvider) JWK(kidOpt ...string) jwk.Key
```

JWK returns the public JWK for the requested kid, or for the active key when no kid is given. The returned key carries kid, alg, and use=sig. It returns nil when the kid is unknown or no key is active.

<a name="LocalKeyProvider.ListKeyIds"></a>
### func \(\*LocalKeyProvider\) [ListKeyIds](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L547>)

```go
func (p *LocalKeyProvider) ListKeyIds() []string
```

ListKeyIds returns the active kid first, followed by retained kids in insertion order. Pending kids are not listed.

<a name="LocalKeyProvider.Purge"></a>
### func \(\*LocalKeyProvider\) [Purge](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L706>)

```go
func (p *LocalKeyProvider) Purge(kid string) error
```

Purge removes a pending or retained key and persists the change. Purging the active key or an unknown kid returns an \*ArgumentError. On ErrKeyStoreDurability the removal is not rolled back.

<a name="LocalKeyProvider.Sign"></a>
### func \(\*LocalKeyProvider\) [Sign](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L567>)

```go
func (p *LocalKeyProvider) Sign(payload []byte) (*KeySignature, error)
```

Sign signs payload with the active key. It returns an error when no key is active. ES256 signatures are deterministic \(RFC 6979\) raw R||S; EdDSA signatures are standard Ed25519.

<a name="LocalKeyProvider.SignKey"></a>
### func \(\*LocalKeyProvider\) [SignKey](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L579>)

```go
func (p *LocalKeyProvider) SignKey(kid string, payload []byte) (*KeySignature, error)
```

SignKey signs payload with the named key, which must be in the active or pending state; signing with a retained key returns an \*ArgumentError.

<a name="LocalKeyProvider.Supersede"></a>
### func \(\*LocalKeyProvider\) [Supersede](<https://github.com/dnsid-ai/dnsid-go/blob/main/keyprovider.go#L693>)

```go
func (p *LocalKeyProvider) Supersede(kid string) error
```

Supersede removes a retained key after a completed rotation. It returns an \*ArgumentError when kid does not name a retained key.

<a name="LogEventCanonicalizer"></a>
## type [LogEventCanonicalizer](<https://github.com/dnsid-ai/dnsid-go/blob/main/log.go#L41-L43>)

LogEventCanonicalizer produces the exact bytes covered by lifecycle\-event signatures for one bound log method and reference.

```go
type LogEventCanonicalizer interface {
    Canonical(event dnsidlog.LogEvent) ([]byte, error)
}
```

<a name="LogSignerRole"></a>
## type [LogSignerRole](<https://github.com/dnsid-ai/dnsid-go/blob/main/log.go#L27>)

LogSignerRole identifies a DNSid lifecycle\-event signer. Signatures from all roles cover the same log\-method canonical bytes.

```go
type LogSignerRole string
```

<a name="LogSignerEntity"></a>The lifecycle\-event signer roles: the accountable entity signature, the operational countersignature on ISSUANCE, and the previous\- and new\-operational signatures on KEY\_ROTATION.

```go
const (
    LogSignerEntity                      LogSignerRole = "entity"
    LogSignerOperationalCountersignature LogSignerRole = "operational_countersignature"
    LogSignerPreviousOperational         LogSignerRole = "previous_operational"
    LogSignerNewOperational              LogSignerRole = "new_operational"
)
```

<a name="RequiredLogSignatures"></a>
### func [RequiredLogSignatures](<https://github.com/dnsid-ai/dnsid-go/blob/main/log.go#L199>)

```go
func RequiredLogSignatures(event dnsidlog.LogEvent) ([]LogSignerRole, error)
```

RequiredLogSignatures returns the base draft\-01 signer roles for event.

<a name="OperationsAgent"></a>
