---
title: "Go: dnsid — records & keys"
description: "TXT identity records, JWKS and JWK types, policy flags, and record parsing helpers."
---

> Generated from the Go source by scripts/gen-docs.sh — do not edit; run it to regenerate.
> Canonical deep reference: [pkg.go.dev/github.com/dnsid-ai/dnsid-go](https://pkg.go.dev/github.com/dnsid-ai/dnsid-go).
> Guides and account setup: [https://docs.dnsid.ai](https://docs.dnsid.ai).

Part of the root package `github.com/dnsid-ai/dnsid-go` — see [Core: IdentityManager](https://docs.dnsid.ai/reference/go/dnsid) for the package overview.

## func [ParseJWKSet](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L38>)

```go
func ParseJWKSet(data []byte) (jwk.Set, error)
```

ParseJWKSet parses a JWKS JSON document and returns a validated raw JWK set.

<a name="ParseLogRef"></a>
## func [ParseLogRef](<https://github.com/dnsid-ai/dnsid-go/blob/main/log.go#L17>)

```go
func ParseLogRef(lr string) (method, entryRef string, err error)
```

ParseLogRef splits an lr= log reference of the form "method:entryRef" into its method and entry\-reference parts. It returns a \*ParseError for malformed references or invalid method names.

<a name="RegistrantDomain"></a>
## type [DNSRecord](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L281-L286>)

DNSRecord matches the OpenAPI DNSRecord schema.

```go
type DNSRecord struct {
    Name  string `json:"name"`
    Type  string `json:"type"`
    Value string `json:"value"`
    TTL   int    `json:"ttl"`
}
```

<a name="DNSResolver"></a>
## type [JWK](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L18-L20>)

JWK is a typed wrapper over a single JWK with SDK\-level helpers.

```go
type JWK struct {
    // contains filtered or unexported fields
}
```

<a name="JWK.Alg"></a>
### func \(\*JWK\) [Alg](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L198>)

```go
func (k *JWK) Alg() JoseAlg
```

Alg returns the key's effective signing algorithm, deriving it from kty/crv when the JWK alg member is absent.

<a name="JWK.Kid"></a>
### func \(\*JWK\) [Kid](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L187>)

```go
func (k *JWK) Kid() string
```

Kid returns the key's kid value, or empty string if unset.

<a name="JWK.Raw"></a>
### func \(\*JWK\) [Raw](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L258>)

```go
func (k *JWK) Raw() jwk.Key
```

Raw returns the underlying jwk.Key.

<a name="JWK.SignatureAlg"></a>
### func \(\*JWK\) [SignatureAlg](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L215>)

```go
func (k *JWK) SignatureAlg(profile string) (JoseAlg, error)
```

SignatureAlg returns the signing algorithm allowed by the selected identity\-record profile. Unlike [JWK.Alg](<#JWK.Alg>), draft profiles require an explicit alg member that is consistent with the key type. An empty profile selects [DefaultPublishProfile](<https://docs.dnsid.ai/reference/go/dnsid#DefaultPublishProfile>).

<a name="JWK.Thumbprint"></a>
### func \(\*JWK\) [Thumbprint](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L173>)

```go
func (k *JWK) Thumbprint() (string, error)
```

Thumbprint returns the RFC 7638 SHA\-256 thumbprint of this key, base64url\-unpadded encoded.

<a name="JWK.Use"></a>
### func \(\*JWK\) [Use](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L239>)

```go
func (k *JWK) Use() string
```

Use returns the key's use value, or empty string if unset.

<a name="JWKS"></a>
## type [JWKS](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L13-L15>)

JWKS is a typed wrapper over a JWK Set with SDK\-level helpers.

```go
type JWKS struct {
    // contains filtered or unexported fields
}
```

<a name="NewJWKS"></a>
### func [NewJWKS](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L23>)

```go
func NewJWKS(set jwk.Set) *JWKS
```

NewJWKS wraps a jwk.Set into the typed SDK form.

<a name="ParseJWKS"></a>
### func [ParseJWKS](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L28>)

```go
func ParseJWKS(data []byte) (*JWKS, error)
```

ParseJWKS parses a JWKS JSON document and returns the typed wrapper.

<a name="JWKS.CurrentOperationalSigningKey"></a>
### func \(\*JWKS\) [CurrentOperationalSigningKey](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L131>)

```go
func (j *JWKS) CurrentOperationalSigningKey(profile string) (*JWK, error)
```

CurrentOperationalSigningKey returns the sole current operational signing key allowed by the selected identity\-record profile.

<a name="JWKS.CurrentRecordSigningKey"></a>
### func \(\*JWKS\) [CurrentRecordSigningKey](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L125>)

```go
func (j *JWKS) CurrentRecordSigningKey(profile string) (*JWK, error)
```

CurrentRecordSigningKey returns the sole current record\-signing key allowed by the selected identity\-record profile.

<a name="JWKS.KeyByID"></a>
### func \(\*JWKS\) [KeyByID](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L73>)

```go
func (j *JWKS) KeyByID(kid string) *JWK
```

KeyByID returns the key with the given kid, or nil if not found. This is an unfiltered lookup; the returned key may have use=enc or any other use value. Callers that want a signing\-eligible key should filter the result against SigningKeys\(\) or check Use\(\) themselves.

<a name="JWKS.Raw"></a>
### func \(\*JWKS\) [Raw](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L249>)

```go
func (j *JWKS) Raw() jwk.Set
```

Raw returns the underlying jwk.Set.

<a name="JWKS.SigningKeys"></a>
### func \(\*JWKS\) [SigningKeys](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L52>)

```go
func (j *JWKS) SigningKeys() []*JWK
```

SigningKeys returns all keys eligible for signature verification. Keys with unset use or use=sig are eligible.

<a name="JWKS.Validate"></a>
### func \(\*JWKS\) [Validate](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L89>)

```go
func (j *JWKS) Validate() error
```

Validate enforces SDK invariants for signing keys.

<a name="JWKS.ValidateOperational"></a>
### func \(\*JWKS\) [ValidateOperational](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L146>)

```go
func (j *JWKS) ValidateOperational(profile string) error
```

ValidateOperational verifies that the JWKS satisfies the selected identity\-record profile's operational\-key constraints. An empty profile selects [DefaultPublishProfile](<https://docs.dnsid.ai/reference/go/dnsid#DefaultPublishProfile>).

<a name="JWKS.ValidateRecordSigning"></a>
### func \(\*JWKS\) [ValidateRecordSigning](<https://github.com/dnsid-ai/dnsid-go/blob/main/jwks_wrapper.go#L138>)

```go
func (j *JWKS) ValidateRecordSigning(profile string) error
```

ValidateRecordSigning verifies that the JWKS satisfies the selected identity\-record profile's record\-signing\-key constraints. An empty profile selects [DefaultPublishProfile](<https://docs.dnsid.ai/reference/go/dnsid#DefaultPublishProfile>).

<a name="JoseAlg"></a>
## type [JoseAlg](<https://github.com/dnsid-ai/dnsid-go/blob/main/alg.go#L6>)

JoseAlg is the default\-deny allowlist of JOSE algorithms DNSid accepts.

```go
type JoseAlg string
```

<a name="JoseAlgEdDSA"></a>The JOSE algorithms DNSid accepts: Ed25519 \(EdDSA\) and ECDSA over P\-256 with SHA\-256 \(ES256\). All other algorithms are rejected.

```go
const (
    JoseAlgEdDSA JoseAlg = "EdDSA"
    JoseAlgES256 JoseAlg = "ES256"
)
```

<a name="JoseAlg.String"></a>
### func \(JoseAlg\) [String](<https://github.com/dnsid-ai/dnsid-go/blob/main/alg.go#L26>)

```go
func (a JoseAlg) String() string
```

String returns the JOSE alg identifier as a string.

<a name="JoseAlg.Valid"></a>
### func \(JoseAlg\) [Valid](<https://github.com/dnsid-ai/dnsid-go/blob/main/alg.go#L16>)

```go
func (a JoseAlg) Valid() bool
```

Valid reports whether a is in the DNSid JOSE algorithm allowlist.

<a name="KeyAge"></a>
## type [PolicyFlag](<https://github.com/dnsid-ai/dnsid-go/blob/main/identity_manager.go#L26>)

PolicyFlag is a DNSid TXT\-record policy flag.

```go
type PolicyFlag string
```

<a name="PolicyFlagMTLS"></a>DNSid TXT\-record policy flags understood by the verifier.

```go
const (
    PolicyFlagMTLS     PolicyFlag = "mtls"
    PolicyFlagLogCheck PolicyFlag = "logchk"
)
```

<a name="PreparedRegistryEvent"></a>
## type [TXTRecord](<https://github.com/dnsid-ai/dnsid-go/blob/main/identity_record.go#L103-L115>)

TXTRecord represents a parsed \_dnsid TXT record.

```go
type TXTRecord struct {
    Version      string            // v= — DNSid wire profile
    GovernanceID string            // gi= — governance identifier
    EntityKeyURI string            // ek= — accountable-entity record-signing JWKS URI
    KeyURI       string            // ku= — JWKS endpoint URL
    LogRef       string            // lr= — ledger address
    StatusURI    string            // su= — status endpoint URL
    Signature    string            // sg= — base64url owner signature
    Flags        []string          // fl= — parsed flag list (nil if absent)
    KeyAge       string            // ka= — key age policy (empty if absent)
    Capabilities string            // cu= — Agent Card URL (empty if absent)
    UnknownTags  map[string]string // syntactically valid extension tags, preserved but ignored semantically
}
```

<a name="ParseTXTRecord"></a>
### func [ParseTXTRecord](<https://github.com/dnsid-ai/dnsid-go/blob/main/identity_record.go#L428>)

```go
func ParseTXTRecord(txt string) (*TXTRecord, error)
```

ParseTXTRecord parses a concatenated TXT record string into a TXTRecord.

<a name="ParseUnsignedCanonical"></a>
### func [ParseUnsignedCanonical](<https://github.com/dnsid-ai/dnsid-go/blob/main/identity_record.go#L435>)

```go
func ParseUnsignedCanonical(txt string) (*TXTRecord, error)
```

ParseUnsignedCanonical parses registry\-supplied unsigned canonical TXT content. It accepts required non\-signature inputs and extension tags, but rejects sg=.

<a name="TXTRecord.Canonical"></a>
### func \(\*TXTRecord\) [Canonical](<https://github.com/dnsid-ai/dnsid-go/blob/main/txt_record.go#L11>)

```go
func (r *TXTRecord) Canonical() string
```

Canonical returns the canonical string used for TXT\-record signature verification.

<a name="TXTRecord.CanonicalContent"></a>
### func \(\*TXTRecord\) [CanonicalContent](<https://github.com/dnsid-ai/dnsid-go/blob/main/identity_record.go#L279>)

```go
func (r *TXTRecord) CanonicalContent() []byte
```

CanonicalContent returns the canonical byte string for signing under the record's declared profile. Values are signed as raw ASCII TXT tag values.

<a name="TXTRecord.KnownTagsCanonical"></a>
### func \(\*TXTRecord\) [KnownTagsCanonical](<https://github.com/dnsid-ai/dnsid-go/blob/main/identity_record.go#L268>)

```go
func (r *TXTRecord) KnownTagsCanonical() []byte
```

KnownTagsCanonical returns the canonical byte string for known TXT tags only, excluding sg=. Unknown extension tags are ignored.

<a name="TXTRecord.MarshalTXT"></a>
### func \(\*TXTRecord\) [MarshalTXT](<https://github.com/dnsid-ai/dnsid-go/blob/main/identity_record.go#L291>)

```go
func (r *TXTRecord) MarshalTXT() (string, error)
```

MarshalTXT serializes the record as one \_dnsid TXT value for wire output. It emits v= first, then all other tags sorted lexically; signing order is profile\-defined and may differ.

<a name="TXTRecord.Serialize"></a>
### func \(\*TXTRecord\) [Serialize](<https://github.com/dnsid-ai/dnsid-go/blob/main/txt_record.go#L19>)

```go
func (r *TXTRecord) Serialize() string
```

Serialize serializes the record as one \_dnsid TXT value.

<a name="TXTRecord.Tags"></a>
### func \(\*TXTRecord\) [Tags](<https://github.com/dnsid-ai/dnsid-go/blob/main/identity_record.go#L217>)

```go
func (r *TXTRecord) Tags() map[string]string
```

Tags returns the record's tag\-value pairs as a map, excluding empty optional fields. It always emits the current wire tag names.

<a name="TXTRecord.Validate"></a>
### func \(\*TXTRecord\) [Validate](<https://github.com/dnsid-ai/dnsid-go/blob/main/txt_record.go#L31>)

```go
func (r *TXTRecord) Validate(identityFQDN string) error
```

Validate checks record\-level semantics with identity\-domain context.

<a name="TXTRecord.WithSignature"></a>
### func \(\*TXTRecord\) [WithSignature](<https://github.com/dnsid-ai/dnsid-go/blob/main/identity_record.go#L191>)

```go
func (r *TXTRecord) WithSignature(sig string) *TXTRecord
```

WithSignature returns a copy of the record with Signature set to sig.

<a name="TXTRecordRData"></a>
## type [TXTRecordRData](<https://github.com/dnsid-ai/dnsid-go/blob/main/identity_manager.go#L287-L290>)

TXTRecordRData is one concatenated TXT RDATA value plus resolver metadata.

```go
type TXTRecordRData struct {
    Value string
    TTL   time.Duration
}
```

<a name="TransportConfig"></a>
