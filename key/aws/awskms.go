package awskms

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/cryptoutil"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const rawSignLimit = 4096

// State records the key rotation state of a [Provider]: which KMS key is
// active, which retained keys remain published for verification, and which
// pending keys await activation. The provider does not persist state itself;
// capture it with [Provider.State] and supply it back through [Config.State]
// when reconstructing the provider.
type State struct {
	// ActiveKeyID identifies the KMS key used by Sign. Required.
	ActiveKeyID string

	// RetainedKeyIDs identify previously active keys that are still
	// published for verification.
	RetainedKeyIDs []string

	// PendingKeyIDs identify generated keys that have not been activated.
	PendingKeyIDs []string
}

// Config configures a [Provider]. The zero value is not usable on its own:
// State.ActiveKeyID must identify an existing KMS signing key. [Load] applies
// the defaults documented on each field.
type Config struct {
	// State is the initial rotation state. State.ActiveKeyID is required.
	State State

	// Algorithm is the KMS signing algorithm used for every signing
	// operation. Supported values are
	// types.SigningAlgorithmSpecEcdsaSha256 (JOSE ES256) and
	// types.SigningAlgorithmSpecEd25519Sha512 (JOSE EdDSA). Defaults to
	// ECDSA_SHA_256.
	Algorithm types.SigningAlgorithmSpec

	// KeySpec is the KMS key spec required of every key the provider uses
	// or creates. If empty it is derived from Algorithm (ECC_NIST_P256 for
	// ECDSA_SHA_256, ECC_NIST_EDWARDS25519 for ED25519_SHA_512); a
	// non-empty value that does not match Algorithm is rejected by Load.
	KeySpec types.KeySpec

	// Description is applied to KMS keys created by GenerateKey.
	Description string

	// Tags are applied to KMS keys created by GenerateKey.
	Tags map[string]string

	// ScheduleDeletionOnPurge schedules KMS key deletion when a key is
	// purged or superseded, and when a key created by GenerateKey fails
	// validation. When false, removed keys are only dropped from the
	// provider's state and remain in KMS.
	ScheduleDeletionOnPurge bool

	// DeletionWindowInDays is the KMS pending-deletion window used when
	// scheduling key deletion. Defaults to 30.
	DeletionWindowInDays int32

	// OperationTimeout bounds each KMS call. Defaults to 30 seconds; a
	// negative value disables the timeout.
	OperationTimeout time.Duration
}

// Client is the narrow AWS KMS surface a [Provider] depends on. [SDKClient]
// adapts the AWS SDK for Go v2 KMS client; test doubles can implement Client
// directly.
type Client interface {
	// CreateSigningKey creates a new SIGN_VERIFY KMS key and returns its ID.
	CreateSigningKey(context.Context, CreateSigningKeyInput) (CreateSigningKeyOutput, error)

	// GetPublicKey returns the public half and metadata of a KMS key.
	GetPublicKey(context.Context, GetPublicKeyInput) (GetPublicKeyOutput, error)

	// Sign signs a raw message or precomputed digest with a KMS key.
	Sign(context.Context, SignInput) (SignOutput, error)

	// ScheduleKeyDeletion schedules a KMS key for deletion.
	ScheduleKeyDeletion(context.Context, ScheduleKeyDeletionInput) error
}

// CreateSigningKeyInput carries the parameters for [Client.CreateSigningKey]:
// the KMS key spec plus the description and tags to apply to the new key.
type CreateSigningKeyInput struct {
	KeySpec     types.KeySpec
	Description string
	Tags        map[string]string
}

// CreateSigningKeyOutput reports the ID — preferably the ARN — of a newly
// created KMS key.
type CreateSigningKeyOutput struct{ KeyID string }

// GetPublicKeyInput identifies the KMS key to fetch with [Client.GetPublicKey].
type GetPublicKeyInput struct{ KeyID string }

// GetPublicKeyOutput carries a KMS key's DER-encoded (PKIX) public key and the
// metadata the provider validates: the canonical key ID, key spec, key usage,
// and supported signing algorithms.
type GetPublicKeyOutput struct {
	KeyID             string
	PublicKey         []byte
	KeySpec           types.KeySpec
	KeyUsage          types.KeyUsageType
	SigningAlgorithms []types.SigningAlgorithmSpec
}

// SignInput carries the parameters for [Client.Sign]. When Digest is true,
// Message is a precomputed digest rather than the raw payload.
type SignInput struct {
	KeyID     string
	Message   []byte
	Algorithm types.SigningAlgorithmSpec
	Digest    bool
}

// SignOutput carries a KMS signature together with the key ID and signing
// algorithm KMS reports having used.
type SignOutput struct {
	KeyID     string
	Signature []byte
	Algorithm types.SigningAlgorithmSpec
}

// ScheduleKeyDeletionInput carries the parameters for
// [Client.ScheduleKeyDeletion]: the key to delete and the KMS
// pending-deletion window in days.
type ScheduleKeyDeletionInput struct {
	KeyID               string
	PendingWindowInDays int32
}

// SDKClient adapts an AWS SDK for Go v2 *kms.Client to the [Client] interface.
type SDKClient struct{ Client *kms.Client }

// CreateSigningKey creates a SIGN_VERIFY KMS key with the requested key spec,
// description, and tags. It returns the new key's ARN when KMS reports one,
// and the bare key ID otherwise.
func (c SDKClient) CreateSigningKey(ctx context.Context, in CreateSigningKeyInput) (CreateSigningKeyOutput, error) {
	out, err := c.Client.CreateKey(ctx, &kms.CreateKeyInput{
		KeyUsage:    types.KeyUsageTypeSignVerify,
		KeySpec:     in.KeySpec,
		Description: aws.String(in.Description),
		Tags:        awsTags(in.Tags),
	})
	if err != nil {
		return CreateSigningKeyOutput{}, err
	}
	if out.KeyMetadata == nil {
		return CreateSigningKeyOutput{}, fmt.Errorf("dnsid/awskms: CreateKey returned no metadata")
	}
	if out.KeyMetadata.Arn != nil {
		return CreateSigningKeyOutput{KeyID: *out.KeyMetadata.Arn}, nil
	}
	return CreateSigningKeyOutput{KeyID: aws.ToString(out.KeyMetadata.KeyId)}, nil
}

// GetPublicKey fetches the public key and metadata of the KMS key named by
// in.KeyID.
func (c SDKClient) GetPublicKey(ctx context.Context, in GetPublicKeyInput) (GetPublicKeyOutput, error) {
	out, err := c.Client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(in.KeyID)})
	if err != nil {
		return GetPublicKeyOutput{}, err
	}
	return GetPublicKeyOutput{KeyID: aws.ToString(out.KeyId), PublicKey: out.PublicKey, KeySpec: out.KeySpec, KeyUsage: out.KeyUsage, SigningAlgorithms: out.SigningAlgorithms}, nil
}

// Sign asks KMS to sign in.Message with in.KeyID, sending it as a RAW message
// or, when in.Digest is true, as a precomputed DIGEST.
func (c SDKClient) Sign(ctx context.Context, in SignInput) (SignOutput, error) {
	msgType := types.MessageTypeRaw
	if in.Digest {
		msgType = types.MessageTypeDigest
	}
	out, err := c.Client.Sign(ctx, &kms.SignInput{KeyId: aws.String(in.KeyID), Message: in.Message, MessageType: msgType, SigningAlgorithm: in.Algorithm})
	if err != nil {
		return SignOutput{}, err
	}
	return SignOutput{KeyID: aws.ToString(out.KeyId), Signature: out.Signature, Algorithm: out.SigningAlgorithm}, nil
}

// ScheduleKeyDeletion schedules the KMS key named by in.KeyID for deletion
// after in.PendingWindowInDays days.
func (c SDKClient) ScheduleKeyDeletion(ctx context.Context, in ScheduleKeyDeletionInput) error {
	_, err := c.Client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: aws.String(in.KeyID), PendingWindowInDays: aws.Int32(in.PendingWindowInDays)})
	return err
}

// Provider is an AWS KMS-backed implementation of [dnsid.KeyProvider].
// Private key material stays in KMS: the provider fetches and caches public
// keys as JWKs and delegates every signing operation to the KMS Sign API.
//
// Key IDs (kids) are the canonical identifiers reported by KMS — normally key
// ARNs. Any KMS key identifier is accepted where a kid parameter allows it,
// but [State], [Provider.ListKeyIds], and [dnsid.KeySignature] always carry
// the canonical form. Rotation state is held in memory only; persist it with
// [Provider.State]. Provider is safe for concurrent use.
type Provider struct {
	mu     sync.RWMutex
	client Client
	state  State
	cfg    Config
	cache  map[string]jwk.Key
}

// Load constructs a [Provider] from an existing rotation state. It applies
// the defaults documented on [Config], then canonicalizes every key ID in
// cfg.State against KMS, verifying that each key exists, is a SIGN_VERIFY key
// of the configured key spec, and supports the configured signing algorithm.
// It returns an error if client is nil, cfg.State.ActiveKeyID is empty, the
// algorithm is unsupported, cfg.KeySpec does not match the algorithm, or any
// state key fails validation.
func Load(ctx context.Context, client Client, cfg Config) (*Provider, error) {
	if client == nil {
		return nil, fmt.Errorf("dnsid/awskms: nil client")
	}
	if cfg.State.ActiveKeyID == "" {
		return nil, fmt.Errorf("dnsid/awskms: active key ID is required")
	}
	if cfg.Algorithm == "" {
		cfg.Algorithm = types.SigningAlgorithmSpecEcdsaSha256
	}
	if _, err := joseAlg(cfg.Algorithm); err != nil {
		return nil, err
	}
	keySpec, err := defaultKeySpec(cfg.Algorithm)
	if err != nil {
		return nil, err
	}
	if cfg.KeySpec == "" {
		cfg.KeySpec = keySpec
	} else if cfg.KeySpec != keySpec {
		return nil, fmt.Errorf("dnsid/awskms: key spec %s does not match algorithm %s", cfg.KeySpec, cfg.Algorithm)
	}
	if cfg.DeletionWindowInDays == 0 {
		cfg.DeletionWindowInDays = 30
	}
	if cfg.OperationTimeout == 0 {
		cfg.OperationTimeout = 30 * time.Second
	}
	p := &Provider{client: client, cfg: cfg, state: cloneState(cfg.State), cache: map[string]jwk.Key{}}
	if err := p.canonicalizeState(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// State returns a copy of the provider's current rotation state, with all key
// IDs in canonical (KMS-reported) form. Persist it and supply it back through
// [Config.State] to reconstruct the provider later.
func (p *Provider) State() State {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return cloneState(p.state)
}

// JWK returns one public JWK, implementing [dnsid.KeyProvider]. With no kid
// it returns the active key. It returns nil when the kid is not the active
// key or among the retained or pending keys, and also when fetching the
// public key from KMS fails; use [Provider.JWKWithError] to distinguish the
// two. The returned key is a clone, so mutating it does not affect the
// provider.
func (p *Provider) JWK(kidOpt ...string) jwk.Key {
	key, _ := p.JWKWithError(kidOpt...)
	return key
}

// JWKWithError is like [Provider.JWK] but reports fetch failures. It returns
// (nil, nil) when the kid is not known to the provider, and (nil, err) when
// the key could not be fetched from KMS or failed validation. Fetched public
// keys are cached for the life of the provider.
func (p *Provider) JWKWithError(kidOpt ...string) (jwk.Key, error) {
	p.mu.RLock()
	kid := p.state.ActiveKeyID
	if len(kidOpt) > 0 {
		kid = kidOpt[0]
	}
	if kid != p.state.ActiveKeyID && !contains(p.state.RetainedKeyIDs, kid) && !contains(p.state.PendingKeyIDs, kid) {
		p.mu.RUnlock()
		return nil, nil
	}
	if key := p.cache[kid]; key != nil {
		p.mu.RUnlock()
		return cloneJWK(key)
	}
	p.mu.RUnlock()

	ctx, cancel := p.operationContext()
	defer cancel()
	return p.publicJWK(ctx, kid)
}

// ListKeyIds returns the active kid first, followed by retained kids,
// implementing [dnsid.KeyProvider]. Pending kids are not listed.
func (p *Provider) ListKeyIds() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string{p.state.ActiveKeyID}, p.state.RetainedKeyIDs...)
}

// Sign signs payload with the active key using the configured algorithm,
// implementing [dnsid.KeyProvider]. Payloads up to 4096 bytes are sent to KMS
// as RAW messages; larger payloads are hashed locally with SHA-256 and sent
// as a DIGEST, which is only possible for ECDSA_SHA_256 — larger Ed25519
// payloads return an error. ECDSA signatures are converted from KMS's ASN.1
// DER encoding to the raw R||S form JOSE requires, so the returned
// KeySignature is always JOSE-ready.
func (p *Provider) Sign(payload []byte) (*dnsid.KeySignature, error) {
	p.mu.RLock()
	kid := p.state.ActiveKeyID
	p.mu.RUnlock()
	return p.signKey(kid, payload)
}

// SignKey signs payload with a specific key, implementing
// [dnsid.KeyProvider]. The kid may be any KMS identifier for the key; it must
// resolve to the active key or a pending key. Signing with a retained key
// returns an argument error, and signature encoding follows the rules
// documented on [Provider.Sign].
func (p *Provider) SignKey(kid string, payload []byte) (*dnsid.KeySignature, error) {
	ctx, cancel := p.operationContext()
	canonical, err := p.canonicalKid(ctx, kid)
	cancel()
	if err != nil {
		return nil, err
	}
	p.mu.RLock()
	allowed := canonical == p.state.ActiveKeyID || contains(p.state.PendingKeyIDs, canonical)
	p.mu.RUnlock()
	if !allowed {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid/awskms: key %q is not active or pending for signing", kid), nil)
	}
	return p.signKey(canonical, payload)
}

func (p *Provider) signKey(kid string, payload []byte) (*dnsid.KeySignature, error) {
	p.mu.RLock()
	alg := p.cfg.Algorithm
	p.mu.RUnlock()

	msg, digest, err := signingMessage(payload, alg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := p.operationContext()
	defer cancel()
	out, err := p.client.Sign(ctx, SignInput{KeyID: kid, Message: msg, Algorithm: alg, Digest: digest})
	if err != nil {
		return nil, err
	}
	if out.Algorithm != "" && out.Algorithm != alg {
		return nil, fmt.Errorf("dnsid/awskms: signing algorithm mismatch: expected %s, got %s", alg, out.Algorithm)
	}
	if out.KeyID != "" {
		signed, err := p.canonicalKid(ctx, out.KeyID)
		if err != nil {
			return nil, err
		}
		if signed != kid {
			return nil, fmt.Errorf("dnsid/awskms: signed with unexpected key: expected %s, got %s", kid, out.KeyID)
		}
	}
	sig, err := signatureForJOSE(alg, out.Signature)
	if err != nil {
		return nil, err
	}
	jose, err := joseAlg(alg)
	if err != nil {
		return nil, err
	}
	return &dnsid.KeySignature{Kid: kid, Alg: jose, Signature: sig}, nil
}

// GenerateKey creates a new KMS signing key and records it as pending,
// implementing [dnsid.KeyProvider]. alg must match the JOSE algorithm the
// provider is configured for (ES256 for ECDSA_SHA_256, EdDSA for
// ED25519_SHA_512). On success it returns the canonical kid of the new key.
// If the new key fails post-creation validation, the KMS key ID is returned
// alongside the error and, when Config.ScheduleDeletionOnPurge is set,
// deletion of the orphaned key is scheduled.
func (p *Provider) GenerateKey(alg dnsid.JoseAlg) (string, error) {
	configuredAlg, err := joseAlg(p.cfg.Algorithm)
	if err != nil {
		return "", err
	}
	if alg != configuredAlg {
		return "", fmt.Errorf("dnsid/awskms: provider is configured for %s, got %s", configuredAlg, alg)
	}
	ctx, cancel := p.operationContext()
	defer cancel()
	out, err := p.client.CreateSigningKey(ctx, CreateSigningKeyInput{KeySpec: p.cfg.KeySpec, Description: p.cfg.Description, Tags: p.cfg.Tags})
	if err != nil {
		return "", err
	}
	if out.KeyID == "" {
		return "", fmt.Errorf("dnsid/awskms: CreateSigningKey returned no key ID")
	}
	kid, err := p.canonicalKid(ctx, out.KeyID)
	if err != nil {
		if p.cfg.ScheduleDeletionOnPurge {
			deleteCtx, deleteCancel := p.operationContext()
			defer deleteCancel()
			if deleteErr := p.client.ScheduleKeyDeletion(deleteCtx, ScheduleKeyDeletionInput{KeyID: out.KeyID, PendingWindowInDays: p.cfg.DeletionWindowInDays}); deleteErr != nil {
				return out.KeyID, fmt.Errorf("dnsid/awskms: created key %q but validation and scheduled deletion failed: %w; deletion: %w", out.KeyID, err, deleteErr)
			}
		}
		return out.KeyID, fmt.Errorf("dnsid/awskms: created key %q but validation failed: %w", out.KeyID, err)
	}
	p.mu.Lock()
	p.state.PendingKeyIDs = append(p.state.PendingKeyIDs, kid)
	p.mu.Unlock()
	return kid, nil
}

// Activate promotes a pending key to active and moves the previously active
// key to the retained list, implementing [dnsid.KeyProvider]. The kid may be
// any KMS identifier for the key; it returns an error if it does not resolve
// to a pending key.
func (p *Provider) Activate(kid string) error {
	ctx, cancel := p.operationContext()
	defer cancel()
	canonical, err := p.canonicalKid(ctx, kid)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := indexOf(p.state.PendingKeyIDs, canonical)
	if idx < 0 {
		return fmt.Errorf("dnsid/awskms: no pending key %q", kid)
	}
	p.state.PendingKeyIDs = append(p.state.PendingKeyIDs[:idx], p.state.PendingKeyIDs[idx+1:]...)
	p.state.RetainedKeyIDs = append(p.state.RetainedKeyIDs, p.state.ActiveKeyID)
	p.state.ActiveKeyID = canonical
	return nil
}

// Supersede removes a retained key after a completed rotation, implementing
// [dnsid.KeyProvider]. The kid must be the canonical form reported by
// [Provider.State] or [Provider.ListKeyIds]; if it does not name a retained
// key, Supersede returns an argument error. Removal follows the rules
// documented on [Provider.Purge].
func (p *Provider) Supersede(kid string) error {
	p.mu.RLock()
	retained := contains(p.state.RetainedKeyIDs, kid)
	p.mu.RUnlock()
	if !retained {
		return dnsid.NewArgumentError(fmt.Sprintf("dnsid/awskms: no retained key %q", kid), nil)
	}
	return p.Purge(kid)
}

// Purge removes a pending or retained key, implementing [dnsid.KeyProvider].
// The kid must be the canonical form reported by [Provider.State]; the active
// key cannot be purged. When Config.ScheduleDeletionOnPurge is set, the
// underlying KMS key is scheduled for deletion after
// Config.DeletionWindowInDays days; if scheduling fails, the key is restored
// to its previous list and the error is returned.
func (p *Provider) Purge(kid string) error {
	p.mu.Lock()
	if kid == p.state.ActiveKeyID {
		p.mu.Unlock()
		return fmt.Errorf("dnsid/awskms: cannot purge active key")
	}
	retainedIdx := indexOf(p.state.RetainedKeyIDs, kid)
	pendingIdx := indexOf(p.state.PendingKeyIDs, kid)
	if retainedIdx < 0 && pendingIdx < 0 {
		p.mu.Unlock()
		return fmt.Errorf("dnsid/awskms: no pending or retained key %q", kid)
	}
	if retainedIdx >= 0 {
		p.state.RetainedKeyIDs = append(p.state.RetainedKeyIDs[:retainedIdx], p.state.RetainedKeyIDs[retainedIdx+1:]...)
	} else {
		p.state.PendingKeyIDs = append(p.state.PendingKeyIDs[:pendingIdx], p.state.PendingKeyIDs[pendingIdx+1:]...)
	}
	schedule := p.cfg.ScheduleDeletionOnPurge
	window := p.cfg.DeletionWindowInDays
	delete(p.cache, kid)
	p.mu.Unlock()

	if !schedule {
		return nil
	}
	ctx, cancel := p.operationContext()
	defer cancel()
	if err := p.client.ScheduleKeyDeletion(ctx, ScheduleKeyDeletionInput{KeyID: kid, PendingWindowInDays: window}); err != nil {
		p.mu.Lock()
		if kid != p.state.ActiveKeyID && !contains(p.state.RetainedKeyIDs, kid) && !contains(p.state.PendingKeyIDs, kid) {
			if retainedIdx >= 0 {
				p.state.RetainedKeyIDs = append(p.state.RetainedKeyIDs, kid)
			} else {
				p.state.PendingKeyIDs = append(p.state.PendingKeyIDs, kid)
			}
		}
		p.mu.Unlock()
		return err
	}
	return nil
}

func (p *Provider) canonicalizeState(ctx context.Context) error {
	active, err := p.canonicalKid(ctx, p.state.ActiveKeyID)
	if err != nil {
		return err
	}
	p.state.ActiveKeyID = active
	for i, kid := range p.state.RetainedKeyIDs {
		p.state.RetainedKeyIDs[i], err = p.canonicalKid(ctx, kid)
		if err != nil {
			return err
		}
	}
	for i, kid := range p.state.PendingKeyIDs {
		p.state.PendingKeyIDs[i], err = p.canonicalKid(ctx, kid)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Provider) canonicalKid(ctx context.Context, kid string) (string, error) {
	key, err := p.publicJWK(ctx, kid)
	if err != nil {
		return "", err
	}
	canonical, _ := key.KeyID()
	return canonical, nil
}

func (p *Provider) publicJWK(ctx context.Context, kid string) (jwk.Key, error) {
	if kid == "" || containsHash(kid) {
		return nil, fmt.Errorf("dnsid/awskms: invalid key ID %q", kid)
	}
	p.mu.RLock()
	if key := p.cache[kid]; key != nil {
		p.mu.RUnlock()
		return cloneJWK(key)
	}
	p.mu.RUnlock()

	out, err := p.client.GetPublicKey(ctx, GetPublicKeyInput{KeyID: kid})
	if err != nil {
		return nil, err
	}
	if out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("dnsid/awskms: key %s is not SIGN_VERIFY", kid)
	}
	if out.KeySpec != p.cfg.KeySpec {
		return nil, fmt.Errorf("dnsid/awskms: key spec mismatch: expected %s, got %s", p.cfg.KeySpec, out.KeySpec)
	}
	if !containsAlg(out.SigningAlgorithms, p.cfg.Algorithm) {
		return nil, fmt.Errorf("dnsid/awskms: key %s does not support %s", kid, p.cfg.Algorithm)
	}
	canonical := out.KeyID
	if canonical == "" {
		canonical = kid
	}
	if containsHash(canonical) {
		return nil, fmt.Errorf("dnsid/awskms: key ID must not contain '#'")
	}
	key, err := spkiToJWK(out.PublicKey, p.cfg.Algorithm, canonical)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.cache[kid] = key
	p.cache[canonical] = key
	p.mu.Unlock()
	return cloneJWK(key)
}

func spkiToJWK(spki []byte, alg types.SigningAlgorithmSpec, kid string) (jwk.Key, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("dnsid/awskms: parsing public key: %w", err)
	}
	switch alg {
	case types.SigningAlgorithmSpecEd25519Sha512:
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return nil, fmt.Errorf("dnsid/awskms: expected Ed25519 public key, got %T", pub)
		}
	case types.SigningAlgorithmSpecEcdsaSha256:
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			return nil, fmt.Errorf("dnsid/awskms: expected ECDSA P-256 public key, got %T", pub)
		}
	}
	key, err := jwk.Import(pub)
	if err != nil {
		return nil, fmt.Errorf("dnsid/awskms: importing JWK: %w", err)
	}
	jwaAlg, err := jwaAlg(alg)
	if err != nil {
		return nil, err
	}
	_ = key.Set(jwk.KeyIDKey, kid)
	_ = key.Set(jwk.AlgorithmKey, jwaAlg)
	_ = key.Set(jwk.KeyUsageKey, string(jwk.ForSignature))
	return key, nil
}

func signingMessage(payload []byte, alg types.SigningAlgorithmSpec) ([]byte, bool, error) {
	if len(payload) <= rawSignLimit {
		return payload, false, nil
	}
	if alg != types.SigningAlgorithmSpecEcdsaSha256 {
		return nil, false, fmt.Errorf("dnsid/awskms: RAW signing payload exceeds %d bytes", rawSignLimit)
	}
	h := sha256.Sum256(payload)
	return h[:], true, nil
}

func signatureForJOSE(alg types.SigningAlgorithmSpec, sig []byte) ([]byte, error) {
	if alg == types.SigningAlgorithmSpecEcdsaSha256 {
		return cryptoutil.ES256RawFromDER(sig)
	}
	return sig, nil
}

func defaultKeySpec(alg types.SigningAlgorithmSpec) (types.KeySpec, error) {
	switch alg {
	case types.SigningAlgorithmSpecEd25519Sha512:
		return types.KeySpecEccNistEdwards25519, nil
	case types.SigningAlgorithmSpecEcdsaSha256:
		return types.KeySpecEccNistP256, nil
	default:
		return "", fmt.Errorf("dnsid/awskms: unsupported algorithm %s", alg)
	}
}

func joseAlg(alg types.SigningAlgorithmSpec) (dnsid.JoseAlg, error) {
	switch alg {
	case types.SigningAlgorithmSpecEd25519Sha512:
		return dnsid.JoseAlgEdDSA, nil
	case types.SigningAlgorithmSpecEcdsaSha256:
		return dnsid.JoseAlgES256, nil
	default:
		return "", fmt.Errorf("dnsid/awskms: unsupported algorithm %s", alg)
	}
}

func jwaAlg(alg types.SigningAlgorithmSpec) (jwa.SignatureAlgorithm, error) {
	switch alg {
	case types.SigningAlgorithmSpecEd25519Sha512:
		return jwa.EdDSA(), nil
	case types.SigningAlgorithmSpecEcdsaSha256:
		return jwa.ES256(), nil
	default:
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf("dnsid/awskms: unsupported algorithm %s", alg)
	}
}

func (p *Provider) operationContext() (context.Context, context.CancelFunc) {
	if p.cfg.OperationTimeout <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), p.cfg.OperationTimeout)
}

func containsAlg(xs []types.SigningAlgorithmSpec, want types.SigningAlgorithmSpec) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func awsTags(tags map[string]string) []types.Tag {
	out := make([]types.Tag, 0, len(tags))
	for k, v := range tags {
		out = append(out, types.Tag{TagKey: aws.String(k), TagValue: aws.String(v)})
	}
	return out
}

func cloneState(s State) State {
	s.RetainedKeyIDs = append([]string(nil), s.RetainedKeyIDs...)
	s.PendingKeyIDs = append([]string(nil), s.PendingKeyIDs...)
	return s
}

func cloneJWK(key jwk.Key) (jwk.Key, error) { return key.Clone() }

func contains(xs []string, want string) bool { return indexOf(xs, want) >= 0 }
func indexOf(xs []string, want string) int {
	for i, x := range xs {
		if x == want {
			return i
		}
	}
	return -1
}
func containsHash(s string) bool {
	for _, r := range s {
		if r == '#' {
			return true
		}
	}
	return false
}

// New constructs a [Provider]. It is equivalent to [Load].
func New(ctx context.Context, client Client, cfg Config) (*Provider, error) {
	return Load(ctx, client, cfg)
}

// Compile-time check that Provider implements dnsid.KeyProvider.
var _ dnsid.KeyProvider = (*Provider)(nil)
