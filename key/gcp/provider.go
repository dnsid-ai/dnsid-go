package gcpkms

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"regexp"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/googleapis/gax-go/v2"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Client is the official Google Cloud KMS runtime surface used by Provider.
// A *kms.KeyManagementClient implements it directly. The caller owns its lifetime.
type Client interface {
	GetPublicKey(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error)
	AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

// Config selects an existing immutable software Ed25519 version.
type Config struct {
	// KeyVersionName is projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}/cryptoKeyVersions/{number}.
	KeyVersionName string
}

// Provider signs RAW Ed25519 messages using an existing Google Cloud KMS version.
// It caches only public material and is safe for concurrent use. Each signing
// call has a 30-second timeout. Rotation state is local and in-memory only.
type Provider struct {
	mu          sync.RWMutex
	client      Client
	version     string
	kid         string
	keys        map[string]*keyEntry
	closeClient func() error
}

type keyEntry struct {
	version string
	public  ed25519.PublicKey
	key     jwk.Key
	pending bool
}

var versionName = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/locations/[A-Za-z0-9_-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+/cryptoKeyVersions/[1-9][0-9]*$`)
var crcTable = crc32.MakeTable(crc32.Castagnoli)

func validateVersion(name string) error {
	if !versionName.MatchString(name) {
		return dnsid.NewArgumentError("dnsid/gcpkms: keyRef must be a fully qualified immutable numeric CryptoKeyVersion name", nil)
	}
	return nil
}

// New opens an existing version, validating its binding, algorithm, software
// protection and public-key CRC32C. It never creates a key or substitutes a signer.
// Service and context errors are preserved for errors.Is and gRPC status handling.
func New(ctx context.Context, client Client, cfg Config) (*Provider, error) {
	if err := validateVersion(cfg.KeyVersionName); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, dnsid.NewArgumentError("dnsid/gcpkms: nil client", nil)
	}
	response, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: cfg.KeyVersionName})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Name != cfg.KeyVersionName || response.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_ED25519 || response.ProtectionLevel != kmspb.ProtectionLevel_SOFTWARE {
		return nil, fmt.Errorf("dnsid/gcpkms: invalid public key version, algorithm or protection level")
	}
	if !validCRC([]byte(response.Pem), response.PemCrc32C) {
		return nil, fmt.Errorf("dnsid/gcpkms: public key CRC32C mismatch or missing")
	}
	block, rest := pem.Decode([]byte(response.Pem))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, fmt.Errorf("dnsid/gcpkms: expected a single public SPKI PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("dnsid/gcpkms: parse public SPKI: %w", err)
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("dnsid/gcpkms: SPKI is not Ed25519")
	}
	key, err := jwk.Import(public)
	if err != nil {
		return nil, err
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	kid := base64.RawURLEncoding.EncodeToString(thumb)
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.EdDSA()); err != nil {
		return nil, err
	}
	return &Provider{client: client, version: cfg.KeyVersionName, kid: kid, keys: map[string]*keyEntry{kid: {version: cfg.KeyVersionName, public: public, key: key}}}, nil
}

func validCRC(data []byte, sum *wrapperspb.Int64Value) bool {
	return sum != nil && sum.Value == int64(crc32.Checksum(data, crcTable))
}

// JWK returns a detached public JWK for the active key, or nil for an unknown ID.
func (p *Provider) JWK(kid ...string) jwk.Key {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(kid) > 1 {
		return nil
	}
	id := p.kid
	if len(kid) == 1 {
		id = kid[0]
	}
	entry := p.keys[id]
	if entry == nil {
		return nil
	}
	key, err := entry.key.Clone()
	if err != nil {
		return nil
	}
	return key
}

// ListKeyIds returns only the active public-key thumbprint, never pending or retained IDs.
func (p *Provider) ListKeyIds() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.kid == "" {
		return []string{}
	}
	return []string{p.kid}
}

// Sign signs payload without prehashing, using the active version.
func (p *Provider) Sign(payload []byte) (*dnsid.KeySignature, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.signKey(p.kid, payload)
}

// SignKey signs with an active or pending key. Retained and unknown IDs fail
// before any API call. Local transitions wait for in-flight signatures to finish.
func (p *Provider) SignKey(kid string, payload []byte) (*dnsid.KeySignature, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.signKey(kid, payload)
}

func (p *Provider) signKey(kid string, payload []byte) (*dnsid.KeySignature, error) {
	entry := p.keys[kid]
	if entry == nil || (kid != p.kid && !entry.pending) {
		return nil, dnsid.NewArgumentError("dnsid/gcpkms: key is not signing-eligible", nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	response, err := p.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: entry.version, Data: payload, DataCrc32C: wrapperspb.Int64(int64(crc32.Checksum(payload, crcTable))),
	})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Name != entry.version || !response.VerifiedDataCrc32C || response.ProtectionLevel != kmspb.ProtectionLevel_SOFTWARE || !validCRC(response.Signature, response.SignatureCrc32C) {
		return nil, fmt.Errorf("dnsid/gcpkms: untrusted signing response binding or integrity")
	}
	if !ed25519.Verify(entry.public, payload, response.Signature) {
		return nil, fmt.Errorf("dnsid/gcpkms: invalid Ed25519 signature")
	}
	return &dnsid.KeySignature{Kid: kid, Alg: dnsid.JoseAlgEdDSA, Signature: append([]byte(nil), response.Signature...)}, nil
}

type versionCreator interface {
	CreateCryptoKeyVersion(context.Context, *kmspb.CreateCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
}

// GenerateKey explicitly creates a pending Ed25519 version under the configured
// CryptoKey. The parent template must specify software EC_SIGN_ED25519. The
// client must also support the official CreateCryptoKeyVersion method. Failed
// validation leaves local state unchanged; cloud cleanup is operator-owned.
func (p *Provider) GenerateKey(alg dnsid.JoseAlg) (string, error) {
	if alg != dnsid.JoseAlgEdDSA {
		return "", dnsid.NewArgumentError("dnsid/gcpkms: only EdDSA generation is supported", nil)
	}
	creator, ok := p.client.(versionCreator)
	if !ok {
		return "", dnsid.NewArgumentError("dnsid/gcpkms: client does not support version creation", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	parent := p.version[:strings.LastIndex(p.version, "/cryptoKeyVersions/")]
	response, err := creator.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{Parent: parent})
	if err != nil {
		return "", err
	}
	if response == nil || validateVersion(response.Name) != nil || !strings.HasPrefix(response.Name, parent+"/cryptoKeyVersions/") || response.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_ED25519 || response.State != kmspb.CryptoKeyVersion_ENABLED || response.ProtectionLevel != kmspb.ProtectionLevel_SOFTWARE {
		return "", fmt.Errorf("dnsid/gcpkms: generated version has invalid binding or metadata")
	}
	opened, err := New(ctx, p.client, Config{KeyVersionName: response.Name})
	if err != nil {
		return "", err
	}
	if _, exists := p.keys[opened.kid]; exists {
		return "", fmt.Errorf("dnsid/gcpkms: generated key duplicates an existing public key")
	}
	entry := opened.keys[opened.kid]
	entry.pending = true
	p.keys[opened.kid] = entry
	return opened.kid, nil
}

// Activate explicitly promotes a pending key. The previous key remains available
// as a public JWK but cannot sign. No remote version state is changed.
func (p *Provider) Activate(kid string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := p.keys[kid]
	if entry == nil {
		return dnsid.NewArgumentError("dnsid/gcpkms: unknown activation key", nil)
	}
	if kid == p.kid {
		return nil
	}
	if !entry.pending {
		return dnsid.NewArgumentError("dnsid/gcpkms: activation requires a pending key", nil)
	}
	entry.pending = false
	p.kid = kid
	return nil
}

// Supersede removes local signing eligibility and public access, without
// disabling or destroying any cloud version. A different active key is preserved.
func (p *Provider) Supersede(kid string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.keys[kid]; !ok {
		return dnsid.NewArgumentError("dnsid/gcpkms: unknown supersession key", nil)
	}
	delete(p.keys, kid)
	if p.kid == kid {
		p.kid = ""
	}
	return nil
}

// Purge removes a pending or retained key locally. It rejects the active key
// and never changes cloud state.
func (p *Provider) Purge(kid string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if kid == p.kid {
		return dnsid.NewArgumentError("dnsid/gcpkms: cannot purge active key", nil)
	}
	if _, ok := p.keys[kid]; !ok {
		return dnsid.NewArgumentError("dnsid/gcpkms: unknown purge key", nil)
	}
	delete(p.keys, kid)
	return nil
}

// Close releases the client created by Open or configuration loading. For New,
// the caller owns the supplied client and Close is a no-op. Connections supplied
// through option.WithGRPCConn may also be closed by the official client. Call
// only after all provider operations have completed.
func (p *Provider) Close() error {
	if p.closeClient != nil {
		return p.closeClient()
	}
	return nil
}
