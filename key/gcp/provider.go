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
// call has a 30-second timeout. Lifecycle operations are not yet supported.
type Provider struct {
	client      Client
	version     string
	kid         string
	public      ed25519.PublicKey
	key         jwk.Key
	closeClient func() error
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
	return &Provider{client: client, version: cfg.KeyVersionName, kid: kid, public: public, key: key}, nil
}

func validCRC(data []byte, sum *wrapperspb.Int64Value) bool {
	return sum != nil && sum.Value == int64(crc32.Checksum(data, crcTable))
}

// JWK returns a detached public JWK for the active key, or nil for an unknown ID.
func (p *Provider) JWK(kid ...string) jwk.Key {
	if len(kid) > 1 || (len(kid) == 1 && kid[0] != p.kid) {
		return nil
	}
	key, err := p.key.Clone()
	if err != nil {
		return nil
	}
	return key
}

// ListKeyIds returns the single active public-key thumbprint.
func (p *Provider) ListKeyIds() []string { return []string{p.kid} }

// Sign signs payload without prehashing, using the configured active version.
func (p *Provider) Sign(payload []byte) (*dnsid.KeySignature, error) {
	return p.SignKey(p.kid, payload)
}

// SignKey signs with the selected key; unknown IDs fail before any API call.
func (p *Provider) SignKey(kid string, payload []byte) (*dnsid.KeySignature, error) {
	if kid != p.kid {
		return nil, dnsid.NewArgumentError("dnsid/gcpkms: unknown signing key", nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	response, err := p.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: p.version, Data: payload, DataCrc32C: wrapperspb.Int64(int64(crc32.Checksum(payload, crcTable))),
	})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Name != p.version || !response.VerifiedDataCrc32C || response.ProtectionLevel != kmspb.ProtectionLevel_SOFTWARE || !validCRC(response.Signature, response.SignatureCrc32C) {
		return nil, fmt.Errorf("dnsid/gcpkms: untrusted signing response binding or integrity")
	}
	if !ed25519.Verify(p.public, payload, response.Signature) {
		return nil, fmt.Errorf("dnsid/gcpkms: invalid Ed25519 signature")
	}
	return &dnsid.KeySignature{Kid: p.kid, Alg: dnsid.JoseAlgEdDSA, Signature: append([]byte(nil), response.Signature...)}, nil
}

// GenerateKey is unavailable; opening this provider never generates a version.
func (p *Provider) GenerateKey(dnsid.JoseAlg) (string, error) { return "", lifecycleUnavailable() }

// Activate is unavailable in the existing-version runtime.
func (p *Provider) Activate(string) error { return lifecycleUnavailable() }

// Supersede is unavailable and never changes remote version state.
func (p *Provider) Supersede(string) error { return lifecycleUnavailable() }

// Purge is unavailable and never destroys a remote version.
func (p *Provider) Purge(string) error { return lifecycleUnavailable() }
func lifecycleUnavailable() error {
	return dnsid.NewArgumentError("dnsid/gcpkms: key lifecycle operations are not available", nil)
}

// Close releases the client created by configuration loading. For New, the
// caller owns the supplied client and Close is a no-op. Call only after all
// provider operations have completed.
func (p *Provider) Close() error {
	if p.closeClient != nil {
		return p.closeClient()
	}
	return nil
}
