//go:build dnsid_foundry

package foundry

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/cryptoutil"
	"github.com/dnsid-ai/dnsid-go/internal/joseutil"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// signingController gates the provider exposed by IdentityManager. Workflow
// issuance signatures use the underlying provider while paused.
type signingController struct {
	dnsid.KeyProvider
	mu     sync.Mutex
	paused bool
	reason string
	kid    string
	public jwk.Key
	facts  Error
}

func newSigningController(provider dnsid.KeyProvider, doc *RecoveryDocument) *signingController {
	return &signingController{KeyProvider: provider, paused: true, reason: "public ACTIVE has not been verified", facts: *failure(Unresolved, doc, nil)}
}

func (s *signingController) pausedError(reason string) *SigningPaused {
	return &SigningPaused{Reason: reason, Phase: s.facts.Phase, IdentityID: s.facts.IdentityID, Domain: s.facts.Domain, RegistryStatus: s.facts.RegistryStatus}
}

func (s *signingController) updateFacts(doc *RecoveryDocument) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.facts = *failure(Unresolved, doc, nil)
}

func (s *signingController) Sign(data []byte) (*dnsid.KeySignature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.paused {
		return nil, s.pausedError(s.reason)
	}
	result, err := s.KeyProvider.Sign(data)
	return s.checked(result, err, data)
}

func (s *signingController) SignKey(kid string, data []byte) (*dnsid.KeySignature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.paused || kid != s.kid {
		return nil, s.pausedError(s.reason)
	}
	result, err := s.KeyProvider.SignKey(kid, data)
	return s.checked(result, err, data)
}

func (s *signingController) checked(result *dnsid.KeySignature, err error, data []byte) (*dnsid.KeySignature, error) {
	if err != nil {
		return nil, err
	}
	if result == nil || result.Kid != s.kid || !joseutil.VerifySignature(joseutil.ProtectedHeader{Alg: result.Alg}, joseutil.SignatureParts{SigningInput: data, Signature: result.Signature}, []jwk.Key{s.public}) {
		s.paused = true
		s.reason = "provider signing key changed"
		return nil, s.pausedError(s.reason)
	}
	return result, nil
}

func (s *signingController) pause(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paused = true
	s.reason = reason
}

func (s *signingController) enable(key jwk.Key) error {
	kid, ok := key.KeyID()
	if !ok || kid == "" {
		return fmt.Errorf("foundry: verified key has no kid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kid = kid
	s.public = key
	s.paused = false
	s.reason = ""
	return nil
}

func providerPublic(ctx context.Context, provider dnsid.KeyProvider) (jwk.Key, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(provider.ListKeyIds()) == 0 {
		return nil, failure(KeyMissing, nil, fmt.Errorf("provider has no signing key"))
	}
	var key jwk.Key
	var err error
	switch p := provider.(type) {
	case interface {
		JWKContext(context.Context, ...string) (jwk.Key, error)
	}:
		key, err = p.JWKContext(ctx)
	case interface {
		JWKWithError(...string) (jwk.Key, error)
	}:
		key, err = p.JWKWithError()
	default:
		key = provider.JWK()
	}
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if key == nil {
		return nil, failure(Integrity, nil, fmt.Errorf("provider lists keys but has no current public signing key"))
	}
	raw, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(raw)
}

func validateProviderKey(ctx context.Context, provider dnsid.KeyProvider, live bool) error {
	key, err := providerPublic(ctx, provider)
	if err != nil {
		return err
	}
	if !live {
		set := jwk.NewSet()
		if err := set.AddKey(key); err != nil {
			return err
		}
		if _, err := dnsid.NewJWKS(set).CurrentOperationalSigningKey(dnsid.DefaultPublishProfile); err != nil {
			return failure(UnsupportedAlgorithm, nil, err)
		}
		return nil
	}
	alg, ok := key.Algorithm()
	var pub ed25519.PublicKey
	if !ok || alg.String() != string(dnsid.JoseAlgEdDSA) || jwk.Export(key, &pub) != nil || !cryptoutil.ValidEd25519PublicKey(pub) {
		return failure(UnsupportedAlgorithm, nil, fmt.Errorf("live registration requires an Ed25519 public signing key with alg=EdDSA"))
	}
	thumb, err := keyThumb(key)
	if err != nil {
		return err
	}
	kid, ok := key.KeyID()
	if !ok || kid != thumb {
		return failure(Integrity, nil, fmt.Errorf("live signing kid must equal the RFC 7638 thumbprint"))
	}
	if use, ok := key.KeyUsage(); ok && use != "sig" {
		return failure(UnsupportedAlgorithm, nil, fmt.Errorf("live key use must be sig"))
	}
	return nil
}

// deadlineProvider passes cancellation to optional contextual signing methods,
// otherwise checks the budget on both sides of the existing provider call.
type deadlineProvider struct {
	dnsid.KeyProvider
	ctx context.Context
}

func (p deadlineProvider) SignKey(kid string, data []byte) (*dnsid.KeySignature, error) {
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}
	var result *dnsid.KeySignature
	var err error
	if provider, ok := p.KeyProvider.(interface {
		SignKeyContext(context.Context, string, []byte) (*dnsid.KeySignature, error)
	}); ok {
		result, err = provider.SignKeyContext(p.ctx, kid, data)
	} else {
		result, err = p.KeyProvider.SignKey(kid, data)
	}
	if deadline := p.ctx.Err(); deadline != nil {
		return nil, deadline
	}
	return result, err
}
func (p deadlineProvider) Sign(data []byte) (*dnsid.KeySignature, error) {
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}
	var result *dnsid.KeySignature
	var err error
	if provider, ok := p.KeyProvider.(interface {
		SignContext(context.Context, []byte) (*dnsid.KeySignature, error)
	}); ok {
		result, err = provider.SignContext(p.ctx, data)
	} else {
		result, err = p.KeyProvider.Sign(data)
	}
	if deadline := p.ctx.Err(); deadline != nil {
		return nil, deadline
	}
	return result, err
}
