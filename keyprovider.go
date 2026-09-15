package dnsid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// KeySignature is the result of signing with a KeyProvider's active key.
type KeySignature struct {
	Kid       string
	Alg       JoseAlg
	Signature []byte
}

// KeyProvider abstracts key storage for the SDK.
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

func activeSigningKid(kp KeyProvider) (string, error) {
	if kp == nil {
		return "", NewArgumentError("dnsid: nil KeyProvider", nil)
	}
	key := kp.JWK()
	if key == nil {
		return "", NewArgumentError("dnsid: KeyProvider has no active key", nil)
	}
	kid, ok := key.KeyID()
	if !ok || kid == "" {
		return "", NewArgumentError("dnsid: active signing key missing kid", nil)
	}
	return kid, nil
}

type localKeyState string

const (
	localKeyPending  localKeyState = "pending"
	localKeyActive   localKeyState = "active"
	localKeyRetained localKeyState = "retained"
)

type localKeyEntry struct {
	kid    string
	alg    JoseAlg
	signer crypto.Signer
	state  localKeyState
}

type localKeyStoreFile struct {
	Active   json.RawMessage   `json:"active"`
	Retained []json.RawMessage `json:"retained"`
	Pending  []json.RawMessage `json:"pending"`
}

// ErrKeyStoreDurability means the new key store is visible on disk, but syncing
// its directory failed. The mutation is NOT rolled back in memory. Stop the
// workflow and resolve the storage error before proceeding; see OPERATIONS.md.
var ErrKeyStoreDurability = errors.New("dnsid: key store published but durability uncertain")

// LocalKeyProvider loads a JWK keypair from disk or holds in-memory keys.
// Only one provider instance may write a given file; there is no file locking.
type LocalKeyProvider struct {
	mu        sync.RWMutex
	keys      map[string]*localKeyEntry
	order     []string
	activeKid string
	path      string
	syncFile  func(*os.File) error // nil uses File.Sync; per-instance fault injection in tests
}

// NewLocalKeyProvider loads a key store file. It accepts the current
// active/retained/pending store shape and the older flat private JWK shape.
func NewLocalKeyProvider(path string) (*LocalKeyProvider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, NewParseError(fmt.Sprintf("dnsid: reading key file %q", path), err)
	}

	kp := &LocalKeyProvider{keys: make(map[string]*localKeyEntry), path: path}
	var store localKeyStoreFile
	if err := json.Unmarshal(data, &store); err == nil && len(store.Active) != 0 {
		if err := kp.addKeyJSON(store.Active, localKeyActive); err != nil {
			return nil, NewParseError("dnsid: parsing active key", err)
		}
		for _, raw := range store.Retained {
			if err := kp.addKeyJSON(raw, localKeyRetained); err != nil {
				return nil, NewParseError("dnsid: parsing retained key", err)
			}
		}
		for _, raw := range store.Pending {
			if err := kp.addKeyJSON(raw, localKeyPending); err != nil {
				return nil, NewParseError("dnsid: parsing pending key", err)
			}
		}
		return kp, nil
	}

	if err := kp.addKeyJSON(data, localKeyActive); err != nil {
		return nil, NewParseError("dnsid: parsing key file", err)
	}
	return kp, nil
}

// LoadOrCreateLocalKeyProvider loads a JWK keypair from disk, or creates one if path does not exist.
func LoadOrCreateLocalKeyProvider(path string, alg JoseAlg) (*LocalKeyProvider, error) {
	return loadOrCreateLocalKeyProvider(path, alg, (*os.File).Sync)
}

func loadOrCreateLocalKeyProvider(path string, alg JoseAlg, syncFile func(*os.File) error) (*LocalKeyProvider, error) {
	if !alg.Valid() {
		return nil, NewArgumentError(fmt.Sprintf("dnsid: unsupported JOSE alg %q", alg), nil)
	}
	kp, err := NewLocalKeyProvider(path)
	if err == nil {
		return kp, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	signer, err := generateSigner(alg)
	if err != nil {
		return nil, err
	}
	entry, err := newLocalKeyEntry(signer, localKeyActive)
	if err != nil {
		return nil, err
	}
	key, err := privateJWKForEntry(entry)
	if err != nil {
		return nil, err
	}
	active, err := rawJWK(key)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(localKeyStoreFile{Active: active, Retained: []json.RawMessage{}, Pending: []json.RawMessage{}}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("dnsid: marshaling key store: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return NewLocalKeyProvider(path)
		}
		return nil, fmt.Errorf("dnsid: writing key file: %w", err)
	}
	_, writeErr := f.Write(append(data, '\n'))
	if writeErr == nil {
		writeErr = syncFile(f)
	}
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("dnsid: writing key file: %w", writeErr)
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("dnsid: closing key file: %w", closeErr)
	}
	if err := syncKeyDirectory(path, syncFile); err != nil {
		return nil, err
	}
	kp = &LocalKeyProvider{keys: make(map[string]*localKeyEntry), path: path}
	kp.addEntry(entry)
	return kp, nil
}

// GenerateEd25519KeyProvider creates an ephemeral in-memory Ed25519 keypair.
func GenerateEd25519KeyProvider() *LocalKeyProvider {
	signer, err := generateSigner(JoseAlgEdDSA)
	if err != nil {
		panic(err.Error())
	}
	kp, err := newLocalKeyProviderFromSigner(signer, localKeyActive)
	if err != nil {
		panic("dnsid: creating Ed25519 key provider: " + err.Error())
	}
	return kp
}

// GenerateES256KeyProvider creates an ephemeral in-memory ES256 keypair.
func GenerateES256KeyProvider() *LocalKeyProvider {
	signer, err := generateSigner(JoseAlgES256)
	if err != nil {
		panic(err.Error())
	}
	kp, err := newLocalKeyProviderFromSigner(signer, localKeyActive)
	if err != nil {
		panic("dnsid: creating ES256 key provider: " + err.Error())
	}
	return kp
}

func newLocalKeyProviderFromSigner(signer crypto.Signer, state localKeyState) (*LocalKeyProvider, error) {
	entry, err := newLocalKeyEntry(signer, state)
	if err != nil {
		return nil, err
	}
	kp := &LocalKeyProvider{keys: make(map[string]*localKeyEntry)}
	kp.addEntry(entry)
	return kp, nil
}

func (p *LocalKeyProvider) addKeyJSON(data []byte, state localKeyState) error {
	entry, err := localKeyEntryFromJWK(data, state)
	if err != nil {
		return err
	}
	if p.keys == nil {
		p.keys = make(map[string]*localKeyEntry)
	}
	if _, exists := p.keys[entry.kid]; exists {
		return NewValidationError(fmt.Sprintf("dnsid: duplicate kid %q in key store", entry.kid), nil)
	}
	p.addEntry(entry)
	return nil
}

func (p *LocalKeyProvider) addEntry(entry *localKeyEntry) {
	p.keys[entry.kid] = entry
	p.order = append(p.order, entry.kid)
	if entry.state == localKeyActive {
		p.activeKid = entry.kid
	}
}

func localKeyEntryFromJWK(data []byte, state localKeyState) (*localKeyEntry, error) {
	parsed, err := jwk.ParseKey(data)
	if err != nil {
		return nil, NewParseError("dnsid: parsing JWK", err)
	}

	var signer crypto.Signer
	switch parsed.KeyType() {
	case jwa.OKP():
		okpKey, ok := parsed.(jwk.OKPPrivateKey)
		if !ok {
			return nil, NewValidationError(fmt.Sprintf("dnsid: key must be Ed25519 private key (OKP/crv=Ed25519), got %s", parsed.KeyType()), nil)
		}
		crv, crvOK := okpKey.Crv()
		if !crvOK || crv != jwa.Ed25519() {
			return nil, NewValidationError(fmt.Sprintf("dnsid: key must be Ed25519 (OKP/crv=Ed25519), got %s", parsed.KeyType()), nil)
		}
		var rawPriv ed25519.PrivateKey
		if err := jwk.Export(parsed, &rawPriv); err != nil {
			return nil, fmt.Errorf("dnsid: extracting Ed25519 private key: %w", err)
		}
		signer = rawPriv
	case jwa.EC():
		ecKey, ok := parsed.(jwk.ECDSAPrivateKey)
		if !ok {
			return nil, NewValidationError(fmt.Sprintf("dnsid: key must be EC private key (crv=P-256), got %s", parsed.KeyType()), nil)
		}
		crv, crvOK := ecKey.Crv()
		if !crvOK || crv != jwa.P256() {
			return nil, NewValidationError(fmt.Sprintf("dnsid: key must be ES256 (EC/crv=P-256), got %s", parsed.KeyType()), nil)
		}
		var rawPriv ecdsa.PrivateKey
		if err := jwk.Export(parsed, &rawPriv); err != nil {
			return nil, fmt.Errorf("dnsid: extracting P-256 private key: %w", err)
		}
		signer = &rawPriv
	default:
		return nil, NewValidationError(fmt.Sprintf("dnsid: unsupported key type %s", parsed.KeyType()), nil)
	}

	entry, err := newLocalKeyEntry(signer, state)
	if err != nil {
		return nil, err
	}
	if kid, ok := parsed.KeyID(); ok && kid != "" {
		entry.kid = kid
	}
	return entry, nil
}

func newLocalKeyEntry(signer crypto.Signer, state localKeyState) (*localKeyEntry, error) {
	if signer == nil {
		return nil, fmt.Errorf("dnsid: nil signer")
	}
	alg, err := joseAlgForPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	_, kid, err := publicJWKForSigner(signer, alg)
	if err != nil {
		return nil, err
	}
	return &localKeyEntry{
		kid:    kid,
		alg:    alg,
		signer: signer,
		state:  state,
	}, nil
}

func generateSigner(alg JoseAlg) (crypto.Signer, error) {
	switch alg {
	case JoseAlgEdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("dnsid: generating Ed25519 key: %w", err)
		}
		return priv, nil
	case JoseAlgES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("dnsid: generating P-256 key: %w", err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("dnsid: unsupported JOSE alg %q", alg)
	}
}

func privateJWKForEntry(entry *localKeyEntry) (jwk.Key, error) {
	return privateJWKForSigner(entry.signer, entry.alg, entry.kid)
}

func privateJWKForSigner(signer crypto.Signer, alg JoseAlg, kid string) (jwk.Key, error) {
	privJWK, err := jwk.Import(signer)
	if err != nil {
		return nil, fmt.Errorf("dnsid: importing private key to JWK: %w", err)
	}
	if kid == "" {
		_, computedKid, err := publicJWKForSigner(signer, alg)
		if err != nil {
			return nil, err
		}
		kid = computedKid
	}
	jwaAlg, ok := alg.jwa()
	if !ok {
		return nil, fmt.Errorf("dnsid: unsupported JOSE alg %q", alg)
	}
	if err := privJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("dnsid: setting kid: %w", err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwaAlg); err != nil {
		return nil, fmt.Errorf("dnsid: setting alg: %w", err)
	}
	if err := privJWK.Set(jwk.KeyUsageKey, string(jwk.ForSignature)); err != nil {
		return nil, fmt.Errorf("dnsid: setting use: %w", err)
	}
	return privJWK, nil
}

func rawJWK(key jwk.Key) (json.RawMessage, error) {
	data, err := json.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("dnsid: marshaling JWK: %w", err)
	}
	return data, nil
}

func (p *LocalKeyProvider) persistLocked() error {
	if p.path == "" {
		return nil
	}
	store := localKeyStoreFile{Retained: []json.RawMessage{}, Pending: []json.RawMessage{}}
	for _, kid := range p.order {
		entry := p.keys[kid]
		if entry == nil {
			continue
		}
		key, err := privateJWKForEntry(entry)
		if err != nil {
			return err
		}
		raw, err := rawJWK(key)
		if err != nil {
			return err
		}
		switch entry.state {
		case localKeyActive:
			store.Active = raw
		case localKeyRetained:
			store.Retained = append(store.Retained, raw)
		case localKeyPending:
			store.Pending = append(store.Pending, raw)
		}
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("dnsid: marshaling key store: %w", err)
	}
	syncFile := p.syncFile
	if syncFile == nil {
		syncFile = (*os.File).Sync
	}
	return writeFileAtomic(p.path, append(data, '\n'), 0o600, syncFile)
}

// syncKeyDirectory is called only after publication: errors must not cause
// callers to roll back memory or delete the newly published key file.
func syncKeyDirectory(path string, syncFile func(*os.File) error) error {
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		err = syncFile(dir)
		err = errors.Join(err, dir.Close())
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKeyStoreDurability, err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode, syncFile func(*os.File) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".dnsid-keys-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := syncFile(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncKeyDirectory(path, syncFile)
}

func publicJWKForSigner(signer crypto.Signer, alg JoseAlg) (jwk.Key, string, error) {
	pubJWK, err := jwk.Import(signer.Public())
	if err != nil {
		return nil, "", fmt.Errorf("dnsid: importing public key to JWK: %w", err)
	}
	thumbBytes, err := pubJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, "", fmt.Errorf("dnsid: computing JWK thumbprint: %w", err)
	}
	return publicJWKForSignerWithKid(signer, alg, base64.RawURLEncoding.EncodeToString(thumbBytes))
}

func publicJWKForSignerWithKid(signer crypto.Signer, alg JoseAlg, kid string) (jwk.Key, string, error) {
	pubJWK, err := jwk.Import(signer.Public())
	if err != nil {
		return nil, "", fmt.Errorf("dnsid: importing public key to JWK: %w", err)
	}
	jwaAlg, ok := alg.jwa()
	if !ok {
		return nil, "", fmt.Errorf("dnsid: unsupported JOSE alg %q", alg)
	}
	if err := pubJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, "", fmt.Errorf("dnsid: setting kid: %w", err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, jwaAlg); err != nil {
		return nil, "", fmt.Errorf("dnsid: setting alg: %w", err)
	}
	if err := pubJWK.Set(jwk.KeyUsageKey, string(jwk.ForSignature)); err != nil {
		return nil, "", fmt.Errorf("dnsid: setting use: %w", err)
	}
	return pubJWK, kid, nil
}

func joseAlgForPublicKey(pub crypto.PublicKey) (JoseAlg, error) {
	switch p := pub.(type) {
	case ed25519.PublicKey:
		if len(p) != ed25519.PublicKeySize {
			return "", fmt.Errorf("dnsid: invalid Ed25519 public key size: %d", len(p))
		}
		return JoseAlgEdDSA, nil
	case *ecdsa.PublicKey:
		if err := validateP256PublicKey(p); err != nil {
			return "", fmt.Errorf("dnsid: invalid ES256 public key: %w", err)
		}
		return JoseAlgES256, nil
	default:
		return "", fmt.Errorf("dnsid: unsupported public key type %T", pub)
	}
}

// JWK returns the public JWK for the requested kid, or for the active key
// when no kid is given. The returned key carries kid, alg, and use=sig. It
// returns nil when the kid is unknown or no key is active.
func (p *LocalKeyProvider) JWK(kidOpt ...string) jwk.Key {
	p.mu.RLock()
	defer p.mu.RUnlock()
	selectedKid := p.activeKid
	if len(kidOpt) > 0 {
		selectedKid = kidOpt[0]
	}
	entry := p.keys[selectedKid]
	if entry == nil {
		return nil
	}
	key, keyID, err := publicJWKForSignerWithKid(entry.signer, entry.alg, entry.kid)
	if err != nil || keyID != entry.kid {
		return nil
	}
	return key
}

// ListKeyIds returns the active kid first, followed by retained kids in
// insertion order. Pending kids are not listed.
func (p *LocalKeyProvider) ListKeyIds() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var ids []string
	if p.activeKid != "" {
		ids = append(ids, p.activeKid)
	}
	for _, kid := range p.order {
		entry := p.keys[kid]
		if entry != nil && entry.state == localKeyRetained {
			ids = append(ids, kid)
		}
	}
	return ids
}

// Sign signs payload with the active key. It returns an error when no key is
// active. ES256 signatures are deterministic (RFC 6979) raw R||S; EdDSA
// signatures are standard Ed25519.
func (p *LocalKeyProvider) Sign(payload []byte) (*KeySignature, error) {
	p.mu.RLock()
	kid := p.activeKid
	p.mu.RUnlock()
	if kid == "" {
		return nil, NewArgumentError("dnsid: no active signing key", nil)
	}
	return p.SignKey(kid, payload)
}

// SignKey signs payload with the named key, which must be in the active or
// pending state; signing with a retained key returns an *ArgumentError.
func (p *LocalKeyProvider) SignKey(kid string, payload []byte) (*KeySignature, error) {
	p.mu.RLock()
	entry := p.keys[kid]
	if entry == nil || (entry.state != localKeyActive && entry.state != localKeyPending) {
		p.mu.RUnlock()
		return nil, NewArgumentError(fmt.Sprintf("dnsid: key %q is not active or pending for signing", kid), nil)
	}
	alg, signer := entry.alg, entry.signer
	p.mu.RUnlock()

	var sig []byte
	var err error
	switch alg {
	case JoseAlgEdDSA:
		if priv, ok := signer.(ed25519.PrivateKey); ok {
			sig = ed25519.Sign(priv, payload)
			break
		}
		sig, err = signer.Sign(rand.Reader, payload, crypto.Hash(0))
	case JoseAlgES256:
		priv, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			return nil, NewArgumentError(fmt.Sprintf("dnsid: ES256 signing requires *ecdsa.PrivateKey for deterministic RFC6979 signing, got %T", signer), nil)
		}
		sig, err = signES256(priv, payload)
	default:
		err = NewArgumentError(fmt.Sprintf("dnsid: unsupported signing alg %q", alg), nil)
	}
	if err != nil {
		return nil, fmt.Errorf("dnsid: key provider signing failed: %w", err)
	}
	return &KeySignature{Kid: kid, Alg: alg, Signature: sig}, nil
}

// GenerateKey creates a new pending key for alg and returns its kid (the
// key's RFC 7638 thumbprint). The new key is persisted to the provider's key
// store file, when one is configured, before the kid is returned; the active
// key is unchanged until Activate is called. On ErrKeyStoreDurability, the
// pending key is retained and its kid is returned alongside the error.
func (p *LocalKeyProvider) GenerateKey(alg JoseAlg) (string, error) {
	if !alg.Valid() {
		return "", NewArgumentError(fmt.Sprintf("dnsid: unsupported JOSE alg %q", alg), nil)
	}

	signer, err := generateSigner(alg)
	if err != nil {
		return "", err
	}

	entry, err := newLocalKeyEntry(signer, localKeyPending)
	if err != nil {
		return "", err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.keys == nil {
		p.keys = make(map[string]*localKeyEntry)
	}
	if _, exists := p.keys[entry.kid]; exists {
		return "", fmt.Errorf("dnsid: generated duplicate kid %q", entry.kid)
	}
	p.keys[entry.kid] = entry
	p.order = append(p.order, entry.kid)
	if err := p.persistLocked(); err != nil {
		if errors.Is(err, ErrKeyStoreDurability) {
			return entry.kid, err
		}
		delete(p.keys, entry.kid)
		p.order = p.order[:len(p.order)-1]
		return "", err
	}
	return entry.kid, nil
}

// Activate promotes the named pending or retained key to active and retains
// the previously active key. It returns an *ArgumentError for unknown kids.
// Even when kid is already active, the store is persisted again so callers can
// retry a durability failure. On failure before publication the previous state
// is restored; ErrKeyStoreDurability leaves the new state in memory and on disk.
func (p *LocalKeyProvider) Activate(kid string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := p.keys[kid]
	if entry == nil {
		return NewArgumentError(fmt.Sprintf("dnsid: unknown kid %q", kid), nil)
	}
	if p.activeKid == kid {
		return p.persistLocked()
	}
	oldActiveKid := p.activeKid
	oldState := entry.state
	current := p.keys[p.activeKid]
	if current != nil {
		current.state = localKeyRetained
	}
	entry.state = localKeyActive
	p.activeKid = kid
	if err := p.persistLocked(); err != nil {
		if errors.Is(err, ErrKeyStoreDurability) {
			return err
		}
		if current != nil {
			current.state = localKeyActive
		}
		entry.state = oldState
		p.activeKid = oldActiveKid
		return err
	}
	return nil
}

// Supersede removes a retained key after a completed rotation. It returns an
// *ArgumentError when kid does not name a retained key.
func (p *LocalKeyProvider) Supersede(kid string) error {
	p.mu.RLock()
	entry := p.keys[kid]
	p.mu.RUnlock()
	if entry == nil || entry.state != localKeyRetained {
		return NewArgumentError(fmt.Sprintf("dnsid: no retained key %q", kid), nil)
	}
	return p.Purge(kid)
}

// Purge removes a pending or retained key and persists the change. Purging
// the active key or an unknown kid returns an *ArgumentError. On
// ErrKeyStoreDurability the removal is not rolled back.
func (p *LocalKeyProvider) Purge(kid string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := p.keys[kid]
	if entry == nil {
		return NewArgumentError(fmt.Sprintf("dnsid: unknown kid %q", kid), nil)
	}
	if entry.state == localKeyActive {
		return NewArgumentError(fmt.Sprintf("dnsid: cannot purge active key %q", kid), nil)
	}
	oldOrder := append([]string(nil), p.order...)
	delete(p.keys, kid)
	for i, id := range p.order {
		if id == kid {
			p.order = append(p.order[:i], p.order[i+1:]...)
			break
		}
	}
	if err := p.persistLocked(); err != nil {
		if errors.Is(err, ErrKeyStoreDurability) {
			return err
		}
		p.keys[kid] = entry
		p.order = oldOrder
		return err
	}
	return nil
}

func (p *LocalKeyProvider) activeEntryLocked() *localKeyEntry {
	if p == nil || p.keys == nil || p.activeKid == "" {
		return nil
	}
	return p.keys[p.activeKid]
}

// Compile-time check that LocalKeyProvider implements KeyProvider.
var _ KeyProvider = (*LocalKeyProvider)(nil)
