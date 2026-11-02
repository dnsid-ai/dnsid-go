package c2sptlog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	formatproof "github.com/transparency-dev/formats/proof"
	"golang.org/x/mod/sumdb/note"
)

const (
	// StreamBundleType is the required "type" value of a stream bundle.
	StreamBundleType = "dnsid-c2sp-stream-bundle"
	// StreamBundleVersion is the bundle format version this package accepts.
	StreamBundleVersion = 2
	// StreamBundleTrustedIndex is the completeness mode of a verified bundle:
	// the stream-head signer asserts completeness through the checkpoint size.
	StreamBundleTrustedIndex          = "trusted-index"
	defaultMaxStreamBundleBytes       = 8 << 20
	defaultMaxStreamBundleEvents      = 10000
	defaultMaxStreamBundleEventBytes  = 65535
	defaultMaxStreamBundleProofHashes = 64
)

// StreamBundleTrust contains verifier-controlled inputs. PolicyDocument is
// parsed as tlog-policy; it is never taken from the bundle. BundleVerifier and
// BundleVerifiers are the accepted stream-head statement keys; several keys
// may overlap during signer rotation. Their names must differ from every log
// and witness name in the policy.
type StreamBundleTrust struct {
	PolicyDocument         []byte
	BundleVerifier         note.Verifier
	BundleVerifiers        []note.Verifier
	Now                    func() time.Time
	MaxBundleLifetime      time.Duration
	MaxCheckpointAge       time.Duration
	ClockSkew              time.Duration
	MaxBundleBytes         int
	MaxEvents              int
	MaxTreeSize            uint64
	TrustedCheckpointStore TrustedC2spCheckpointStore
	MigrationVerifier      MigrationVerifier
	MigrationLimits        MigrationVerificationLimits
}

// VerifiedStreamBundle is the result of VerifyStreamBundle: the verified
// lifecycle events and materialized snapshot for one stream, its logged state,
// the bundle's expiry and completeness bound, the accepted signer, and a Source
// over the bundle's proven entries for further Client operations. LoggedState
// is historical log state, not current protocol status.
type VerifiedStreamBundle struct {
	Reference           Reference
	FQDN                string
	Events              []dnsidlog.LogEvent
	Snapshot            *dnsidlog.DomainSnapshot
	LoggedState         string
	Expires             time.Time
	CompleteThroughSize uint64
	SignerKeyID         string
	Source              *StreamBundleSource
}

// StreamBundleSource adapts verified bundle evidence to Source and
// CompleteSource without trusting the producer's event parsing.
type StreamBundleSource struct {
	reference           Reference
	domain              string
	entries             []ProvenEntry
	checkpoint          []byte
	completeThrough     uint64
	completenessMode    string
	checkpointFreshness time.Time
	expires             time.Time
	now                 func() time.Time
}

// fetchedStreamBundleSource retrieves the current domain bundle from the
// authenticated lr log prefix. Its fallback is the complete raw scanner.
type fetchedStreamBundleSource struct {
	fetcher       BoundedResourceFetcher
	fallback      Source
	trust         StreamBundleTrust
	requireBundle bool
}

// entryDiscoverySource reads one raw entry without a complete log scan.
type entryDiscoverySource interface {
	discoverEntry(context.Context, Reference, uint64) ([]byte, error)
}

func (s *fetchedStreamBundleSource) ReadEvent(ctx context.Context, ref dnsidlog.LogRef) (ProvenEntry, error) {
	if s == nil || s.fallback == nil {
		return ProvenEntry{}, fmt.Errorf("dnsid: reading one c2sp-tlog event requires the raw discovery source")
	}
	reference, index, err := ParseFinalEventRef(ref)
	if err != nil {
		return ProvenEntry{}, err
	}
	// The raw entry only names the domain bundle; the bundle proves the entry.
	var discovered *ProvenEntry
	var raw []byte
	if source, ok := s.fallback.(entryDiscoverySource); ok {
		raw, err = source.discoverEntry(ctx, reference, index)
	} else {
		var entry ProvenEntry
		entry, err = s.fallback.ReadEvent(ctx, ref)
		discovered, raw = &entry, entry.Entry
	}
	if err != nil {
		return ProvenEntry{}, err
	}
	event, err := LogEventFromEntry(raw)
	if err != nil {
		return ProvenEntry{}, err
	}
	bundle, fallback, err := s.load(ctx, reference, event.Domain)
	if err != nil {
		return ProvenEntry{}, err
	}
	if fallback {
		if discovered != nil {
			return *discovered, nil
		}
		return s.fallback.ReadEvent(ctx, ref)
	}
	proven, err := bundle.Source.ReadEvent(ctx, ref)
	if err != nil {
		return ProvenEntry{}, err
	}
	if !bytes.Equal(proven.Entry, raw) {
		return ProvenEntry{}, fmt.Errorf("dnsid: c2sp stream bundle entry does not match the log entry at index %d", index)
	}
	return proven, nil
}

func (s *fetchedStreamBundleSource) RebuildHistory(ctx context.Context, reference Reference, domain string) ([]ProvenEntry, error) {
	bundle, fallback, err := s.load(ctx, reference, domain)
	if err != nil {
		return nil, err
	}
	if fallback {
		return s.fallback.RebuildHistory(ctx, reference, domain)
	}
	return bundle.Source.RebuildHistory(ctx, reference, domain)
}

func (s *fetchedStreamBundleSource) RebuildCompleteHistory(ctx context.Context, reference Reference, domain string) (CompleteHistoryResult, error) {
	bundle, fallback, err := s.load(ctx, reference, domain)
	if err != nil {
		return CompleteHistoryResult{}, err
	}
	if fallback {
		complete, ok := s.fallback.(CompleteSource)
		if !ok {
			return CompleteHistoryResult{}, fmt.Errorf("dnsid: c2sp-tlog complete fallback source is required")
		}
		return complete.RebuildCompleteHistory(ctx, reference, domain)
	}
	return bundle.Source.RebuildCompleteHistory(ctx, reference, domain)
}

// GlobalCandidates is safe for both paths: raw scans need candidate filtering,
// while bundle entries have already passed strict verification in load.
func (*fetchedStreamBundleSource) GlobalCandidates() bool { return true }

func (s *fetchedStreamBundleSource) load(ctx context.Context, reference Reference, domain string) (*VerifiedStreamBundle, bool, error) {
	if s == nil || s.fetcher == nil {
		return nil, false, fmt.Errorf("dnsid: c2sp stream bundle fetcher is required")
	}
	normalized, err := dnsid.NormalizeFQDN(domain)
	if err != nil {
		return nil, false, err
	}
	maximum := s.trust.MaxBundleBytes
	if maximum == 0 {
		maximum = defaultMaxStreamBundleBytes
	}
	endpoint := reference.LogPrefix + "/streams/" + url.PathEscape(normalized) + "?format=bundle-v2"
	data, err := fetchBounded(s.fetcher, ctx, endpoint, int64(maximum))
	if err != nil {
		if !s.requireBundle && s.fallback != nil && streamBundleFallbackAllowed(err) {
			return nil, true, nil
		}
		return nil, false, err
	}
	trust := s.trust
	// The outer Client owns continuity checks and atomic checkpoint advancement.
	trust.TrustedCheckpointStore = nil
	verified, err := VerifyStreamBundle(ctx, data, trust)
	if err != nil {
		return nil, false, err
	}
	bundleFQDN, err := dnsid.NormalizeFQDN(verified.FQDN)
	if err != nil || verified.FQDN != bundleFQDN || bundleFQDN != normalized {
		return nil, false, fmt.Errorf("dnsid: c2sp stream bundle fqdn does not match request")
	}
	if verified.Reference.String() != reference.String() {
		return nil, false, fmt.Errorf("dnsid: c2sp stream bundle lr does not match authenticated record")
	}
	return verified, false, nil
}

func streamBundleFallbackAllowed(err error) bool {
	var fetchErr *ResourceFetchError
	if errors.As(err, &fetchErr) {
		switch fetchErr.Kind {
		case ResourceFetchUnavailable:
			return fetchErr.Transient()
		case ResourceFetchHTTPStatus:
			return fetchErr.HTTPStatus == http.StatusNotFound || fetchErr.HTTPStatus == http.StatusRequestTimeout ||
				fetchErr.HTTPStatus == http.StatusTooManyRequests ||
				fetchErr.HTTPStatus >= http.StatusInternalServerError && fetchErr.HTTPStatus <= 599
		default:
			return false
		}
	}
	var transient interface{ Transient() bool }
	return errors.As(err, &transient) && transient.Transient()
}

// ReadEvent implements Source over the bundle's entries. It returns an error
// if ref does not address this bundle's reference or names an index the
// bundle does not contain.
func (s *StreamBundleSource) ReadEvent(_ context.Context, ref dnsidlog.LogRef) (ProvenEntry, error) {
	wantRef, index, err := ParseFinalEventRef(ref)
	if err != nil {
		return ProvenEntry{}, err
	}
	if s == nil || wantRef.String() != s.reference.String() {
		return ProvenEntry{}, fmt.Errorf("dnsid: stream bundle reference mismatch")
	}
	for _, entry := range s.entries {
		if entry.Index == index {
			return cloneProvenEntry(entry), nil
		}
	}
	return ProvenEntry{}, fmt.Errorf("dnsid: stream bundle does not contain index %d", index)
}

// RebuildHistory implements Source over the bundle's entries. It returns
// copies of every bundled entry, or an error if reference or domain does not
// match the bundle.
func (s *StreamBundleSource) RebuildHistory(_ context.Context, reference Reference, domain string) ([]ProvenEntry, error) {
	if s == nil || reference.String() != s.reference.String() || !strings.EqualFold(domain, s.domain) {
		return nil, fmt.Errorf("dnsid: stream bundle reference or fqdn mismatch")
	}
	entries := make([]ProvenEntry, len(s.entries))
	for i, entry := range s.entries {
		entries[i] = cloneProvenEntry(entry)
	}
	return entries, nil
}

// RebuildCompleteHistory implements CompleteSource: a verified bundle's
// trusted-index completeness assertion and entries share one checkpoint.
func (s *StreamBundleSource) RebuildCompleteHistory(_ context.Context, reference Reference, domain string) (CompleteHistoryResult, error) {
	if s == nil || reference.String() != s.reference.String() || !strings.EqualFold(domain, s.domain) {
		return CompleteHistoryResult{}, fmt.Errorf("dnsid: stream bundle reference or fqdn mismatch")
	}
	entries := make([]ProvenEntry, len(s.entries))
	for i, entry := range s.entries {
		entries[i] = cloneProvenEntry(entry)
	}
	return CompleteHistoryResult{
		Entries:          entries,
		Checkpoint:       append([]byte(nil), s.checkpoint...),
		CompleteThrough:  s.completeThrough,
		CompletenessMode: s.completenessMode,
		FreshnessTime:    s.checkpointFreshness,
	}, nil
}

// VerifyStreamBundle verifies an offline dnsid-c2sp-stream-bundle@v2 without
// network access (method §12.1.3). It checks the exact member set, opens the
// signed stream-head statement with the accepted verifiers, verifies the
// checkpoint under PolicyDocument and requires it to match the statement,
// replays every bundled entry through full Client verification (inclusion
// proofs, lifecycle signatures, and stream chain), and requires the last
// applied event ID to equal the statement head. Expiry is checked against
// local time and MaxBundleLifetime. Nothing in data is trusted until all
// checks pass. The bundle JSON need not be canonical.
func VerifyStreamBundle(ctx context.Context, data []byte, trust StreamBundleTrust) (*VerifiedStreamBundle, error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	maxBytes := trust.MaxBundleBytes
	if maxBytes == 0 {
		maxBytes = defaultMaxStreamBundleBytes
	}
	if maxBytes < 1 || len(data) > maxBytes {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle exceeds size limit")
	}
	verifiers := trust.BundleVerifiers
	if trust.BundleVerifier != nil {
		verifiers = append([]note.Verifier{trust.BundleVerifier}, verifiers...)
	}
	if len(verifiers) == 0 {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle verifier is required")
	}
	object, err := decodeJSONObject(data)
	if err != nil {
		return nil, fmt.Errorf("dnsid: parsing c2sp stream bundle: %w", err)
	}
	if err := requireExactFields(object, "checkpoint", "events", "head", "type", "v"); err != nil {
		return nil, err
	}
	version, err := bundleUint(object, "v")
	if err != nil || version != StreamBundleVersion {
		return nil, fmt.Errorf("dnsid: unsupported c2sp stream bundle version")
	}
	typeName, err := bundleString(object, "type")
	if err != nil || typeName != StreamBundleType {
		return nil, fmt.Errorf("dnsid: unsupported c2sp stream bundle type")
	}
	policy, err := ParsePolicy(trust.PolicyDocument)
	if err != nil {
		return nil, err
	}
	if err := requireIndependentStreamHeadKeys(policy, verifiers); err != nil {
		return nil, err
	}
	policy.Now = trust.Now
	policy.MaxCheckpointAge = trust.MaxCheckpointAge
	policy.ClockSkew = trust.ClockSkew

	headText, err := bundleString(object, "head")
	if err != nil {
		return nil, err
	}
	headNote, err := decodeBundleBase64("head", headText, 1, maxBytes)
	if err != nil {
		return nil, err
	}
	head, signerKeyID, err := OpenStreamHead(headNote, verifiers)
	if err != nil {
		return nil, err
	}
	reference, err := ParseReference(head.LR)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if trust.Now != nil {
		now = trust.Now()
	}
	expires := head.Expires
	if !expires.After(now) {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle expired")
	}
	if trust.MaxBundleLifetime <= 0 {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle maximum lifetime is required")
	}

	checkpointText, err := bundleString(object, "checkpoint")
	if err != nil {
		return nil, err
	}
	checkpoint, err := decodeBundleBase64("checkpoint", checkpointText, 1, maxBytes)
	if err != nil {
		return nil, err
	}
	maxTreeSize := trust.MaxTreeSize
	if maxTreeSize == 0 {
		maxTreeSize = defaultScanMaxTreeSize
	}
	if head.TreeSize > maxTreeSize {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle checkpoint exceeds configured tree-size maximum")
	}
	accepted, err := policy.verifyCheckpoint(reference, checkpoint)
	if err != nil {
		return nil, err
	}
	if accepted.Checkpoint.Size != head.TreeSize || !bytes.Equal(accepted.Checkpoint.Hash, head.RootHash) {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle checkpoint does not match stream-head statement")
	}
	if expires.After(accepted.CheckpointFreshnessTime.Add(trust.MaxBundleLifetime)) {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle lifetime exceeds checkpoint-relative policy")
	}
	entries, err := parseBundleEntries(object["events"], checkpoint, trust.MaxEvents)
	if err != nil {
		return nil, err
	}
	fqdn, err := streamHeadDomain(entries, head.HeadEventID)
	if err != nil {
		return nil, err
	}
	source := &StreamBundleSource{reference: reference, domain: fqdn, entries: entries}
	clientOptions := []Option{WithSource(source), WithPolicy(policy), WithMigrationVerificationLimits(trust.MigrationLimits)}
	if trust.MigrationVerifier != nil {
		clientOptions = append(clientOptions, WithMigrationVerifier(trust.MigrationVerifier))
	}
	client, err := New(head.LR, clientOptions...)
	if err != nil {
		return nil, err
	}
	applied, events, err := client.rebuildVerifiedHistory(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	if len(applied) == 0 || EventID(applied[len(applied)-1].signed) != head.HeadEventID {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle replay does not end at the stream-head statement head")
	}
	source.checkpoint = append([]byte(nil), checkpoint...)
	source.completeThrough = accepted.Checkpoint.Size
	source.completenessMode = StreamBundleTrustedIndex
	source.checkpointFreshness = accepted.CheckpointFreshnessTime
	snapshot, err := dnsidlog.NewDomainLog(fqdn, events).SnapshotAt(now)
	if err != nil {
		return nil, err
	}
	if trust.TrustedCheckpointStore != nil {
		client.checkpointStore = trust.TrustedCheckpointStore
		if err := client.advanceTrustedCheckpoint(ctx, TrustedC2spCheckpoint{
			Origin:      accepted.Checkpoint.Origin,
			TreeSize:    accepted.Checkpoint.Size,
			RootHash:    append([]byte(nil), accepted.Checkpoint.Hash...),
			WitnessTime: accepted.CheckpointWitnessTime,
		}); err != nil {
			return nil, logVerificationError(err, false)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	checkTime := time.Now()
	if trust.Now != nil {
		checkTime = trust.Now()
	}
	if !checkTime.Before(expires) {
		return nil, fmt.Errorf("dnsid: stream bundle expired during verification")
	}
	source.expires, source.now = expires, trust.Now
	return &VerifiedStreamBundle{
		Reference:           reference,
		FQDN:                fqdn,
		Events:              events,
		Snapshot:            snapshot,
		LoggedState:         snapshot.HistoricalState.String(),
		Expires:             expires,
		CompleteThroughSize: accepted.Checkpoint.Size,
		SignerKeyID:         signerKeyID,
		Source:              source,
	}, nil
}

// streamHeadDomain returns the FQDN of the bundled entry whose logical event
// ID is the statement head. Replay then authenticates that entry.
func streamHeadDomain(entries []ProvenEntry, headID string) (string, error) {
	for _, entry := range entries {
		signed, err := CanonicalFromEntry(entry.Entry)
		if err != nil || EventID(signed) != headID {
			continue
		}
		if event, err := LogEventFromEntry(entry.Entry); err == nil {
			return event.Domain, nil
		}
	}
	return "", fmt.Errorf("dnsid: c2sp stream bundle does not contain the stream-head event")
}

// requireIndependentStreamHeadKeys rejects stream-head keys that reuse a
// policy log or witness name or public key (method §12.1.1).
func requireIndependentStreamHeadKeys(policy Policy, verifiers []note.Verifier) error {
	names := map[string]bool{}
	if policy.LogVerifier != nil {
		names[policy.LogVerifier.Name()] = true
	}
	for _, witness := range policy.WitnessVerifiers {
		names[witness.Name()] = true
	}
	for _, verifier := range verifiers {
		if verifier == nil {
			return fmt.Errorf("dnsid: c2sp stream bundle verifier must not be nil")
		}
		if names[verifier.Name()] {
			return fmt.Errorf("dnsid: c2sp stream-head key name must differ from every policy log and witness name")
		}
		for _, publicKey := range policy.trustedPublicKeys {
			// Recompute the Ed25519 key ID under the stream-head name to detect renamed keys.
			key, err := note.NewEd25519VerifierKey(verifier.Name(), ed25519.PublicKey(publicKey))
			if err != nil {
				return err
			}
			checkpointVerifier, err := note.NewVerifier(key)
			if err != nil {
				return err
			}
			if verifier.KeyHash() == checkpointVerifier.KeyHash() {
				return fmt.Errorf("dnsid: c2sp stream-head signer must be independent of checkpoint policy keys")
			}
		}
	}
	return nil
}

func parseBundleEntries(value any, checkpoint []byte, configuredMax int) ([]ProvenEntry, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle events must be an array")
	}
	maxEvents := configuredMax
	if maxEvents == 0 {
		maxEvents = defaultMaxStreamBundleEvents
	}
	if maxEvents < 1 || len(items) > maxEvents {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle event count exceeds limit")
	}
	// Each portable proof copies the checkpoint; bound that expansion before allocating it.
	if len(items) > 0 && int64(len(checkpoint)) > defaultScanMaxTotalEntryBytes/int64(len(items)) {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle reconstructed history exceeds byte limit")
	}
	entries := make([]ProvenEntry, 0, len(items))
	var total int64
	var previous uint64
	for i, value := range items {
		item, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("dnsid: c2sp stream bundle event must be an object")
		}
		if err := requireExactFields(item, "entry", "index", "proof"); err != nil {
			return nil, err
		}
		index, err := bundleUint(item, "index")
		if err != nil {
			return nil, err
		}
		if i > 0 && index <= previous {
			return nil, fmt.Errorf("dnsid: c2sp stream bundle indexes must be strictly increasing")
		}
		previous = index
		entryText, err := bundleString(item, "entry")
		if err != nil {
			return nil, err
		}
		entry, err := decodeBundleBase64("events.entry", entryText, 1, defaultMaxStreamBundleEventBytes)
		if err != nil {
			return nil, err
		}
		proofText, err := bundleString(item, "proof")
		if err != nil {
			return nil, err
		}
		proofBytes, err := decodeBundleBase64("events.proof", proofText, 0, defaultMaxStreamBundleProofHashes*sha256.Size)
		if err != nil {
			return nil, err
		}
		if len(proofBytes)%sha256.Size != 0 {
			return nil, fmt.Errorf("dnsid: c2sp stream bundle proof length must be a multiple of 32")
		}
		hashes := make([][sha256.Size]byte, len(proofBytes)/sha256.Size)
		for i := range hashes {
			copy(hashes[i][:], proofBytes[i*sha256.Size:(i+1)*sha256.Size])
		}
		rawProof := formatproof.TLogProof{Index: index, Hashes: hashes}.Marshal()
		total += int64(len(entry)) + int64(len(rawProof)) + int64(len(checkpoint))
		if total > defaultScanMaxTotalEntryBytes {
			return nil, fmt.Errorf("dnsid: c2sp stream bundle reconstructed history exceeds byte limit")
		}
		rawProof = append(rawProof, checkpoint...)
		entries = append(entries, ProvenEntry{Index: index, Entry: entry, Proof: rawProof})
	}
	return entries, nil
}

func requireExactFields(object map[string]any, fields ...string) error {
	if len(object) != len(fields) {
		return fmt.Errorf("dnsid: c2sp stream bundle contains unknown or missing fields")
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return fmt.Errorf("dnsid: c2sp stream bundle missing field %q", field)
		}
	}
	return nil
}

func bundleString(object map[string]any, field string) (string, error) {
	value, ok := object[field].(string)
	if !ok {
		return "", fmt.Errorf("dnsid: c2sp stream bundle field %q must be a string", field)
	}
	return value, nil
}

func bundleUint(object map[string]any, field string) (uint64, error) {
	number, ok := object[field].(json.Number)
	if !ok {
		return 0, fmt.Errorf("dnsid: c2sp stream bundle field %q must be an integer", field)
	}
	value, err := number.Int64()
	if err != nil || value < 0 || value > maxJSONInteger {
		return 0, fmt.Errorf("dnsid: c2sp stream bundle field %q must be a non-negative integer", field)
	}
	return uint64(value), nil
}

func decodeBundleBase64(field, value string, minBytes, maxBytes int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle %s must use canonical unpadded base64url", field)
	}
	if len(decoded) < minBytes || len(decoded) > maxBytes {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle %s length is outside bounds", field)
	}
	return decoded, nil
}

func cloneProvenEntry(entry ProvenEntry) ProvenEntry {
	entry.Entry = append([]byte(nil), entry.Entry...)
	entry.Proof = append([]byte(nil), entry.Proof...)
	return entry
}
