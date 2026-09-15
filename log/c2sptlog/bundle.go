package c2sptlog

import (
	"bytes"
	"context"
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
	// StreamBundleVersion is the bundle format version this package
	// produces and accepts.
	StreamBundleVersion = 1
	// StreamBundleTrustedIndex is the only supported completeness mode: the
	// producer asserts the bundle is complete through the checkpoint size.
	StreamBundleTrustedIndex          = "trusted-index"
	defaultMaxStreamBundleBytes       = 8 << 20
	defaultMaxStreamBundleEvents      = 10000
	defaultMaxStreamBundleEventBytes  = 65535
	defaultMaxStreamBundleProofHashes = 64
)

// StreamBundleTrust contains verifier-controlled inputs. PolicyDocument is
// hashed byte-for-byte and parsed as tlog-policy; it is never taken from the
// bundle. BundleVerifier is retained for single-key callers; BundleVerifiers
// allows independently configured keys to overlap during signer rotation.
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
}

// fetchedStreamBundleSource retrieves the current domain bundle from the
// authenticated lr log prefix. Its fallback is the complete raw scanner.
type fetchedStreamBundleSource struct {
	fetcher       BoundedResourceFetcher
	fallback      Source
	trust         StreamBundleTrust
	requireBundle bool
}

func (s *fetchedStreamBundleSource) ReadEvent(ctx context.Context, ref dnsidlog.LogRef) (ProvenEntry, error) {
	if s == nil || s.fallback == nil {
		return ProvenEntry{}, fmt.Errorf("dnsid: reading one c2sp-tlog event requires the raw discovery source")
	}
	discovered, err := s.fallback.ReadEvent(ctx, ref)
	if err != nil {
		return ProvenEntry{}, err
	}
	event, err := LogEventFromEntry(discovered.Entry)
	if err != nil {
		return ProvenEntry{}, err
	}
	reference, _, err := ParseFinalEventRef(ref)
	if err != nil {
		return ProvenEntry{}, err
	}
	bundle, fallback, err := s.load(ctx, reference, event.Domain)
	if err != nil {
		return ProvenEntry{}, err
	}
	if fallback {
		return discovered, nil
	}
	return bundle.Source.ReadEvent(ctx, ref)
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

// FetchEntriesThrough supplies the narrowly permitted raw-scan fallback for
// advancing a checkpoint accepted from an otherwise valid stream bundle.
func (s *fetchedStreamBundleSource) FetchEntriesThrough(ctx context.Context, reference Reference, treeSize uint64) ([][]byte, error) {
	if s == nil || s.requireBundle {
		return nil, fmt.Errorf("dnsid: c2sp-tlog stream bundle consistency evidence is required")
	}
	fallback, ok := s.fallback.(C2spFullLogSource)
	if !ok {
		return nil, fmt.Errorf("dnsid: c2sp-tlog complete raw scanner is required for checkpoint consistency")
	}
	return fallback.FetchEntriesThrough(ctx, reference, treeSize)
}

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
	endpoint := reference.LogPrefix + "/streams/" + url.PathEscape(normalized) + "?format=bundle"
	data, err := fetchBounded(s.fetcher, ctx, endpoint, int64(maximum))
	if err != nil {
		if !s.requireBundle && s.fallback != nil && streamBundleFallbackAllowed(err) {
			return nil, true, nil
		}
		return nil, false, err
	}
	trust := s.trust
	// The outer Client owns checkpoint advancement so it can use the raw
	// scanner only when an otherwise valid bundle lacks consistency evidence.
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

// VerifyStreamBundle verifies an offline stream bundle without network
// access. It checks, in order: size and canonical JCS form, the accepted
// bundle signer's Ed25519 signature, format version and type, expiry against
// local time and MaxBundleLifetime, that the bundle's policy hash matches the
// verifier-supplied PolicyDocument, and then replays every bundled entry
// through full Client verification (inclusion proofs against the embedded
// checkpoint, lifecycle signatures, and stream chain). The bundle's own
// state summary must match the replayed result. Nothing in data is trusted
// until all checks pass.
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
	if trust.BundleVerifier == nil && len(trust.BundleVerifiers) == 0 {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle verifier is required")
	}
	object, err := decodeJSONObject(data)
	if err != nil {
		return nil, fmt.Errorf("dnsid: parsing c2sp stream bundle: %w", err)
	}
	if err := requireExactFields(object, "checkpoint", "complete_through_size", "completeness_mode", "events", "expires", "fqdn", "lr", "policy_hash", "sig", "state", "type", "v"); err != nil {
		return nil, err
	}
	canonical, err := canonicalJSON(object)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle is not canonical JCS")
	}

	sigObject, err := bundleObject(object, "sig")
	if err != nil {
		return nil, err
	}
	if err := requireExactFields(sigObject, "alg", "kid", "value"); err != nil {
		return nil, err
	}
	alg, err := bundleString(sigObject, "alg")
	if err != nil || alg != "EdDSA" {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle signature algorithm must be EdDSA")
	}
	kid, err := bundleString(sigObject, "kid")
	if err != nil {
		return nil, err
	}
	verifier := acceptedBundleVerifier(trust, kid)
	if verifier == nil {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle signer is not accepted")
	}
	signatureText, err := bundleString(sigObject, "value")
	if err != nil {
		return nil, err
	}
	signature, err := decodeBundleBase64("sig.value", signatureText, 64, 64)
	if err != nil {
		return nil, err
	}
	delete(object, "sig")
	unsigned, err := canonicalJSON(object)
	if err != nil {
		return nil, err
	}
	object["sig"] = sigObject
	if !verifier.Verify(unsigned, signature) {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle signature verification failed")
	}

	version, err := bundleUint(object, "v")
	if err != nil || version != StreamBundleVersion {
		return nil, fmt.Errorf("dnsid: unsupported c2sp stream bundle version")
	}
	typeName, err := bundleString(object, "type")
	if err != nil || typeName != StreamBundleType {
		return nil, fmt.Errorf("dnsid: unsupported c2sp stream bundle type")
	}
	mode, err := bundleString(object, "completeness_mode")
	if err != nil || mode != StreamBundleTrustedIndex {
		return nil, fmt.Errorf("dnsid: unsupported c2sp stream bundle completeness mode")
	}
	fqdn, err := bundleString(object, "fqdn")
	if err != nil {
		return nil, err
	}
	referenceText, err := bundleString(object, "lr")
	if err != nil {
		return nil, err
	}
	reference, err := ParseReference(referenceText)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if trust.Now != nil {
		now = trust.Now()
	}
	expiresUnix, err := bundleUint(object, "expires")
	if err != nil {
		return nil, err
	}
	expires := time.Unix(int64(expiresUnix), 0).UTC()
	if !expires.After(now) {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle expired")
	}
	if trust.MaxBundleLifetime <= 0 {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle maximum lifetime is required")
	}

	policyHashText, err := bundleString(object, "policy_hash")
	if err != nil {
		return nil, err
	}
	policyHash, err := decodeBundleBase64("policy_hash", policyHashText, sha256.Size, sha256.Size)
	if err != nil {
		return nil, err
	}
	wantPolicyHash := sha256.Sum256(trust.PolicyDocument)
	if !bytes.Equal(policyHash, wantPolicyHash[:]) {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle policy hash mismatch")
	}
	policy, err := ParsePolicy(trust.PolicyDocument)
	if err != nil {
		return nil, err
	}
	policy.Now = trust.Now
	policy.MaxCheckpointAge = trust.MaxCheckpointAge
	policy.ClockSkew = trust.ClockSkew

	checkpointText, err := bundleString(object, "checkpoint")
	if err != nil {
		return nil, err
	}
	checkpoint, err := decodeBundleBase64("checkpoint", checkpointText, 1, maxBytes)
	if err != nil {
		return nil, err
	}
	completeThrough, err := bundleUint(object, "complete_through_size")
	if err != nil {
		return nil, err
	}
	maxTreeSize := trust.MaxTreeSize
	if maxTreeSize == 0 {
		maxTreeSize = defaultScanMaxTreeSize
	}
	if completeThrough > maxTreeSize {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle checkpoint exceeds configured tree-size maximum")
	}
	entries, err := parseBundleEntries(object["events"], checkpoint, trust.MaxEvents)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle requires events")
	}
	source := &StreamBundleSource{reference: reference, domain: fqdn, entries: entries}
	clientOptions := []Option{WithSource(source), WithPolicy(policy), WithMigrationVerificationLimits(trust.MigrationLimits)}
	if trust.MigrationVerifier != nil {
		clientOptions = append(clientOptions, WithMigrationVerifier(trust.MigrationVerifier))
	}
	client, err := New(referenceText, clientOptions...)
	if err != nil {
		return nil, err
	}
	events, err := client.RebuildHistory(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	proof, err := policy.VerifyProof(reference, entries[0].Entry, entries[0].Proof)
	if err != nil {
		return nil, err
	}
	if expires.After(proof.CheckpointFreshnessTime.Add(trust.MaxBundleLifetime)) {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle lifetime exceeds checkpoint-relative policy")
	}
	if completeThrough != proof.Checkpoint.Size {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle complete_through_size does not match checkpoint")
	}
	source.checkpoint = append([]byte(nil), checkpoint...)
	source.completeThrough = completeThrough
	source.completenessMode = mode
	source.checkpointFreshness = proof.CheckpointFreshnessTime
	snapshot, err := dnsidlog.NewDomainLog(fqdn, events).SnapshotAt(now)
	if err != nil {
		return nil, err
	}
	if err := verifyBundleState(object["state"], snapshot, events); err != nil {
		return nil, err
	}
	if trust.TrustedCheckpointStore != nil {
		client.checkpointStore = trust.TrustedCheckpointStore
		if err := client.advanceTrustedCheckpoint(ctx, TrustedC2spCheckpoint{
			Origin:      proof.Checkpoint.Origin,
			TreeSize:    proof.Checkpoint.Size,
			RootHash:    append([]byte(nil), proof.Checkpoint.Hash...),
			WitnessTime: proof.CheckpointWitnessTime,
		}); err != nil {
			return nil, err
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
	return &VerifiedStreamBundle{
		Reference:           reference,
		FQDN:                fqdn,
		Events:              events,
		Snapshot:            snapshot,
		LoggedState:         snapshot.HistoricalState.String(),
		Expires:             expires,
		CompleteThroughSize: completeThrough,
		SignerKeyID:         kid,
		Source:              source,
	}, nil
}

func acceptedBundleVerifier(trust StreamBundleTrust, kid string) note.Verifier {
	verifiers := trust.BundleVerifiers
	if trust.BundleVerifier != nil {
		verifiers = append([]note.Verifier{trust.BundleVerifier}, verifiers...)
	}
	var accepted note.Verifier
	for _, verifier := range verifiers {
		if verifier != nil && kid == fmt.Sprintf("%s+%08x", verifier.Name(), verifier.KeyHash()) {
			if accepted != nil {
				return nil
			}
			accepted = verifier
		}
	}
	return accepted
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
	entries := make([]ProvenEntry, 0, len(items))
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
		rawProof := formatproof.TLogProof{Index: index, Hashes: hashes, Checkpoint: checkpoint}.Marshal()
		entries = append(entries, ProvenEntry{Index: index, Entry: entry, Proof: rawProof})
	}
	return entries, nil
}

func verifyBundleState(value any, snapshot *dnsidlog.DomainSnapshot, events []dnsidlog.LogEvent) error {
	state, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("dnsid: c2sp stream bundle state must be an object")
	}
	if err := requireExactFields(state, "event_count", "last_event_type", "logged_state"); err != nil {
		return err
	}
	count, err := bundleUint(state, "event_count")
	if err != nil {
		return err
	}
	lastType, err := bundleString(state, "last_event_type")
	if err != nil {
		return err
	}
	loggedState, err := bundleString(state, "logged_state")
	if err != nil {
		return err
	}
	if count != uint64(len(events)) || len(events) == 0 || lastType != string(events[len(events)-1].Type) || loggedState != snapshot.HistoricalState.String() {
		return fmt.Errorf("dnsid: c2sp stream bundle state does not match replay")
	}
	return nil
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

func bundleObject(object map[string]any, field string) (map[string]any, error) {
	value, ok := object[field].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle field %q must be an object", field)
	}
	return value, nil
}

func bundleUint(object map[string]any, field string) (uint64, error) {
	number, ok := object[field].(json.Number)
	if !ok {
		return 0, fmt.Errorf("dnsid: c2sp stream bundle field %q must be an integer", field)
	}
	value, err := number.Int64()
	if err != nil || value < 0 {
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
