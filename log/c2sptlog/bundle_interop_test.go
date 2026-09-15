package c2sptlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"golang.org/x/mod/sumdb/note"
)

type streamBundleVector struct {
	Bundle   string `json:"bundle"`
	Policy   string `json:"policy"`
	Expected struct {
		ActiveOperationalThumbprint string `json:"active_operational_thumbprint"`
		BundleSignerKID             string `json:"bundle_signer_kid"`
		EventCount                  int    `json:"event_count"`
		Status                      string `json:"status"`
	} `json:"expected"`
	Trust struct {
		BundleVerifierKey   string `json:"bundle_verifier_key"`
		CheckpointFreshness int64  `json:"checkpoint_freshness_ms"`
		MaxBundleLifetime   int64  `json:"max_bundle_lifetime_ms"`
		Now                 int64  `json:"now"`
	} `json:"trust"`
	NegativeMutations []struct {
		Name   string          `json:"name"`
		Path   string          `json:"path"`
		Append string          `json:"append"`
		Value  json.RawMessage `json:"value"`
	} `json:"negative_mutations"`
}

func TestVerifyStreamBundleCorrectedVector(t *testing.T) {
	path := filepath.Join("testdata", "c2sp-stream-bundle-logical-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vector streamBundleVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	verifier, err := note.NewVerifier(vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyStreamBundle(context.Background(), []byte(vector.Bundle), StreamBundleTrust{
		PolicyDocument:    []byte(vector.Policy),
		BundleVerifier:    verifier,
		Now:               func() time.Time { return time.Unix(vector.Trust.Now, 0).UTC() },
		MaxBundleLifetime: time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
		MaxCheckpointAge:  time.Duration(vector.Trust.CheckpointFreshness) * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("VerifyStreamBundle(%s): %v", path, err)
	}
	if got, want := len(verified.Events), vector.Expected.EventCount; got != want {
		t.Fatalf("event count = %d, want %d", got, want)
	}
	if got, want := verified.Snapshot.HistoricalState.String(), vector.Expected.Status; got != want {
		t.Fatalf("status = %q, want %q", got, want)
	}
	if got, want := verified.LoggedState, vector.Expected.Status; got != want {
		t.Fatalf("logged state = %q, want %q", got, want)
	}
	if got, want := verified.Snapshot.ActiveKeyThumbprint, vector.Expected.ActiveOperationalThumbprint; got != want {
		t.Fatalf("active thumbprint = %q, want %q", got, want)
	}
	if got, want := verified.SignerKeyID, vector.Expected.BundleSignerKID; got != want {
		t.Fatalf("signer kid = %q, want %q", got, want)
	}
}

func TestVerifyStreamBundleEnforcesTreeSizeLimit(t *testing.T) {
	vector := loadStreamBundleVector(t)
	verifier, err := note.NewVerifier(vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyStreamBundle(context.Background(), []byte(vector.Bundle), StreamBundleTrust{
		PolicyDocument:    []byte(vector.Policy),
		BundleVerifier:    verifier,
		Now:               func() time.Time { return time.Unix(vector.Trust.Now, 0).UTC() },
		MaxBundleLifetime: time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
		MaxCheckpointAge:  time.Duration(vector.Trust.CheckpointFreshness) * time.Millisecond,
		MaxTreeSize:       1,
	})
	if err == nil || !strings.Contains(err.Error(), "tree-size maximum") {
		t.Fatalf("VerifyStreamBundle tree-size error = %v", err)
	}
}

type acceptingBundleVerifier struct{}

func (acceptingBundleVerifier) Name() string                   { return "bundle.test" }
func (acceptingBundleVerifier) KeyHash() uint32                { return 1 }
func (acceptingBundleVerifier) Verify(_ []byte, _ []byte) bool { return true }

func TestVerifyStreamBundleAdvancesCheckpointOnlyAfterFullValidation(t *testing.T) {
	vector := loadStreamBundleVector(t)
	verifier := acceptingBundleVerifier{}
	object, err := decodeJSONObject([]byte(vector.Bundle))
	if err != nil {
		t.Fatal(err)
	}
	state, err := bundleObject(object, "state")
	if err != nil {
		t.Fatal(err)
	}
	state["logged_state"] = "REVOKED"
	signature, err := bundleObject(object, "sig")
	if err != nil {
		t.Fatal(err)
	}
	signature["kid"] = fmt.Sprintf("%s+%08x", verifier.Name(), verifier.KeyHash())
	invalid, err := canonicalJSON(object)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryTrustedC2spCheckpointStore()
	trust := StreamBundleTrust{
		PolicyDocument:         []byte(vector.Policy),
		BundleVerifier:         verifier,
		Now:                    func() time.Time { return time.Unix(vector.Trust.Now, 0).UTC() },
		MaxBundleLifetime:      time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
		MaxCheckpointAge:       time.Duration(vector.Trust.CheckpointFreshness) * time.Millisecond,
		TrustedCheckpointStore: store,
	}
	if _, err := VerifyStreamBundle(context.Background(), invalid, trust); err == nil || !strings.Contains(err.Error(), "state does not match") {
		t.Fatalf("VerifyStreamBundle state error = %v", err)
	}
	referenceText, err := bundleString(object, "lr")
	if err != nil {
		t.Fatal(err)
	}
	reference, err := ParseReference(referenceText)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := reference.Origin()
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint, err := store.Load(origin); err != nil || checkpoint != nil {
		t.Fatalf("checkpoint after rejected bundle = %#v, %v", checkpoint, err)
	}

	state["logged_state"] = vector.Expected.Status
	valid, err := canonicalJSON(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStreamBundle(context.Background(), valid, trust); err != nil {
		t.Fatalf("VerifyStreamBundle valid bundle: %v", err)
	}
	checkpoint, err := store.Load(origin)
	if err != nil || checkpoint == nil {
		t.Fatalf("checkpoint after accepted bundle = %#v, %v", checkpoint, err)
	}
	advanced := cloneTrustedCheckpoint(*checkpoint)
	advanced.TreeSize++
	if swapped, err := store.CompareAndSwap(origin, checkpoint, advanced); err != nil || !swapped {
		t.Fatal(swapped, err)
	}
	_, err = VerifyStreamBundle(context.Background(), valid, trust)
	var advanceErr *CheckpointAdvanceError
	if !errors.As(err, &advanceErr) || advanceErr.Kind != CheckpointAdvanceRollback {
		t.Fatalf("bundle lost checkpoint error: %v", err)
	}

	// The same evidence through Client must preserve the typed cause beneath
	// its non-transient invalid_evidence wrapper.
	trust.TrustedCheckpointStore = nil
	bundle, err := VerifyStreamBundle(context.Background(), valid, trust)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ParsePolicy(trust.PolicyDocument)
	if err != nil {
		t.Fatal(err)
	}
	policy.Now, policy.MaxCheckpointAge = trust.Now, trust.MaxCheckpointAge
	client, err := New(referenceText, WithSource(bundle.Source), WithPolicy(policy), WithTrustedCheckpointStore(store))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RebuildHistory(context.Background(), bundle.FQDN)
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &advanceErr) || advanceErr.Kind != CheckpointAdvanceRollback ||
		!errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeInvalidEvidence || verificationErr.Transient() {
		t.Fatalf("client lost checkpoint classification: %v", err)
	}
	if got, err := store.Load(origin); err != nil || !trustedCheckpointsEqual(*got, advanced) {
		t.Fatalf("rejected evidence changed trust: %v, %v", got, err)
	}
}

func TestFetchedStreamBundleSourceUsesBoundReferenceEndpoint(t *testing.T) {
	vector := loadStreamBundleVector(t)
	verifier, err := note.NewVerifier(vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	object, err := decodeJSONObject([]byte(vector.Bundle))
	if err != nil {
		t.Fatal(err)
	}
	lr, _ := bundleString(object, "lr")
	fqdn, _ := bundleString(object, "fqdn")
	reference, err := ParseReference(lr)
	if err != nil {
		t.Fatal(err)
	}
	var requested string
	source := &fetchedStreamBundleSource{
		fetcher: &testBoundedFetcher{fetch: func(_ context.Context, rawURL string, _ int64) ([]byte, error) {
			requested = rawURL
			return []byte(vector.Bundle), nil
		}},
		requireBundle: true,
		trust: StreamBundleTrust{
			PolicyDocument:    []byte(vector.Policy),
			BundleVerifiers:   []note.Verifier{verifier},
			Now:               func() time.Time { return time.Unix(vector.Trust.Now, 0).UTC() },
			MaxBundleLifetime: time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
			MaxCheckpointAge:  time.Duration(vector.Trust.CheckpointFreshness) * time.Millisecond,
		},
	}
	entries, err := source.RebuildHistory(context.Background(), reference, fqdn)
	if err != nil {
		t.Fatalf("RebuildHistory: %v", err)
	}
	if len(entries) != vector.Expected.EventCount {
		t.Fatalf("entries = %d, want %d", len(entries), vector.Expected.EventCount)
	}
	if want := reference.LogPrefix + "/streams/" + fqdn + "?format=bundle"; requested != want {
		t.Fatalf("bundle URL = %q, want %q", requested, want)
	}
}

func TestFetchedStreamBundleSourceFallsBackOnlyWhenUnavailable(t *testing.T) {
	reference, err := ParseReference("c2sp-tlog:public:https://log.example#stream-id")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		body     []byte
		fetchErr error
		wantScan bool
	}{
		{name: "not found", fetchErr: &ResourceFetchError{Kind: ResourceFetchHTTPStatus, HTTPStatus: http.StatusNotFound}, wantScan: true},
		{name: "request timeout", fetchErr: &ResourceFetchError{Kind: ResourceFetchHTTPStatus, HTTPStatus: http.StatusRequestTimeout, TransientFailure: true}, wantScan: true},
		{name: "rate limited", fetchErr: &ResourceFetchError{Kind: ResourceFetchHTTPStatus, HTTPStatus: http.StatusTooManyRequests, TransientFailure: true}, wantScan: true},
		{name: "server error", fetchErr: &ResourceFetchError{Kind: ResourceFetchHTTPStatus, HTTPStatus: http.StatusBadGateway, TransientFailure: true}, wantScan: true},
		{name: "last server error", fetchErr: &ResourceFetchError{Kind: ResourceFetchHTTPStatus, HTTPStatus: 599, TransientFailure: true}, wantScan: true},
		{name: "above server error range", fetchErr: &ResourceFetchError{Kind: ResourceFetchHTTPStatus, HTTPStatus: 600, TransientFailure: true}},
		{name: "truncated read", fetchErr: &ResourceFetchError{Kind: ResourceFetchUnavailable, TransientFailure: true}, wantScan: true},
		{name: "custom transient", fetchErr: transientBundleFetchError{}, wantScan: true},
		{name: "other status", fetchErr: &ResourceFetchError{Kind: ResourceFetchHTTPStatus, HTTPStatus: http.StatusBadRequest, TransientFailure: true}},
		{name: "response limit", fetchErr: &ResourceFetchError{Kind: ResourceFetchResponseLimit, TransientFailure: true}},
		{name: "invalid bytes", body: []byte("{}")},
	} {
		t.Run(test.name, func(t *testing.T) {
			fallback := &countingSource{}
			source := &fetchedStreamBundleSource{
				fetcher: &testBoundedFetcher{fetch: func(context.Context, string, int64) ([]byte, error) {
					return test.body, test.fetchErr
				}},
				fallback: fallback,
			}
			_, _ = source.RebuildHistory(context.Background(), reference, "agent.example")
			if got := fallback.rebuilds > 0; got != test.wantScan {
				t.Fatalf("raw fallback used = %v, want %v", got, test.wantScan)
			}
		})
	}
}

type transientBundleFetchError struct{}

func (transientBundleFetchError) Error() string   { return "temporarily unavailable" }
func (transientBundleFetchError) Transient() bool { return true }

func TestRequiredFetchedStreamBundleSourceUsesRawEventDiscoveryAndBundleHistory(t *testing.T) {
	vector := loadStreamBundleVector(t)
	verifier, err := note.NewVerifier(vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	trust := StreamBundleTrust{
		PolicyDocument:    []byte(vector.Policy),
		BundleVerifier:    verifier,
		Now:               func() time.Time { return time.Unix(vector.Trust.Now, 0).UTC() },
		MaxBundleLifetime: time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
		MaxCheckpointAge:  time.Duration(vector.Trust.CheckpointFreshness) * time.Millisecond,
	}
	bundle, err := VerifyStreamBundle(context.Background(), []byte(vector.Bundle), trust)
	if err != nil {
		t.Fatal(err)
	}
	discovered := cloneProvenEntry(bundle.Source.entries[0])
	discovered.Proof = []byte("invalid raw discovery proof")
	fetches := 0
	source := &fetchedStreamBundleSource{
		fallback: basicSource{entries: []ProvenEntry{discovered}}, requireBundle: true, trust: trust,
		fetcher: &testBoundedFetcher{fetch: func(context.Context, string, int64) ([]byte, error) {
			fetches++
			return []byte(vector.Bundle), nil
		}},
	}
	policy, err := ParsePolicy([]byte(vector.Policy))
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(bundle.Reference.String(), WithSource(source), WithPolicy(policy))
	if err != nil {
		t.Fatal(err)
	}
	ref := dnsidlog.LogRef(fmt.Sprintf("%s@%d", bundle.Reference.String(), bundle.Source.entries[0].Index))
	if _, err := client.ReadEvent(context.Background(), ref); err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if fetches == 0 {
		t.Fatal("ReadEvent returned without requiring bundle history")
	}
}

func TestFetchedStreamBundleSourceUsesRawScanOnlyForMissingConsistencyEvidence(t *testing.T) {
	vector := loadStreamBundleVector(t)
	verifier, err := note.NewVerifier(vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	trust := StreamBundleTrust{
		PolicyDocument:    []byte(vector.Policy),
		BundleVerifier:    verifier,
		Now:               func() time.Time { return time.Unix(vector.Trust.Now, 0).UTC() },
		MaxBundleLifetime: time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
		MaxCheckpointAge:  time.Duration(vector.Trust.CheckpointFreshness) * time.Millisecond,
	}
	bundle, err := VerifyStreamBundle(context.Background(), []byte(vector.Bundle), trust)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ParsePolicy([]byte(vector.Policy))
	if err != nil {
		t.Fatal(err)
	}
	policy.Now = trust.Now
	policy.MaxCheckpointAge = trust.MaxCheckpointAge
	origin, err := bundle.Reference.Origin()
	if err != nil {
		t.Fatal(err)
	}
	rawEntries := make([][]byte, len(bundle.Source.entries))
	for i, entry := range bundle.Source.entries {
		rawEntries[i] = append([]byte(nil), entry.Entry...)
	}

	for _, test := range []struct {
		name          string
		requireBundle bool
		wantScan      bool
		wantError     bool
	}{
		{name: "preferred bundle", wantScan: true},
		{name: "required bundle", requireBundle: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemoryTrustedC2spCheckpointStore()
			old := TrustedC2spCheckpoint{Origin: origin, TreeSize: 1, RootHash: merkleRoot(rawEntries[:1])}
			if swapped, err := store.CompareAndSwap(origin, nil, old); err != nil || !swapped {
				t.Fatalf("seed checkpoint = %v, %v", swapped, err)
			}
			fallback := &fullLogCountingSource{entries: bundle.Source.entries, rawEntries: rawEntries}
			source := &fetchedStreamBundleSource{
				fetcher: &testBoundedFetcher{fetch: func(context.Context, string, int64) ([]byte, error) {
					return []byte(vector.Bundle), nil
				}},
				fallback: fallback, trust: trust, requireBundle: test.requireBundle,
			}
			client, err := New(bundle.Reference.String(), WithSource(source), WithPolicy(policy), WithTrustedCheckpointStore(store))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.RebuildHistory(context.Background(), bundle.FQDN)
			if (err != nil) != test.wantError {
				t.Fatalf("RebuildHistory error = %v, want error %v", err, test.wantError)
			}
			if got := fallback.fullScans > 0; got != test.wantScan {
				t.Fatalf("raw consistency scan used = %v, want %v", got, test.wantScan)
			}
		})
	}
}

type fullLogCountingSource struct {
	entries    []ProvenEntry
	rawEntries [][]byte
	fullScans  int
}

func (s *fullLogCountingSource) ReadEvent(_ context.Context, _ dnsidlog.LogRef) (ProvenEntry, error) {
	return cloneProvenEntry(s.entries[0]), nil
}

func (s *fullLogCountingSource) RebuildHistory(_ context.Context, _ Reference, _ string) ([]ProvenEntry, error) {
	return append([]ProvenEntry(nil), s.entries...), nil
}

func (s *fullLogCountingSource) FetchEntriesThrough(_ context.Context, _ Reference, treeSize uint64) ([][]byte, error) {
	s.fullScans++
	if treeSize != uint64(len(s.rawEntries)) {
		return nil, fmt.Errorf("tree size = %d, want %d", treeSize, len(s.rawEntries))
	}
	return cloneEntries(s.rawEntries), nil
}

func TestVerifyStreamBundleRejectsAmbiguousSignerKeyID(t *testing.T) {
	vector := loadStreamBundleVector(t)
	verifier, err := note.NewVerifier(vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	trust := StreamBundleTrust{
		PolicyDocument:    []byte(vector.Policy),
		BundleVerifiers:   []note.Verifier{verifier, verifier},
		Now:               func() time.Time { return time.Unix(vector.Trust.Now, 0).UTC() },
		MaxBundleLifetime: time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
	}
	if _, err := VerifyStreamBundle(context.Background(), []byte(vector.Bundle), trust); err == nil {
		t.Fatal("VerifyStreamBundle accepted an ambiguous signer key ID")
	}
}

func TestVerifyStreamBundleRejectsPythonInteropMutations(t *testing.T) {
	vector := loadStreamBundleVector(t)
	verifier, err := note.NewVerifier(vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	trust := StreamBundleTrust{
		PolicyDocument:    []byte(vector.Policy),
		BundleVerifier:    verifier,
		Now:               func() time.Time { return time.Unix(vector.Trust.Now, 0).UTC() },
		MaxBundleLifetime: time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
		MaxCheckpointAge:  time.Duration(vector.Trust.CheckpointFreshness) * time.Millisecond,
	}
	for _, mutation := range vector.NegativeMutations {
		t.Run(mutation.Name, func(t *testing.T) {
			object, err := decodeJSONObject([]byte(vector.Bundle))
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if len(mutation.Value) != 0 {
				decoder := json.NewDecoder(bytes.NewReader(mutation.Value))
				decoder.UseNumber()
				if err := decoder.Decode(&value); err != nil {
					t.Fatal(err)
				}
			}
			if err := applyBundleVectorMutation(object, mutation.Path, mutation.Append, value); err != nil {
				t.Fatal(err)
			}
			mutated, err := canonicalJSON(object)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyStreamBundle(context.Background(), mutated, trust); err == nil {
				t.Fatal("VerifyStreamBundle accepted negative cross-SDK mutation")
			}
		})
	}
}

func loadStreamBundleVector(t *testing.T) streamBundleVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "c2sp-stream-bundle-logical-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector streamBundleVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func applyBundleVectorMutation(object map[string]any, path, appendText string, value any) error {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	var current any = object
	for _, part := range parts[:len(parts)-1] {
		switch node := current.(type) {
		case map[string]any:
			current = node[part]
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(node) {
				return fmt.Errorf("invalid mutation path %q", path)
			}
			current = node[index]
		default:
			return fmt.Errorf("invalid mutation path %q", path)
		}
	}
	last := parts[len(parts)-1]
	set := func(old any) any {
		if appendText == "" {
			return value
		}
		return old.(string) + appendText
	}
	switch node := current.(type) {
	case map[string]any:
		node[last] = set(node[last])
	case []any:
		index, err := strconv.Atoi(last)
		if err != nil || index < 0 || index >= len(node) {
			return fmt.Errorf("invalid mutation path %q", path)
		}
		node[index] = set(node[index])
	default:
		return fmt.Errorf("invalid mutation path %q", path)
	}
	return nil
}
