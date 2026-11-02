package c2sptlog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
		HeadEventID                 string `json:"head_event_id"`
		Status                      string `json:"status"`
	} `json:"expected"`
	Trust struct {
		BundleVerifierKey   string `json:"bundle_verifier_key"`
		CheckpointFreshness int64  `json:"checkpoint_freshness_ms"`
		MaxBundleLifetime   int64  `json:"max_bundle_lifetime_ms"`
		Now                 int64  `json:"now"`
	} `json:"trust"`
}

func TestVerifyStreamBundleCorrectedVector(t *testing.T) {
	path := filepath.Join("testdata", "c2sp-stream-bundle-v2.json")
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

func TestVerifyStreamBundleAdvancesCheckpointOnlyAfterFullValidation(t *testing.T) {
	vector := loadStreamBundleVector(t)
	verifier, err := note.NewVerifier(vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	object, err := decodeJSONObject([]byte(vector.Bundle))
	if err != nil {
		t.Fatal(err)
	}
	// A valid statement whose head is a bundled event but not the replayed head.
	first, err := base64.RawURLEncoding.DecodeString(object["events"].([]any)[0].(map[string]any)["entry"].(string))
	if err != nil {
		t.Fatal(err)
	}
	firstSigned, err := CanonicalFromEntry(first)
	if err != nil {
		t.Fatal(err)
	}
	invalid := signTestBundle(t, object, func(head *StreamHead) { head.HeadEventID = EventID(firstSigned) })
	store := NewMemoryTrustedC2spCheckpointStore()
	trust := StreamBundleTrust{
		PolicyDocument:         []byte(vector.Policy),
		BundleVerifier:         verifier,
		Now:                    func() time.Time { return time.Unix(vector.Trust.Now, 0).UTC() },
		MaxBundleLifetime:      time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
		MaxCheckpointAge:       time.Duration(vector.Trust.CheckpointFreshness) * time.Millisecond,
		TrustedCheckpointStore: store,
	}
	if _, err := VerifyStreamBundle(context.Background(), invalid, trust); err == nil || !strings.Contains(err.Error(), "does not end at the stream-head") {
		t.Fatalf("VerifyStreamBundle head error = %v", err)
	}
	referenceText := testBundleHead(t, object).LR
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

	valid := []byte(vector.Bundle)
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
		!errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeLogRollback || verificationErr.Transient() {
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
	fqdn := "agent.example.com"
	reference, err := ParseReference(testBundleHead(t, object).LR)
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
	if want := reference.LogPrefix + "/streams/" + fqdn + "?format=bundle-v2"; requested != want {
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

func TestFetchedStreamBundleSource_CustomReaderMissingCapabilityFallback(t *testing.T) {
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
			old := TrustedC2spCheckpoint{Origin: origin, TreeSize: 1, RootHash: merkleRoot(rawEntries[:1]), WitnessTime: time.Unix(1, 0)}
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

func TestVerifyStreamBundleRejectsMutations(t *testing.T) {
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
	load := func(t *testing.T) map[string]any {
		object, err := decodeJSONObject([]byte(vector.Bundle))
		if err != nil {
			t.Fatal(err)
		}
		return object
	}
	events := func(object map[string]any) []any { return object["events"].([]any) }
	setHead := func(text string) func(*testing.T, map[string]any) []byte {
		return func(t *testing.T, object map[string]any) []byte {
			object["head"] = signTestNote(t, "bundle.example", testStreamHeadSeed, []byte(text))
			encoded, _ := json.Marshal(object)
			return encoded
		}
	}
	head := testBundleHead(t, load(t))
	root := base64.StdEncoding.EncodeToString(head.RootHash)
	valid := fmt.Sprintf("%s\nlr %s\ncheckpoint %d %s\nhead %s\nexpires %d\n", StreamHeadStatementType, head.LR, head.TreeSize, root, head.HeadEventID, head.Expires.Unix())
	if _, err := VerifyStreamBundle(context.Background(), setHead(valid)(t, load(t)), trust); err != nil {
		t.Fatalf("hand-built statement rejected: %v", err)
	}
	resign := func(edit func(*StreamHead)) func(*testing.T, map[string]any) []byte {
		return func(t *testing.T, object map[string]any) []byte { return signTestBundle(t, object, edit) }
	}
	unsigned := func(edit func(map[string]any)) func(*testing.T, map[string]any) []byte {
		return func(t *testing.T, object map[string]any) []byte {
			edit(object)
			encoded, _ := json.Marshal(object)
			return encoded
		}
	}
	for name, mutate := range map[string]func(*testing.T, map[string]any) []byte{
		"padded head":        unsigned(func(o map[string]any) { o["head"] = o["head"].(string) + "=" }),
		"version 1":          unsigned(func(o map[string]any) { o["v"] = json.Number("1") }),
		"wrong type":         unsigned(func(o map[string]any) { o["type"] = "other" }),
		"extra member":       unsigned(func(o map[string]any) { o["fqdn"] = "agent.example.com" }),
		"missing member":     unsigned(func(o map[string]any) { delete(o, "events") }),
		"out-of-order index": unsigned(func(o map[string]any) { events(o)[1].(map[string]any)["index"] = json.Number("0") }),
		"index beyond tree":  unsigned(func(o map[string]any) { events(o)[1].(map[string]any)["index"] = json.Number("2") }),
		"proof length":       unsigned(func(o map[string]any) { events(o)[0].(map[string]any)["proof"] = "AA" }),
		"entry mismatch": unsigned(func(o map[string]any) {
			events(o)[0].(map[string]any)["entry"] = events(o)[1].(map[string]any)["entry"]
		}),
		"omitted final event":  unsigned(func(o map[string]any) { o["events"] = events(o)[:1] }),
		"omitted middle event": unsigned(func(o map[string]any) { o["events"] = events(o)[1:] }),
		"unaccepted key": func(t *testing.T, o map[string]any) []byte {
			text, _ := head.MarshalText()
			o["head"] = signTestNote(t, "bundle.example", bytes.Repeat([]byte{9}, 32), text)
			encoded, _ := json.Marshal(o)
			return encoded
		},
		"log key": func(t *testing.T, o map[string]any) []byte {
			text, _ := head.MarshalText()
			o["head"] = signTestNote(t, "log.example", bytes.Repeat([]byte{4}, 32), text)
			encoded, _ := json.Marshal(o)
			return encoded
		},
		"lr mismatch":          resign(func(h *StreamHead) { h.LR = "c2sp-tlog:public:https://log.example#other" }),
		"tree size mismatch":   resign(func(h *StreamHead) { h.TreeSize++ }),
		"root mismatch":        resign(func(h *StreamHead) { h.RootHash = make([]byte, 32) }),
		"expired":              resign(func(h *StreamHead) { h.Expires = time.Unix(vector.Trust.Now, 0) }),
		"beyond lifetime":      resign(func(h *StreamHead) { h.Expires = time.Unix(vector.Trust.Now, 0).Add(24 * time.Hour) }),
		"extra line":           setHead(valid + "extra\n"),
		"missing line":         setHead(strings.Replace(valid, fmt.Sprintf("expires %d\n", head.Expires.Unix()), "", 1)),
		"reordered lines":      setHead(strings.Replace(valid, "head "+head.HeadEventID+"\nexpires", "expires", 1) + "head " + head.HeadEventID + "\n"),
		"leading zero":         setHead(strings.Replace(valid, fmt.Sprintf("checkpoint %d ", head.TreeSize), fmt.Sprintf("checkpoint 0%d ", head.TreeSize), 1)),
		"double space":         setHead(strings.Replace(valid, "lr ", "lr  ", 1)),
		"non-canonical root":   setHead(strings.Replace(valid, root, root[:len(root)-2]+string(root[len(root)-2]+1)+"=", 1)),
		"wrong statement type": setHead(strings.Replace(valid, StreamHeadStatementType, "dnsid-c2sp-stream-head@v2", 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyStreamBundle(context.Background(), mutate(t, load(t)), trust); err == nil {
				t.Fatal("VerifyStreamBundle accepted an invalid bundle")
			}
		})
	}
}

func TestVerifyStreamBundleAcceptsReencodedBundle(t *testing.T) {
	vector := loadStreamBundleVector(t)
	verifier, err := note.NewVerifier(vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	decoder := json.NewDecoder(strings.NewReader(vector.Bundle))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.MarshalIndent(object, " ", "\t")
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyStreamBundle(context.Background(), reencoded, StreamBundleTrust{
		PolicyDocument:    []byte(vector.Policy),
		BundleVerifiers:   []note.Verifier{verifier},
		Now:               func() time.Time { return time.Unix(vector.Trust.Now, 0).UTC() },
		MaxBundleLifetime: time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
		MaxCheckpointAge:  time.Duration(vector.Trust.CheckpointFreshness) * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("re-encoded bundle rejected: %v", err)
	}
}

func loadStreamBundleVector(t *testing.T) streamBundleVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "c2sp-stream-bundle-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector streamBundleVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

type discoveringSource struct {
	basicSource
	entry      []byte
	fullScans  int
	discovered int
}

func (s *discoveringSource) ReadEvent(ctx context.Context, ref dnsidlog.LogRef) (ProvenEntry, error) {
	s.fullScans++
	return s.basicSource.ReadEvent(ctx, ref)
}

func (s *discoveringSource) discoverEntry(context.Context, Reference, uint64) ([]byte, error) {
	s.discovered++
	return append([]byte(nil), s.entry...), nil
}

func TestFetchedStreamBundleSourceReadEventUsesBundleWithoutFullScan(t *testing.T) {
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
	if len(bundle.Source.entries) < 2 {
		t.Fatal("vector needs two bundled entries")
	}
	policy, err := ParsePolicy([]byte(vector.Policy))
	if err != nil {
		t.Fatal(err)
	}
	target := bundle.Source.entries[0]
	for name, hint := range map[string][]byte{"match": target.Entry, "mismatch": bundle.Source.entries[1].Entry} {
		t.Run(name, func(t *testing.T) {
			fallback := &discoveringSource{entry: hint}
			source := &fetchedStreamBundleSource{
				fallback: fallback, requireBundle: true, trust: trust,
				fetcher: &testBoundedFetcher{fetch: func(context.Context, string, int64) ([]byte, error) {
					return []byte(vector.Bundle), nil
				}},
			}
			client, err := New(bundle.Reference.String(), WithSource(source), WithPolicy(policy))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.ReadEvent(context.Background(), bundle.Reference.FinalEventRef(target.Index))
			if (err != nil) != (name == "mismatch") {
				t.Fatalf("ReadEvent error = %v", err)
			}
			if fallback.fullScans != 0 || fallback.discovered != 1 {
				t.Fatalf("fullScans=%d discovered=%d", fallback.fullScans, fallback.discovered)
			}
		})
	}
}
