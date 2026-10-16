package c2sptlog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	formatproof "github.com/transparency-dev/formats/proof"
	"golang.org/x/mod/sumdb/note"
)

// Use real lifecycle signatures from the native bundle fixture and sign each
// test checkpoint with that fixture's disposable log and timestamped witness.
func checkpointReaderFixture(t *testing.T) (*VerifiedStreamBundle, Policy, [][]byte) {
	t.Helper()
	v := loadStreamBundleVector(t)
	verifier, err := note.NewVerifier(v.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	trust := StreamBundleTrust{PolicyDocument: []byte(v.Policy), BundleVerifier: verifier,
		Now:               func() time.Time { return time.Unix(v.Trust.Now, 0) },
		MaxBundleLifetime: time.Duration(v.Trust.MaxBundleLifetime) * time.Millisecond,
		MaxCheckpointAge:  time.Duration(v.Trust.CheckpointFreshness) * time.Millisecond}
	bundle, err := VerifyStreamBundle(context.Background(), []byte(v.Bundle), trust)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ParsePolicy(trust.PolicyDocument)
	if err != nil {
		t.Fatal(err)
	}
	policy.Now = trust.Now
	var raw [][]byte
	for _, entry := range bundle.Source.entries {
		raw = append(raw, entry.Entry)
	}
	return bundle, policy, raw
}

func signedCheckpointEntries(t *testing.T, policy Policy, raw [][]byte) []ProvenEntry {
	t.Helper()
	checkpoint := fmt.Sprintf("log.example\n%d\n%s\n", len(raw), base64.StdEncoding.EncodeToString(merkleRoot(raw)))
	scan := completeScan{checkpoint: signTestCheckpoint(policy, checkpoint), entries: raw, levels: merkleLevels(raw)}
	var entries []ProvenEntry
	for i := range raw {
		entries = append(entries, scan.provenEntry(uint64(i)))
	}
	return entries
}

func signTestCheckpoint(policy Policy, checkpoint string) []byte {
	var signatures string
	for i, verifier := range []note.Verifier{policy.LogVerifier, policy.WitnessVerifiers[0]} {
		input := []byte(checkpoint)
		prefix := binary.BigEndian.AppendUint32(nil, verifier.KeyHash())
		if i == 1 {
			ts := policy.now().Unix()
			input = fmt.Appendf(nil, "cosignature/v1\ntime %d\n%s", ts, checkpoint)
			prefix = binary.BigEndian.AppendUint64(prefix, uint64(ts))
		}
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(4 + i)}, 32))
		signatures += fmt.Sprintf("— %s %s\n", verifier.Name(), base64.StdEncoding.EncodeToString(append(prefix, ed25519.Sign(key, input)...)))
	}
	return []byte(checkpoint + "\n" + signatures)
}

func TestCheckpointProof_RejectsUnrepresentableTreeSize(t *testing.T) {
	bundle, policy, raw := checkpointReaderFixture(t)
	checkpoint := signTestCheckpoint(policy, fmt.Sprintf("log.example\n%d\n%s\n", uint64(math.MaxUint64), base64.StdEncoding.EncodeToString(merkleRoot(raw))))
	proof := formatproof.TLogProof{Checkpoint: checkpoint}.Marshal()
	_, err := policy.VerifyProof(bundle.Reference, raw[0], proof)
	checkpointCode(t, err, dnsid.VerificationCodeInvalidEvidence, false)
}

func checkpointCode(t *testing.T, err error, code dnsid.VerificationCode, transient bool) {
	t.Helper()
	var ve *dnsid.VerificationError
	if !errors.As(err, &ve) || ve.Code() != code || ve.Transient() != transient {
		t.Fatalf("error = %v; want %s transient=%v", err, code, transient)
	}
}

type regressionFetchError struct{ error }

func (regressionFetchError) Transient() bool { return true }
func (e regressionFetchError) Unwrap() error { return e.error }

type regressionScanSource struct {
	globalMemorySource
	raw   [][]byte
	fetch func(context.Context) error
}

func (s regressionScanSource) FetchEntriesThrough(ctx context.Context, _ Reference, _ uint64) ([][]byte, error) {
	if s.fetch != nil {
		if err := s.fetch(ctx); err != nil {
			return nil, err
		}
	}
	return s.raw, nil
}

type regressionProofSource struct {
	regressionScanSource
	err      error
	requests *int
}

func (s regressionProofSource) FetchConsistencyProof(context.Context, Reference, uint64, uint64) ([][]byte, error) {
	*s.requests += 1
	return nil, s.err
}

func TestCheckpointReader_ClassificationsAndState(t *testing.T) {
	bundle, policy, raw := checkpointReaderFixture(t)
	cause := errors.New("dependency failure")
	for _, mode := range []string{"rollback", "fork", "missing leaf", "candidate root", "trusted prefix", "proof", "fetch", "scan fetch", "load", "write", "corrupt store", "invalid signature", "invalid index", "missing consistency", "proof unavailable"} {
		t.Run(mode, func(t *testing.T) {
			store := NewMemoryTrustedC2spCheckpointStore()
			seedRaw := raw[:1]
			if mode == "rollback" {
				seedRaw = raw
			}
			seed, err := New(bundle.Reference.String(), WithSource(globalMemorySource{memorySource{entries: signedCheckpointEntries(t, policy, seedRaw)}}), WithPolicy(policy), WithTrustedCheckpointStore(store))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := seed.RebuildHistory(context.Background(), bundle.FQDN); err != nil {
				t.Fatal(err)
			}
			old, err := store.Load("log.example")
			if err != nil {
				t.Fatal(err)
			}
			entries := signedCheckpointEntries(t, policy, raw)
			scan := regressionScanSource{globalMemorySource: globalMemorySource{memorySource{entries: entries}}, raw: raw}
			var source Source = scan
			var selected TrustedC2spCheckpointStore = store
			code, transient := dnsid.VerificationCodeInvalidEvidence, false
			wantCause := false
			proofRequests := 0
			switch mode {
			case "rollback":
				source = globalMemorySource{memorySource{entries: signedCheckpointEntries(t, policy, raw[:1])}}
				code = dnsid.VerificationCodeLogRollback
			case "fork":
				source = globalMemorySource{memorySource{entries: signedCheckpointEntries(t, policy, [][]byte{[]byte("another global log entry")})}}
				code = dnsid.VerificationCodeLogFork
			case "missing leaf":
				scan.raw = raw[:1]
				source = scan
			case "candidate root":
				scan.raw = [][]byte{[]byte("wrong"), raw[1]}
				source = scan
			case "trusted prefix":
				conflict := cloneTrustedCheckpoint(*old)
				conflict.RootHash = bytes.Repeat([]byte{9}, 32)
				if ok, err := store.CompareAndSwap(old.Origin, old, conflict); err != nil || !ok {
					t.Fatal(ok, err)
				}
				old = &conflict
				code = dnsid.VerificationCodeLogInconsistent
			case "proof":
				source = regressionProofSource{regressionScanSource: scan, requests: &proofRequests}
				code = dnsid.VerificationCodeLogInconsistent
			case "fetch":
				source = regressionProofSource{regressionScanSource: scan, err: regressionFetchError{cause}, requests: &proofRequests}
				code, transient, wantCause = dnsid.VerificationCodeLogError, true, true
			case "scan fetch":
				scan.fetch = func(context.Context) error { return regressionFetchError{cause} }
				source = scan
				code, transient, wantCause = dnsid.VerificationCodeLogError, true, true
			case "load":
				selected = failingCheckpointStore{TrustedC2spCheckpointStore: store, loadErr: regressionFetchError{cause}}
				code, wantCause = dnsid.VerificationCodeCheckpointStore, true
			case "write":
				selected = failingCheckpointStore{TrustedC2spCheckpointStore: store, casErr: regressionFetchError{cause}}
				code, wantCause = dnsid.VerificationCodeCheckpointStore, true
			case "corrupt store":
				selected = corruptCheckpointStore{store, TrustedC2spCheckpoint{Origin: old.Origin, TreeSize: old.TreeSize, RootHash: []byte("corrupt"), WitnessTime: old.WitnessTime}}
				code = dnsid.VerificationCodeCheckpointStore
			case "invalid signature":
				for i := range entries {
					var p formatproof.TLogProof
					if err := p.Unmarshal(entries[i].Proof); err != nil {
						t.Fatal(err)
					}
					p.Checkpoint = bytes.Replace(p.Checkpoint, []byte("— log.example "), []byte("— untrusted.example "), 1)
					entries[i].Proof = p.Marshal()
				}
			case "invalid index":
				entries[0].Index++
			case "missing consistency":
				source = globalMemorySource{memorySource{entries: entries}}
			case "proof unavailable":
				source = regressionProofSource{regressionScanSource: scan, err: ErrConsistencyUnavailable, requests: &proofRequests}
			}
			client, err := New(bundle.Reference.String(), WithSource(source), WithPolicy(policy), WithTrustedCheckpointStore(selected))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.RebuildHistory(context.Background(), bundle.FQDN)
			checkpointCode(t, err, code, transient)
			if (mode == "proof" || mode == "fetch" || mode == "proof unavailable") && proofRequests != 1 {
				t.Fatalf("proof requests = %d", proofRequests)
			}
			if wantCause && !errors.Is(err, cause) {
				t.Fatal("lost cause")
			}
			var advance *CheckpointAdvanceError
			if errors.As(err, &advance) {
				if mode != "rollback" && mode != "fork" && mode != "trusted prefix" && mode != "proof" && mode != "missing consistency" && mode != "proof unavailable" {
					t.Fatalf("unexpected continuity classification: %v", err)
				}
				if mode == "missing consistency" || mode == "proof unavailable" {
					if advance.Kind != CheckpointAdvanceConsistencyUnavailable {
						t.Fatal(advance.Kind)
					}
				}
				if advance.Origin != old.Origin || advance.OldTreeSize != old.TreeSize || !bytes.Equal(advance.OldRootHash, old.RootHash) || len(advance.NewRootHash) != 32 || advance.SplitView != (mode == "fork") {
					t.Fatalf("incorrect diagnostics: %+v", advance)
				}
				advance.OldRootHash[0] ^= 0xff
				advance.NewRootHash[0] ^= 0xff
			}
			got, err := store.Load(old.Origin)
			if err != nil || !trustedCheckpointsEqual(*got, *old) {
				t.Fatalf("failure changed trust: %v, %v", got, err)
			}
		})
	}
}

type historicalOccurrenceSource struct {
	basicSource
	occurrence ProvenEntry
}

func (s historicalOccurrenceSource) ReadEvent(context.Context, dnsidlog.LogRef) (ProvenEntry, error) {
	return s.occurrence, nil
}

func TestCheckpointReadEvent_ChecksOccurrenceCheckpointBeforeCurrentHistory(t *testing.T) {
	bundle, policy, raw := checkpointReaderFixture(t)
	store := NewMemoryTrustedC2spCheckpointStore()
	current := signedCheckpointEntries(t, policy, raw)
	client, err := New(bundle.Reference.String(), WithSource(basicSource{entries: current}), WithPolicy(policy), WithTrustedCheckpointStore(store))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RebuildHistory(context.Background(), bundle.FQDN); err != nil {
		t.Fatal(err)
	}
	old, _ := store.Load("log.example")
	client.source = historicalOccurrenceSource{basicSource: basicSource{entries: current}, occurrence: signedCheckpointEntries(t, policy, raw[:1])[0]}
	_, err = client.ReadEvent(context.Background(), bundle.Reference.FinalEventRef(0))
	checkpointCode(t, err, dnsid.VerificationCodeLogRollback, false)
	got, err := store.Load("log.example")
	if err != nil || !trustedCheckpointsEqual(*got, *old) {
		t.Fatal("replayed occurrence changed trust")
	}
}

type corruptCheckpointStore struct {
	TrustedC2spCheckpointStore
	checkpoint TrustedC2spCheckpoint
}

func (s corruptCheckpointStore) Load(string) (*TrustedC2spCheckpoint, error) {
	return &s.checkpoint, nil
}

func TestMemoryCheckpointStore_ValidationAndExactTime(t *testing.T) {
	for _, store := range []*MemoryTrustedC2spCheckpointStore{nil, {}} {
		_, err := store.Load("log")
		checkpointCode(t, err, dnsid.VerificationCodeCheckpointStore, false)
	}
	var argumentError *dnsid.ArgumentError
	if _, err := NewMemoryTrustedC2spCheckpointStore().Load(""); !errors.As(err, &argumentError) {
		t.Fatalf("empty origin: %v", err)
	}
	if _, err := NewMemoryTrustedC2spCheckpointStore().LoadContext(nil, "log"); !errors.As(err, &argumentError) {
		t.Fatalf("nil context: %v", err)
	}
	valid := TrustedC2spCheckpoint{Origin: "log", TreeSize: 1, RootHash: bytes.Repeat([]byte{1}, 32), WitnessTime: time.Unix(1, 0)}
	for _, field := range []string{"origin", "root", "size", "time", "time range"} {
		t.Run(field, func(t *testing.T) {
			bad := cloneTrustedCheckpoint(valid)
			switch field {
			case "origin":
				bad.Origin = "other"
			case "root":
				bad.RootHash = bad.RootHash[:31]
			case "size":
				bad.TreeSize = math.MaxUint64
			case "time":
				bad.WitnessTime = time.Time{}
			case "time range":
				bad.WitnessTime = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			}
			store := NewMemoryTrustedC2spCheckpointStore()
			var arg *dnsid.ArgumentError
			if ok, err := store.CompareAndSwap("log", nil, bad); ok || !errors.As(err, &arg) {
				t.Fatalf("invalid candidate: %v %v", ok, err)
			}
			if ok, err := store.CompareAndSwap("log", &bad, valid); ok || !errors.As(err, &arg) {
				t.Fatalf("invalid expected: %v %v", ok, err)
			}
			if got, err := store.Load("log"); err != nil || got != nil {
				t.Fatal("invalid input wrote state")
			}
			if ok, err := store.CompareAndSwap("log", nil, valid); err != nil || !ok {
				t.Fatal(ok, err)
			}
			store.checkpoints["log"] = bad // Inject corruption behind the store boundary.
			_, err := store.Load("log")
			checkpointCode(t, err, dnsid.VerificationCodeCheckpointStore, false)
			_, err = store.CompareAndSwap("log", &valid, valid)
			checkpointCode(t, err, dnsid.VerificationCodeCheckpointStore, false)
		})
	}
	store := NewMemoryTrustedC2spCheckpointStore()
	if ok, err := store.CompareAndSwap("log", nil, valid); err != nil || !ok {
		t.Fatal(ok, err)
	}
	stale := cloneTrustedCheckpoint(valid)
	stale.WitnessTime = stale.WitnessTime.Add(time.Nanosecond)
	if ok, err := store.CompareAndSwap("log", &stale, valid); err != nil || ok {
		t.Fatal("ignored stale witness time", ok, err)
	}
}

func TestMemoryCheckpointStore_CancelledWaitCannotPublish(t *testing.T) {
	store := NewMemoryTrustedC2spCheckpointStore()
	candidate := TrustedC2spCheckpoint{Origin: "log", TreeSize: 1, RootHash: bytes.Repeat([]byte{1}, 32), WitnessTime: time.Unix(1, 0)}
	if err := store.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	started, done := make(chan struct{}), make(chan error, 1)
	go func() { close(started); _, err := store.CompareAndSwapContext(ctx, "log", nil, candidate); done <- err }()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	<-store.mu
	if got, err := store.Load("log"); err != nil || got != nil {
		t.Fatal("cancelled waiter published")
	}
	// Cancellation must not release a different invocation's lock.
	if err := store.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadContext(ctx, "log"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(store.mu) != 1 {
		t.Fatal("cancelled load released owner lock")
	}
	<-store.mu
}

func TestCheckpointReader_CancellationAndConflictingWriters(t *testing.T) {
	bundle, policy, raw := checkpointReaderFixture(t)
	for _, cancelBeforeCAS := range []bool{true, false} {
		t.Run(fmt.Sprint(cancelBeforeCAS), func(t *testing.T) {
			store := NewMemoryTrustedC2spCheckpointStore()
			seed, _ := New(bundle.Reference.String(), WithSource(globalMemorySource{memorySource{entries: signedCheckpointEntries(t, policy, raw[:1])}}), WithPolicy(policy), WithTrustedCheckpointStore(store))
			if _, err := seed.RebuildHistory(context.Background(), bundle.FQDN); err != nil {
				t.Fatal(err)
			}
			old, _ := store.Load("log.example")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			arrived, release := make(chan struct{}, 2), make(chan struct{})
			var wg sync.WaitGroup
			results := make(chan error, 2)
			for i := range 2 {
				leaves := cloneEntries(raw)
				if i == 1 {
					leaves[1] = []byte("other global entry")
				}
				source := regressionScanSource{globalMemorySource: globalMemorySource{memorySource{entries: signedCheckpointEntries(t, policy, leaves)}}, raw: leaves,
					fetch: func(context.Context) error { arrived <- struct{}{}; <-release; return nil }}
				client, _ := New(bundle.Reference.String(), WithSource(source), WithPolicy(policy), WithTrustedCheckpointStore(store))
				wg.Go(func() { _, err := client.RebuildHistory(ctx, bundle.FQDN); results <- err })
			}
			<-arrived
			<-arrived
			if cancelBeforeCAS {
				cancel()
			}
			close(release)
			wg.Wait()
			close(results)
			successes := 0
			for err := range results {
				if err == nil {
					successes++
					continue
				}
				if cancelBeforeCAS {
					if !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
				} else {
					checkpointCode(t, err, dnsid.VerificationCodeLogFork, false)
				}
			}
			got, err := store.Load("log.example")
			if err != nil {
				t.Fatal(err)
			}
			if cancelBeforeCAS {
				if successes != 0 || !trustedCheckpointsEqual(*got, *old) {
					t.Fatal("cancelled verification published")
				}
			} else if successes != 1 || got.TreeSize != 2 {
				t.Fatalf("conflicting writers: successes=%d state=%+v", successes, got)
			}
		})
	}
}

type indeterminateCheckpointStore struct {
	TrustedC2spCheckpointStore
	cause  error
	writes int
}

func (s *indeterminateCheckpointStore) CompareAndSwap(origin string, old *TrustedC2spCheckpoint, next TrustedC2spCheckpoint) (bool, error) {
	s.writes++
	ok, err := s.TrustedC2spCheckpointStore.CompareAndSwap(origin, old, next)
	if err != nil || !ok {
		return ok, err
	}
	return false, s.cause
}

type rejectedCompleteSource struct {
	basicSource
	err error
}

func (s rejectedCompleteSource) RebuildCompleteHistory(context.Context, Reference, string) (CompleteHistoryResult, error) {
	return CompleteHistoryResult{}, s.err
}

func TestCheckpointReader_CompleteSourcePreservesClassifications(t *testing.T) {
	cause := errors.New("dependency unavailable")
	for _, code := range []dnsid.VerificationCode{dnsid.VerificationCodeCheckpointStore, dnsid.VerificationCodeInvalidEvidence} {
		client, err := New("c2sp-tlog:public:https://log.example#identity-01", WithSource(rejectedCompleteSource{err: dnsid.NewVerificationError(code, false, "dependency failure", cause)}), WithPolicy(Policy{MaxCheckpointAge: time.Minute}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.VerifyNonRevocation(context.Background(), "agent.example", time.Now())
		checkpointCode(t, err, code, false)
		if !errors.Is(err, cause) {
			t.Fatal("lost complete-source cause")
		}
	}
}

func TestCheckpointScanner_InvalidCandidateEvidencePreservesTrust(t *testing.T) {
	bundle, policy, raw := checkpointReaderFixture(t)
	for _, mode := range []string{"missing leaf", "wrong tile", "wrong root"} {
		t.Run(mode, func(t *testing.T) {
			store := NewMemoryTrustedC2spCheckpointStore()
			seed, err := New(bundle.Reference.String(), WithSource(globalMemorySource{memorySource{entries: signedCheckpointEntries(t, policy, raw[:1])}}), WithPolicy(policy), WithTrustedCheckpointStore(store))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := seed.RebuildHistory(context.Background(), bundle.FQDN); err != nil {
				t.Fatal(err)
			}
			old, _ := store.Load("log.example")
			proven := signedCheckpointEntries(t, policy, raw)
			var proof formatproof.TLogProof
			if err := proof.Unmarshal(proven[0].Proof); err != nil {
				t.Fatal(err)
			}
			leaves := cloneEntries(raw)
			if mode == "missing leaf" {
				leaves = leaves[:1]
			}
			if mode == "wrong root" {
				leaves[0] = []byte("other leaf")
			}
			var entries, tile []byte
			for _, entry := range leaves {
				entries = binary.BigEndian.AppendUint16(entries, uint16(len(entry)))
				entries = append(entries, entry...)
				leaf := LeafHash(entry)
				tile = append(tile, leaf[:]...)
			}
			if mode == "wrong tile" {
				tile[0] ^= 1
			}
			resources := map[string][]byte{"/checkpoint": proof.Checkpoint, "/tile/entries/000.p/2": entries, "/tile/0/000.p/2": tile}
			scanner, err := NewScanSource(policy, ScanSourceConfig{Transport: scanHTTPClient(resources).Transport})
			if err != nil {
				t.Fatal(err)
			}
			client, err := New(bundle.Reference.String(), WithSource(scanner), WithPolicy(policy), WithTrustedCheckpointStore(store))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.RebuildHistory(context.Background(), bundle.FQDN)
			checkpointCode(t, err, dnsid.VerificationCodeInvalidEvidence, false)
			got, err := store.Load("log.example")
			if err != nil || !trustedCheckpointsEqual(*got, *old) {
				t.Fatal("invalid scanner evidence changed trust")
			}
		})
	}
	// Scanner transport failures must not be relabeled as malformed scan bytes.
	scanner, err := NewScanSource(policy, ScanSourceConfig{ResourceFetcher: &testBoundedFetcher{fetch: func(context.Context, string, int64) ([]byte, error) {
		return nil, &ResourceFetchError{Kind: ResourceFetchHTTPStatus, HTTPStatus: http.StatusServiceUnavailable, TransientFailure: true}
	}}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(bundle.Reference.String(), WithSource(scanner), WithPolicy(policy))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RebuildHistory(context.Background(), bundle.FQDN)
	checkpointCode(t, err, dnsid.VerificationCodeLogError, true)
}

type stagedCheckpointStore struct {
	*MemoryTrustedC2spCheckpointStore
	staged chan struct{}
	resume chan struct{}
}

func (s stagedCheckpointStore) CompareAndSwapContext(ctx context.Context, origin string, old *TrustedC2spCheckpoint, next TrustedC2spCheckpoint) (bool, error) {
	close(s.staged)
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-s.resume:
		return s.MemoryTrustedC2spCheckpointStore.CompareAndSwapContext(ctx, origin, old, next)
	}
}

func TestVerifyStreamBundle_CancellationBeforePublication(t *testing.T) {
	v := loadStreamBundleVector(t)
	verifier, err := note.NewVerifier(v.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	store := stagedCheckpointStore{MemoryTrustedC2spCheckpointStore: NewMemoryTrustedC2spCheckpointStore(), staged: make(chan struct{}), resume: make(chan struct{})}
	trust := StreamBundleTrust{PolicyDocument: []byte(v.Policy), BundleVerifier: verifier, TrustedCheckpointStore: store,
		Now: func() time.Time { return time.Unix(v.Trust.Now, 0) }, MaxBundleLifetime: time.Duration(v.Trust.MaxBundleLifetime) * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := VerifyStreamBundle(ctx, []byte(v.Bundle), trust); done <- err }()
	<-store.staged
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(store.resume)
	if got, err := store.Load("log.example"); err != nil || got != nil {
		t.Fatal("canceled bundle published")
	}
}

func TestVerifyStreamBundle_IndeterminatePublicationRequiresReconciliation(t *testing.T) {
	v := loadStreamBundleVector(t)
	verifier, err := note.NewVerifier(v.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	base := NewMemoryTrustedC2spCheckpointStore()
	cause := errors.New("acknowledgment lost after publication")
	store := &indeterminateCheckpointStore{TrustedC2spCheckpointStore: base, cause: cause}
	trust := StreamBundleTrust{PolicyDocument: []byte(v.Policy), BundleVerifier: verifier, TrustedCheckpointStore: store,
		Now: func() time.Time { return time.Unix(v.Trust.Now, 0) }, MaxBundleLifetime: time.Duration(v.Trust.MaxBundleLifetime) * time.Millisecond}
	_, err = VerifyStreamBundle(context.Background(), []byte(v.Bundle), trust)
	checkpointCode(t, err, dnsid.VerificationCodeCheckpointStore, false)
	if !errors.Is(err, cause) || store.writes != 1 {
		t.Fatal("lost failure or retried uncertain write", err)
	}
	stored, err := base.Load("log.example")
	if err != nil || stored == nil || stored.TreeSize != 2 {
		t.Fatalf("published state not available for reconciliation: %v %v", stored, err)
	}
	// A subsequent invocation must inspect actual state, not the pre-write baseline.
	if _, err := VerifyStreamBundle(context.Background(), []byte(v.Bundle), trust); err != nil {
		t.Fatal(err)
	}
	if store.writes != 1 {
		t.Fatal("repeated reconciled write")
	}
}
