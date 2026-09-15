package c2sptlog

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	formatlog "github.com/transparency-dev/formats/log"
	"golang.org/x/mod/sumdb/note"
)

func TestScanSourceRebuildsSelectedHistoryFromAuthenticatedGlobalScan(t *testing.T) {
	entries := [][]byte{[]byte(`{"not":"dnsid"}`), []byte(issuanceEntry)}
	policy, resources := scanFixture(t, entries)
	httpClient := scanHTTPClient(resources)
	source, err := NewScanSource(policy, ScanSourceConfig{
		Transport:   httpClient.Transport,
		MaxTreeSize: 10,
	})
	if err != nil {
		t.Fatalf("newScanSource: %v", err)
	}
	client, err := New(
		"c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01",
		WithSource(source),
		WithPolicy(policy),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	history, err := client.RebuildHistory(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("RebuildHistory: %v", err)
	}
	if len(history) != 1 || history[0].Type != dnsidlog.LogEventIssuance {
		t.Fatalf("history = %#v, want one ISSUANCE", history)
	}
	complete, err := source.RebuildCompleteHistory(context.Background(), client.ref, "agent.example")
	if err != nil {
		t.Fatalf("RebuildCompleteHistory: %v", err)
	}
	if complete.CompleteThrough != 2 || complete.CompletenessMode != "full-scan" {
		t.Fatalf("complete history evidence = %#v", complete)
	}
	all, err := source.FetchEntriesThrough(context.Background(), client.ref, 2)
	if err != nil {
		t.Fatalf("FetchEntriesThrough: %v", err)
	}
	if len(all) != 2 || !bytes.Equal(all[1], []byte(issuanceEntry)) {
		t.Fatalf("complete entries = %#v", all)
	}
	prefix, err := source.FetchEntriesThrough(context.Background(), client.ref, 1)
	if err != nil || len(prefix) != 1 || !bytes.Equal(prefix[0], entries[0]) {
		t.Fatalf("authenticated prefix = %#v, %v", prefix, err)
	}
}

func TestNewScanSourceRejectsEntryBundleLimitAboveFixedGeometry(t *testing.T) {
	policy, _ := scanFixture(t, [][]byte{[]byte(issuanceEntry)})
	_, err := NewScanSource(policy, ScanSourceConfig{MaxEntryBundleBytes: defaultScanMaxBundleBytes + 1})
	if err == nil || !strings.Contains(err.Error(), "fixed maximum") {
		t.Fatalf("NewScanSource error = %v, want fixed maximum rejection", err)
	}
}

func TestScanSourceFailsTileMismatchAndBounds(t *testing.T) {
	entries := [][]byte{[]byte(issuanceEntry)}
	policy, resources := scanFixture(t, entries)
	resources["/log/tile/0/000.p/1"][0] ^= 0xff
	httpClient := scanHTTPClient(resources)
	source, err := NewScanSource(policy, ScanSourceConfig{Transport: httpClient.Transport})
	if err != nil {
		t.Fatalf("newScanSource: %v", err)
	}
	ref, _ := ParseReference("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01")
	if _, err := source.RebuildHistory(context.Background(), ref, "agent.example"); err == nil || !strings.Contains(err.Error(), "level-zero tile") {
		t.Fatalf("RebuildHistory tile error = %v", err)
	}

	_, resources = scanFixture(t, entries)
	httpClient = scanHTTPClient(resources)
	source, err = NewScanSource(policy, ScanSourceConfig{Transport: httpClient.Transport, MaxCheckpointBytes: 1})
	if err != nil {
		t.Fatalf("newScanSource bounded: %v", err)
	}
	if _, err := source.RebuildHistory(context.Background(), ref, "agent.example"); err == nil || !strings.Contains(err.Error(), "byte maximum") {
		t.Fatalf("RebuildHistory bound error = %v", err)
	}
}

func TestScanSourceNonRevocationUsesOneCompleteCheckpointScan(t *testing.T) {
	entries := [][]byte{[]byte(issuanceEntry), []byte(correctedFixture(legacyRevocationEntry, issuanceEntry, op1JWK, 1))}
	policy, resources := scanFixture(t, entries)
	checkpointTime := time.Unix(1782345601, 0).UTC()
	policy.MaxCheckpointAge = time.Hour
	policy.Now = func() time.Time { return checkpointTime }
	policy.CheckpointTime = func(*formatlog.Checkpoint, *note.Note) (time.Time, error) { return checkpointTime, nil }
	var checkpointFetches atomic.Int32
	httpClient := &http.Client{Transport: scanRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/log/checkpoint" {
			checkpointFetches.Add(1)
		}
		body, ok := resources[req.URL.Path]
		status := http.StatusOK
		if !ok {
			status = http.StatusNotFound
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}
	source, err := NewScanSource(policy, ScanSourceConfig{Transport: httpClient.Transport})
	if err != nil {
		t.Fatalf("newScanSource: %v", err)
	}
	client, err := New(
		"c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01",
		WithSource(source),
		WithPolicy(policy),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.VerifyNonRevocation(context.Background(), "agent.example", time.Unix(1782345600, 0).UTC())
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("VerifyNonRevocation error = %v, want revoked", err)
	}
	if got := checkpointFetches.Load(); got != 1 {
		t.Fatalf("checkpoint fetches = %d, want one exact complete scan", got)
	}
}

func TestScanSourceNonRevocationReturnsCheckpointBoundEvidence(t *testing.T) {
	entries := [][]byte{[]byte(issuanceEntry)}
	policy, resources := scanFixture(t, entries)
	checkpointTime := time.Unix(1782259201, 0).UTC()
	policy.MaxCheckpointAge = time.Hour
	policy.Now = func() time.Time { return checkpointTime }
	policy.CheckpointTime = func(*formatlog.Checkpoint, *note.Note) (time.Time, error) { return checkpointTime, nil }
	httpClient := scanHTTPClient(resources)
	source, err := NewScanSource(policy, ScanSourceConfig{Transport: httpClient.Transport})
	if err != nil {
		t.Fatalf("newScanSource: %v", err)
	}
	client, err := New(
		"c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01",
		WithSource(source),
		WithPolicy(policy),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	evidence, err := client.VerifyNonRevocation(context.Background(), "agent.example", checkpointTime)
	if err != nil {
		t.Fatalf("VerifyNonRevocation: %v", err)
	}
	if evidence.LogReference != "c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01" ||
		evidence.LoggedState != dnsidlog.AgentStateActive ||
		evidence.HistoryStart != "c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01@0" ||
		evidence.HistoryEnd != evidence.HistoryStart ||
		evidence.CompleteThrough != "1" ||
		evidence.CompletenessMode != "full-scan" ||
		len(evidence.Checkpoint) == 0 ||
		!evidence.FreshnessTime.Equal(checkpointTime) {
		t.Fatalf("VerifyNonRevocation evidence = %#v", evidence)
	}
}

func scanFixture(t *testing.T, entries [][]byte) (Policy, map[string][]byte) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, "dnsid-ledger:8080/log")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	checkpoint := formatlog.Checkpoint{Origin: "dnsid-ledger:8080/log", Size: uint64(len(entries)), Hash: merkleRoot(entries)}
	signed, err := note.Sign(&note.Note{Text: string(checkpoint.Marshal())}, signer)
	if err != nil {
		t.Fatalf("Sign checkpoint: %v", err)
	}
	bundle := make([]byte, 0)
	tile := make([]byte, 0, len(entries)*32)
	for _, entry := range entries {
		bundle = append(bundle, byte(len(entry)>>8), byte(len(entry)))
		bundle = append(bundle, entry...)
		leaf := LeafHash(entry)
		tile = append(tile, leaf[:]...)
	}
	width := len(entries)
	return Policy{LogVerifier: verifier}, map[string][]byte{
		"/log/checkpoint":                        signed,
		"/log/tile/entries/000.p/" + itoa(width): bundle,
		"/log/tile/0/000.p/" + itoa(width):       tile,
	}
}

func scanHTTPClient(resources map[string][]byte) *http.Client {
	return &http.Client{Transport: scanRoundTripper(func(req *http.Request) (*http.Response, error) {
		body, ok := resources[req.URL.Path]
		status := http.StatusOK
		if !ok {
			status = http.StatusNotFound
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}
}

type scanRoundTripper func(*http.Request) (*http.Response, error)

func (fn scanRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func itoa(value int) string {
	if value == 1 {
		return "1"
	}
	if value == 2 {
		return "2"
	}
	panic("test fixture width")
}
