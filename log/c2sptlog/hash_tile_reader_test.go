package c2sptlog

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	formatlog "github.com/transparency-dev/formats/log"
	"golang.org/x/mod/sumdb/note"
)

type tileProofSource struct {
	*ScanSource
	calls  int
	hashes [][]byte
	err    error
}

func (s *tileProofSource) FetchConsistencyProof(context.Context, Reference, uint64, uint64) ([][]byte, error) {
	s.calls++
	return s.hashes, s.err
}

func TestCheckpointReader_ReusesVerifiedScanBeforeExplicitProof(t *testing.T) {
	raw := [][]byte{[]byte(`{"not":"dnsid"}`), []byte(issuanceEntry)}
	policy, resources := scanFixture(t, raw)
	checkpointTime := time.Unix(1782259201, 0).UTC()
	policy.CheckpointTime = func(*formatlog.Checkpoint, *note.Note) (time.Time, error) { return checkpointTime, nil }
	policy.Now = func() time.Time { return checkpointTime }
	policy.MaxCheckpointAge = time.Hour
	for _, mode := range []string{"history", "preloaded", "non-revocation"} {
		t.Run(mode, func(t *testing.T) {
			var reads []string
			scan, err := NewScanSource(policy, ScanSourceConfig{ResourceFetcher: &testBoundedFetcher{fetch: func(_ context.Context, url string, _ int64) ([]byte, error) {
				path := strings.TrimPrefix(url, "http://dnsid-ledger:8080")
				reads = append(reads, path)
				body, ok := resources[path]
				if !ok {
					t.Fatalf("unexpected resource %s", path)
				}
				return body, nil
			}}})
			if err != nil {
				t.Fatal(err)
			}
			source := &tileProofSource{ScanSource: scan, err: errors.New("must reuse the scan")}
			store := NewMemoryTrustedC2spCheckpointStore()
			ref, _ := ParseReference("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01")
			origin, _ := ref.Origin()
			old := tileCheckpoint(raw[:1])
			old.Origin = origin
			if ok, err := store.CompareAndSwap(origin, nil, old); err != nil || !ok {
				t.Fatal(ok, err)
			}
			client, err := New(ref.String(), WithSource(source), WithPolicy(policy), WithTrustedCheckpointStore(store))
			if err != nil {
				t.Fatal(err)
			}
			// Preloading recognizes the built-in scanner; the explicit proof source
			// is checked separately by the history and non-revocation cases.
			if mode == "preloaded" {
				client.source = scan
			}
			switch mode {
			case "history":
				_, err = client.RebuildHistory(context.Background(), "agent.example")
			case "preloaded":
				reader, loadErr := client.PreloadHistory(context.Background(), "agent.example")
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				_, err = reader.RebuildHistory(context.Background(), "agent.example")
			case "non-revocation":
				_, err = client.VerifyNonRevocation(context.Background(), "agent.example", checkpointTime)
			}
			if err != nil {
				t.Fatal(err)
			}
			if source.calls != 0 || len(reads) != 3 {
				t.Fatalf("proof calls=%d resources=%v", source.calls, reads)
			}
			got, err := store.Load(origin)
			if err != nil || got.TreeSize != 2 {
				t.Fatal(got, err)
			}
		})
	}
}

func TestVerificationRegistry_HashTileAdvancementAndFailureIsolation(t *testing.T) {
	vector := loadStreamBundleVector(t)
	bundle, policy, raw := checkpointReaderFixture(t)
	verifier, err := note.NewVerifier(vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("tile transport failed")
	for _, required := range []bool{false, true} {
		for _, mode := range []string{"tiles", "first", "equal", "empty growth", "tree limit", "trusted root", "bad tile", "short tile", "long tile", "missing partial", "retry succeeds", "retry fails", "transport", "canceled", "proof", "bad proof", "proof unavailable", "proof transport"} {
			t.Run(fmt.Sprintf("required=%v/%s", required, mode), func(t *testing.T) {
				resources := hashTileResources(raw, len(raw))
				partial := fmt.Sprintf("/tile/0/000.p/%d", len(raw))
				if mode == "bad tile" {
					resources[partial][0] ^= 1
				}
				if mode == "short tile" {
					resources[partial] = resources[partial][:31]
				}
				if mode == "long tile" {
					resources[partial] = append(resources[partial], 0)
				}
				if mode == "missing partial" || mode == "retry succeeds" || mode == "retry fails" {
					prefix := resources[partial]
					delete(resources, partial)
					if mode == "retry succeeds" {
						resources["/tile/0/000"] = append(append([]byte(nil), prefix...), make([]byte, (256-len(raw))*32)...)
					}
				}
				var reads []string
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				fetcher := &testBoundedFetcher{fetch: func(ctx context.Context, url string, _ int64) ([]byte, error) {
					path := strings.TrimPrefix(url, bundle.Reference.LogPrefix)
					reads = append(reads, path)
					if strings.HasPrefix(path, "/streams/") {
						return []byte(vector.Bundle), nil
					}
					if strings.Contains(path, "entries") || path == "/checkpoint" {
						t.Fatalf("consistency failure triggered scan: %v", reads)
					}
					if mode == "transport" || mode == "retry fails" && path == "/tile/0/000" {
						return nil, regressionFetchError{cause}
					}
					if mode == "canceled" {
						cancel()
						return nil, ctx.Err()
					}
					if body, ok := resources[path]; ok {
						return body, nil
					}
					return nil, &ResourceFetchError{Kind: ResourceFetchHTTPStatus, HTTPStatus: http.StatusNotFound}
				}}
				store := NewMemoryTrustedC2spCheckpointStore()
				old := tileCheckpoint(raw[:1])
				switch mode {
				case "equal":
					old = tileCheckpoint(raw)
				case "empty growth":
					old = tileCheckpoint(nil)
				case "trusted root":
					old.RootHash[0] ^= 1
				}
				old.Origin = policy.LogVerifier.Name()
				if mode != "first" {
					if ok, err := store.CompareAndSwap(old.Origin, nil, old); err != nil || !ok {
						t.Fatal(ok, err)
					}
				}
				registry, err := NewVerificationRegistry(ctx, VerificationRegistryConfig{
					PolicyDocument: []byte(vector.Policy), BundleVerifiers: []note.Verifier{verifier}, ResourceFetcher: fetcher,
					TrustedCheckpointStore: store, RequireStreamBundle: required,
					MaxBundleLifetime: time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
					// This entry-byte cap must not constrain hash tiles.
					ScanSourceConfig: ScanSourceConfig{MaxTotalEntryBytes: 1},
				})
				if err != nil {
					t.Fatal(err)
				}
				client := verificationClient(t, registry, bundle.Reference.String())
				client.policy.Now = policy.Now
				source := client.source.(*fetchedStreamBundleSource)
				source.trust.Now = policy.Now
				var explicit *tileProofSource
				if strings.HasPrefix(mode, "proof") || mode == "bad proof" {
					explicit = &tileProofSource{ScanSource: source.fallback.(*ScanSource), hashes: [][]byte{merkleRoot(raw[1:])}}
					if mode == "bad proof" {
						explicit.hashes = nil
					}
					if mode == "proof unavailable" {
						explicit.err = ErrConsistencyUnavailable
					}
					if mode == "proof transport" {
						explicit.err = regressionFetchError{cause}
					}
					source.fallback = explicit
				}
				if mode == "tree limit" {
					source.trust.MaxTreeSize = 1
				}
				_, err = client.RebuildHistory(ctx, bundle.FQDN)
				success := mode == "tiles" || mode == "retry succeeds" || mode == "proof" || mode == "first" || mode == "equal" || mode == "empty growth"
				if success {
					if err != nil {
						t.Fatal(err)
					}
					got, err := store.Load(old.Origin)
					if err != nil || got.TreeSize != uint64(len(raw)) {
						t.Fatal(got, err)
					}
				} else {
					switch mode {
					case "tree limit":
						if err == nil {
							t.Fatal("accepted oversized candidate")
						}
					case "bad proof", "trusted root":
						checkpointCode(t, err, dnsid.VerificationCodeLogInconsistent, false)
					case "proof unavailable":
						var advance *CheckpointAdvanceError
						if !errors.As(err, &advance) || advance.Kind != CheckpointAdvanceConsistencyUnavailable {
							t.Fatal(err)
						}
					case "transport", "retry fails", "proof transport":
						checkpointCode(t, err, dnsid.VerificationCodeLogError, true)
						if !errors.Is(err, cause) {
							t.Fatal("lost transport cause")
						}
					case "canceled":
						if !errors.Is(err, context.Canceled) {
							t.Fatal(err)
						}
					case "missing partial":
						var fetch *ResourceFetchError
						if !errors.As(err, &fetch) || fetch.HTTPStatus != 404 {
							t.Fatal(err)
						}
					default:
						checkpointCode(t, err, dnsid.VerificationCodeInvalidEvidence, false)
					}
					got, loadErr := store.Load(old.Origin)
					if loadErr != nil || !trustedCheckpointsEqual(*got, old) {
						t.Fatal("failed evidence changed trust")
					}
				}
				if (mode == "first" || mode == "equal" || mode == "empty growth" || mode == "tree limit") && len(reads) != 1 {
					t.Fatalf("unexpected consistency reads: %v", reads)
				}
				if mode == "trusted root" {
					var advance *CheckpointAdvanceError
					if !errors.As(err, &advance) || advance.Origin != old.Origin || advance.OldTreeSize != old.TreeSize || advance.NewTreeSize != uint64(len(raw)) || string(advance.OldRootHash) != string(old.RootHash) || string(advance.NewRootHash) != string(merkleRoot(raw)) {
						t.Fatalf("lost continuity diagnostics: %v", err)
					}
					advance.OldRootHash[0] ^= 1
					got, loadErr := store.Load(old.Origin)
					if loadErr != nil || !trustedCheckpointsEqual(*got, old) {
						t.Fatal("diagnostics mutated trust")
					}
				}
				if explicit != nil && (explicit.calls != 1 || len(reads) != 1) {
					t.Fatalf("proof calls=%d reads=%v", explicit.calls, reads)
				}
			})
		}
	}
}

type tileRaceStore struct {
	TrustedC2spCheckpointStore
	winner TrustedC2spCheckpoint
	calls  int
}

func (s *tileRaceStore) CompareAndSwap(origin string, expected *TrustedC2spCheckpoint, next TrustedC2spCheckpoint) (bool, error) {
	s.calls++
	if s.calls == 1 {
		_, err := s.TrustedC2spCheckpointStore.CompareAndSwap(origin, expected, s.winner)
		return false, err
	}
	return s.TrustedC2spCheckpointStore.CompareAndSwap(origin, expected, next)
}

func TestHashTiles_ReverifyAgainstCASWinner(t *testing.T) {
	entries := hashTileEntries(300)
	for _, conflicting := range []bool{false, true} {
		t.Run(fmt.Sprint(conflicting), func(t *testing.T) {
			var reads []string
			source := tileTestSource(hashTileResources(entries, len(entries)), &reads)
			store := NewMemoryTrustedC2spCheckpointStore()
			old := tileCheckpoint(entries[:1])
			if ok, err := store.CompareAndSwap(old.Origin, nil, old); err != nil || !ok {
				t.Fatal(ok, err)
			}
			winner := tileCheckpoint(entries[:2])
			if conflicting {
				winner.RootHash[0] ^= 1
			}
			race := &tileRaceStore{TrustedC2spCheckpointStore: store, winner: winner}
			client := &Client{source: source, ref: Reference{LogPrefix: "https://log.example"}, checkpointStore: race}
			next := tileCheckpoint(entries)
			err := logVerificationError(client.advanceTrustedCheckpoint(context.Background(), next), false)
			want := next
			if conflicting {
				checkpointCode(t, err, dnsid.VerificationCodeLogInconsistent, false)
				var advance *CheckpointAdvanceError
				if !errors.As(err, &advance) || advance.OldTreeSize != winner.TreeSize {
					t.Fatal("did not check winning state")
				}
				want = winner
			} else if err != nil {
				t.Fatal(err)
			}
			got, loadErr := store.Load(old.Origin)
			if loadErr != nil || !trustedCheckpointsEqual(*got, want) {
				t.Fatal(got, loadErr)
			}
			if len(reads) != 6 {
				t.Fatalf("did not re-read tiles after race: %v", reads)
			}
		})
	}
}

func TestCheckpointPolicy_ValidatesEmptyTreeRoot(t *testing.T) {
	bundle, policy, _ := checkpointReaderFixture(t)
	for _, valid := range []bool{false, true} {
		root := make([]byte, 32)
		if valid {
			root = merkleRoot(nil)
		}
		raw := signTestCheckpoint(policy, fmt.Sprintf("log.example\n0\n%s\n", base64.StdEncoding.EncodeToString(root)))
		_, err := policy.verifyCheckpoint(bundle.Reference, raw)
		if valid {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			checkpointCode(t, err, dnsid.VerificationCodeInvalidEvidence, false)
		}
	}
}
