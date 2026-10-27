package c2sptlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"golang.org/x/mod/sumdb/tlog"
)

func hashTileEntries(n int) [][]byte {
	entries := make([][]byte, n)
	for i := range entries {
		entries[i] = []byte(strconv.Itoa(i))
	}
	return entries
}

// Build resources independently from the reader, using the in-memory RFC 6962 tree.
func hashTileResources(entries [][]byte, n int) map[string][]byte {
	levels := merkleLevels(entries)
	resources := make(map[string][]byte)
	for level, width := 0, n; width > 0; level, width = level+1, width/256 {
		for start := 0; start < width; start += 256 {
			end := min(start+256, width)
			path := fmt.Sprintf("/tile/%d/%s", level, tileNumber(uint64(start/256)))
			if end-start < 256 {
				path += fmt.Sprintf(".p/%d", end-start)
			}
			for _, hash := range levels[level*8][start:end] {
				resources[path] = append(resources[path], hash[:]...)
			}
		}
	}
	return resources
}

func tileCheckpoint(entries [][]byte) TrustedC2spCheckpoint {
	return TrustedC2spCheckpoint{Origin: "log.example", TreeSize: uint64(len(entries)), RootHash: merkleRoot(entries), WitnessTime: time.Unix(1, 0)}
}

func tileTestSource(resources map[string][]byte, reads *[]string) *ScanSource {
	return &ScanSource{maxTreeSize: defaultScanMaxTreeSize, fetcher: &testBoundedFetcher{fetch: func(ctx context.Context, url string, _ int64) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := strings.TrimPrefix(url, "https://log.example")
		*reads = append(*reads, path)
		if body, ok := resources[path]; ok {
			return append([]byte(nil), body...), nil
		}
		return nil, &ResourceFetchError{Kind: ResourceFetchHTTPStatus, HTTPStatus: http.StatusNotFound, URL: url}
	}}}
}

func TestHashTiles_RootsAndPerLevelBounds(t *testing.T) {
	entries := hashTileEntries(400000)
	rng := rand.New(rand.NewPCG(1, 2))
	sizes := []int{2, 3, 7, 8, 9, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 65535, 65536, 65537, 70000, 131071, 131072, 131073, 400000}
	for range 12 {
		sizes = append(sizes, 2+rng.IntN(len(entries)-2))
	}
	for _, n := range sizes {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			resources := hashTileResources(entries, n)
			next := tileCheckpoint(entries[:n])
			ms := []int{1, n - 1, n / 2}
			for _, m := range []int{2, 3, 7, 8, 9, 255, 256, 257, 511, 512, 513, 65535, 65536, 65537, 300} {
				if m < n {
					ms = append(ms, m)
				}
			}
			for range 5 {
				ms = append(ms, 1+rng.IntN(n-1))
			}
			for _, m := range ms {
				var reads []string
				source := tileTestSource(resources, &reads)
				old := tileCheckpoint(entries[:m])
				if err := source.verifyTileConsistency(context.Background(), Reference{LogPrefix: "https://log.example"}, old, next); err != nil {
					t.Fatalf("m=%d n=%d: %v", m, n, err)
				}
				counts := map[string]int{}
				for _, path := range reads {
					counts[strings.Split(path, "/")[2]]++
				}
				for level, count := range counts {
					if count > 2 {
						t.Fatalf("m=%d n=%d level=%s reads=%v", m, n, level, reads)
					}
				}
				if m == 300 && n == 70000 && len(reads) != 5 {
					t.Fatalf("m=300 n=70000 reads=%v; want exactly 5", reads)
				}
			}
		})
	}
}

func TestHashTiles_AuthenticationPrecedesTrustedRootComparison(t *testing.T) {
	entries := hashTileEntries(70000)
	next := tileCheckpoint(entries)
	for _, m := range []int{1, 2, 256, 300, 65536} {
		t.Run(strconv.Itoa(m), func(t *testing.T) {
			old := tileCheckpoint(entries[:m])
			old.RootHash[0] ^= 1
			var reads []string
			source := tileTestSource(hashTileResources(entries, len(entries)), &reads)
			err := logVerificationError(source.verifyTileConsistency(context.Background(), Reference{LogPrefix: "https://log.example"}, old, next), false)
			checkpointCode(t, err, dnsid.VerificationCodeLogInconsistent, false)
		})
	}
	for _, path := range []string{"/tile/0/273.p/112", "/tile/1/001.p/17", "/tile/2/000.p/1", "/tile/0/001", "/tile/1/000"} {
		for _, badTrust := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/badTrust=%v", path, badTrust), func(t *testing.T) {
				resources := hashTileResources(entries, len(entries))
				offset := 0
				if path == "/tile/0/001" {
					offset = 200 * tlog.HashSize
				} // Outside the trusted prefix.
				resources[path][offset] ^= 1
				var reads []string
				source := tileTestSource(resources, &reads)
				old := tileCheckpoint(entries[:300])
				if badTrust {
					old.RootHash[0] ^= 1
				}
				err := source.verifyTileConsistency(context.Background(), Reference{LogPrefix: "https://log.example"}, old, next)
				checkpointCode(t, err, dnsid.VerificationCodeInvalidEvidence, false)
			})
		}
	}
}

func TestHashTiles_PartialRecoveryAndExactWidths(t *testing.T) {
	entries := hashTileEntries(512)
	for _, mode := range []string{"recover", "missing full", "short partial", "long partial", "short full", "long full", "retry transport", "retry canceled", "retry deadline"} {
		t.Run(mode, func(t *testing.T) {
			resources := hashTileResources(entries, 300)
			full := hashTileResources(entries, 512)["/tile/0/001"]
			partial := "/tile/0/001.p/44"
			if mode == "short partial" {
				resources[partial] = resources[partial][:31]
			} else if mode == "long partial" {
				resources[partial] = append(resources[partial], 0)
			} else {
				delete(resources, partial)
				if mode != "missing full" {
					resources["/tile/0/001"] = full
				}
			}
			if mode == "short full" {
				resources["/tile/0/001"] = full[:len(full)-1]
			}
			if mode == "long full" {
				resources["/tile/0/001"] = append(full, 0)
			}
			var reads []string
			source := tileTestSource(resources, &reads)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "retry deadline" {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer deadlineCancel()
			}
			cause := errors.New("connection interrupted")
			original := source.fetcher
			source.fetcher = &testBoundedFetcher{fetch: func(ctx context.Context, url string, max int64) ([]byte, error) {
				if strings.HasSuffix(url, "/tile/0/001") {
					switch mode {
					case "retry transport":
						return nil, regressionFetchError{cause}
					case "retry canceled":
						cancel()
						return nil, context.Canceled
					case "retry deadline":
						<-ctx.Done()
						return nil, ctx.Err()
					}
				}
				return original.FetchBounded(ctx, url, max)
			}}
			err := source.verifyTileConsistency(ctx, Reference{LogPrefix: "https://log.example"}, tileCheckpoint(entries[:1]), tileCheckpoint(entries[:300]))
			switch mode {
			case "recover":
				if err != nil {
					t.Fatal(err)
				}
				if len(reads) != 4 {
					t.Fatalf("reads=%v", reads)
				}
			case "missing full":
				var fetch *ResourceFetchError
				if !errors.As(err, &fetch) || fetch.HTTPStatus != 404 {
					t.Fatalf("error=%v", err)
				}
			case "retry transport":
				checkpointCode(t, err, dnsid.VerificationCodeLogError, true)
				if !errors.Is(err, cause) {
					t.Fatal("lost cause")
				}
			case "retry canceled":
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case "retry deadline":
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			default:
				checkpointCode(t, err, dnsid.VerificationCodeInvalidEvidence, false)
			}
			for _, path := range reads {
				if strings.Contains(path, "entries") || path == "/checkpoint" {
					t.Fatalf("unexpected scan: %v", reads)
				}
			}
		})
	}
}

func TestHashTiles_EmptyAndRepeatedCheckpointsNeedNoEvidence(t *testing.T) {
	entries := hashTileEntries(2)
	for _, mode := range []string{"first", "equal", "empty growth", "bad candidate", "bad stored"} {
		t.Run(mode, func(t *testing.T) {
			var reads []string
			source := tileTestSource(nil, &reads)
			store := NewMemoryTrustedC2spCheckpointStore()
			next := tileCheckpoint(entries)
			switch mode {
			case "equal":
				store.CompareAndSwap(next.Origin, nil, next)
			case "empty growth":
				empty := tileCheckpoint(nil)
				store.CompareAndSwap(empty.Origin, nil, empty)
			case "bad candidate":
				next.TreeSize = 0
			case "bad stored":
				bad := tileCheckpoint(entries)
				bad.TreeSize = 0
				store.checkpoints[bad.Origin] = bad
			}
			client := &Client{source: source, checkpointStore: store}
			err := client.advanceTrustedCheckpoint(context.Background(), next)
			if mode == "bad candidate" {
				checkpointCode(t, err, dnsid.VerificationCodeInvalidEvidence, false)
			} else if mode == "bad stored" {
				checkpointCode(t, err, dnsid.VerificationCodeCheckpointStore, false)
			} else if err != nil {
				t.Fatal(err)
			}
			if len(reads) != 0 {
				t.Fatalf("unexpected reads: %v", reads)
			}
			if mode == "bad candidate" {
				if stored, _ := store.Load(next.Origin); stored != nil {
					t.Fatal("bad candidate published")
				}
			}
		})
	}
	bad := tileCheckpoint(entries)
	bad.TreeSize = 0
	if ok, err := NewMemoryTrustedC2spCheckpointStore().CompareAndSwap(bad.Origin, nil, bad); err == nil || ok {
		t.Fatal("store accepted malformed empty tree")
	}
}

func TestHashTiles_TreeLimitAndBudget(t *testing.T) {
	entries := hashTileEntries(300)
	for _, mode := range []string{"tree limit", "canceled", "budget"} {
		t.Run(mode, func(t *testing.T) {
			var reads []string
			source := tileTestSource(hashTileResources(entries, len(entries)), &reads)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "tree limit" {
				source.maxTreeSize = 299
			} else {
				if mode == "budget" {
					var deadlineCancel context.CancelFunc
					ctx, deadlineCancel = context.WithTimeout(ctx, 10*time.Millisecond)
					defer deadlineCancel()
				}
				source.fetcher = &testBoundedFetcher{fetch: func(ctx context.Context, _ string, _ int64) ([]byte, error) {
					if mode == "canceled" {
						cancel()
					}
					<-ctx.Done()
					return nil, ctx.Err()
				}}
			}
			store := NewMemoryTrustedC2spCheckpointStore()
			old := tileCheckpoint(entries[:1])
			store.CompareAndSwap(old.Origin, nil, old)
			client := &Client{source: source, ref: Reference{LogPrefix: "https://log.example"}, checkpointStore: store}
			err := client.advanceTrustedCheckpoint(ctx, tileCheckpoint(entries))
			if mode == "tree limit" {
				checkpointCode(t, err, dnsid.VerificationCodeInvalidEvidence, false)
			} else if mode == "budget" {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			} else if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			got, loadErr := store.Load(old.Origin)
			if loadErr != nil || !trustedCheckpointsEqual(*got, old) {
				t.Fatal("failure changed trust")
			}
		})
	}
}

func TestHashTiles_IndexEncoding(t *testing.T) {
	for index, want := range map[uint64]string{0: "000", 1234: "x001/234", 1234067: "x001/x234/067"} {
		if got := tileNumber(index); got != want {
			t.Fatalf("tileNumber(%d)=%s, want %s", index, got, want)
		}
	}
	entries := hashTileEntries(400000)
	var reads []string
	source := tileTestSource(hashTileResources(entries, len(entries)), &reads)
	err := source.verifyTileConsistency(context.Background(), Reference{LogPrefix: "https://log.example"}, tileCheckpoint(entries[:1234*256+1]), tileCheckpoint(entries))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range reads {
		if path == "/tile/0/x001/234" {
			return
		}
	}
	t.Fatalf("missing encoded tile path: %v", reads)
}

func TestHashTileRoot_MatchesRFC6962(t *testing.T) {
	entries := hashTileEntries(257)
	for n := 1; n <= 256; n++ {
		hashes := make([]tlog.Hash, n)
		for i := range hashes {
			hashes[i] = tlog.RecordHash(entries[i])
		}
		root := hashTileRoot(hashes)
		if !bytes.Equal(root[:], merkleRoot(entries[:n])) {
			t.Fatalf("n=%d", n)
		}
	}
}
