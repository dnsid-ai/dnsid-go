package c2sptlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	dnsid "github.com/dnsid-ai/dnsid-go"

	"github.com/dnsid-ai/dnsid-go/internal/netguard"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	formatproof "github.com/transparency-dev/formats/proof"
	"golang.org/x/mod/sumdb/tlog"
)

const (
	defaultScanMaxTreeSize        = 1_000_000
	defaultScanMaxCheckpointBytes = 1 << 20
	defaultScanMaxBundleBytes     = entriesPerC2spBundle * (2 + maxEntrySize)
	defaultScanMaxTotalEntryBytes = 256 << 20
	entriesPerC2spBundle          = 256
)

// ScanSourceConfig bounds a standard checkpoint/tile/entry-bundle scan.
// ResourceFetcher is mutually exclusive with HTTPClient and Transport. The
// lower-level Transport option is used verbatim, so its caller owns destination
// safety; NewVerificationRegistry applies the stricter public-read capability
// contract before constructing a scanner.
type ScanSourceConfig struct {
	HTTPClient          *http.Client
	Transport           http.RoundTripper
	ResourceFetcher     BoundedResourceFetcher
	MaxTreeSize         uint64
	MaxCheckpointBytes  int64
	MaxEntryBundleBytes int64
	MaxTotalEntryBytes  int64
}

// ScanSource reads the standard C2SP tiled-log surface and authenticates a
// complete raw-log scan against its signed checkpoint and level-zero tiles.
// Configure the Client with the same Policy passed to NewScanSource.
type ScanSource struct {
	fetcher             BoundedResourceFetcher
	policy              Policy
	maxTreeSize         uint64
	maxCheckpointBytes  int64
	maxEntryBundleBytes int64
	maxTotalEntryBytes  int64
}

var (
	_ GlobalCandidateSource = (*ScanSource)(nil)
	_ CompleteSource        = (*ScanSource)(nil)
	_ C2spFullLogSource     = (*ScanSource)(nil)
)

// NewScanSource constructs a bounded C2SP network scanner. It is SSRF-resistant
// unless the caller supplies a custom Transport.
func NewScanSource(policy Policy, config ScanSourceConfig) (*ScanSource, error) {
	if policy.LogVerifier == nil {
		return nil, fmt.Errorf("dnsid: c2sp-tlog scan policy missing log verifier")
	}
	if config.ResourceFetcher != nil && (config.HTTPClient != nil || config.Transport != nil) {
		return nil, fmt.Errorf("dnsid: c2sp-tlog resource fetcher is mutually exclusive with HTTP client and transport")
	}
	maxTreeSize := config.MaxTreeSize
	if maxTreeSize == 0 {
		maxTreeSize = defaultScanMaxTreeSize
	}
	maxCheckpointBytes := configuredScanLimit(config.MaxCheckpointBytes, defaultScanMaxCheckpointBytes)
	maxEntryBundleBytes := configuredScanLimit(config.MaxEntryBundleBytes, defaultScanMaxBundleBytes)
	maxTotalEntryBytes := configuredScanLimit(config.MaxTotalEntryBytes, defaultScanMaxTotalEntryBytes)
	if maxCheckpointBytes < 1 || maxEntryBundleBytes < 1 || maxTotalEntryBytes < 1 {
		return nil, fmt.Errorf("dnsid: c2sp-tlog scan byte limits must be positive")
	}
	if maxEntryBundleBytes > defaultScanMaxBundleBytes {
		return nil, fmt.Errorf("dnsid: c2sp-tlog entry bundle byte limit exceeds fixed maximum %d", defaultScanMaxBundleBytes)
	}
	fetcher := config.ResourceFetcher
	if fetcher == nil {
		fetcher = &httpBoundedResourceFetcher{client: configuredScanHTTPClient(config)}
	}
	return &ScanSource{
		fetcher:             fetcher,
		policy:              policy,
		maxTreeSize:         maxTreeSize,
		maxCheckpointBytes:  maxCheckpointBytes,
		maxEntryBundleBytes: maxEntryBundleBytes,
		maxTotalEntryBytes:  maxTotalEntryBytes,
	}, nil
}

func configuredScanLimit(value, fallback int64) int64 {
	if value == 0 {
		return fallback
	}
	return value
}

func configuredScanHTTPClient(config ScanSourceConfig) *http.Client {
	client := config.HTTPClient
	if config.Transport == nil {
		return netguard.NewSafeHTTPClientFrom(client)
	}
	if client == nil {
		client = &http.Client{}
	}
	custom := *client
	custom.Transport = config.Transport
	custom.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &custom
}

// GlobalCandidates implements GlobalCandidateSource: scan results are
// unfiltered global-log candidates, so the Client skips invalid or unrelated
// entries instead of failing.
func (*ScanSource) GlobalCandidates() bool { return true }

// ReadEvent implements Source by running a full authenticated scan and
// returning the entry at the reference's index. It returns an error if the
// index is outside the scanned checkpoint size.
func (s *ScanSource) ReadEvent(ctx context.Context, ref dnsidlog.LogRef) (ProvenEntry, error) {
	reference, index, err := ParseFinalEventRef(ref)
	if err != nil {
		return ProvenEntry{}, err
	}
	scan, err := s.scan(ctx, reference)
	if err != nil {
		return ProvenEntry{}, err
	}
	if index >= uint64(len(scan.entries)) {
		return ProvenEntry{}, fmt.Errorf("dnsid: c2sp-tlog entry index %d outside checkpoint size %d", index, len(scan.entries))
	}
	return scan.provenEntry(index), nil
}

// RebuildHistory implements Source by scanning the complete log once,
// authenticating every entry against the signed checkpoint, and returning
// the entries whose fqdn matches domain, each with a derived inclusion
// proof.
func (s *ScanSource) RebuildHistory(ctx context.Context, reference Reference, domain string) ([]ProvenEntry, error) {
	result, err := s.RebuildCompleteHistory(ctx, reference, domain)
	if err != nil {
		return nil, err
	}
	return result.Entries, nil
}

// RebuildCompleteHistory implements CompleteSource by binding the returned
// candidates to the exact authenticated full-scan checkpoint.
func (s *ScanSource) RebuildCompleteHistory(ctx context.Context, reference Reference, domain string) (CompleteHistoryResult, error) {
	scan, err := s.scan(ctx, reference)
	if err != nil {
		return CompleteHistoryResult{}, err
	}
	entries := make([]ProvenEntry, 0)
	for index, entry := range scan.entries {
		if !candidateFQDN(entry, domain) {
			continue
		}
		entries = append(entries, scan.provenEntry(uint64(index)))
	}
	return CompleteHistoryResult{
		Entries:          entries,
		Checkpoint:       append([]byte(nil), scan.checkpoint...),
		CompleteThrough:  scan.verified.Checkpoint.Size,
		CompletenessMode: "full-scan",
		FreshnessTime:    scan.verified.CheckpointFreshnessTime,
	}, nil
}

// FetchEntriesThrough implements C2spFullLogSource by returning the requested
// prefix from a fresh authenticated scan. The scan may have advanced beyond
// treeSize; its authenticated entries still independently prove the requested
// checkpoint prefix.
func (s *ScanSource) FetchEntriesThrough(ctx context.Context, reference Reference, treeSize uint64) ([][]byte, error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	scan, err := s.scan(ctx, reference)
	if err != nil {
		return nil, err
	}
	if uint64(len(scan.entries)) < treeSize {
		return nil, fmt.Errorf("dnsid: c2sp-tlog complete scan ended at size %d before requested checkpoint size %d", len(scan.entries), treeSize)
	}
	return cloneEntries(scan.entries[:treeSize]), nil
}

type completeScan struct {
	checkpoint []byte
	verified   *VerifiedProof
	entries    [][]byte
	levels     [][]tlog.Hash
}

func (s *ScanSource) scan(ctx context.Context, reference Reference) (*completeScan, error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	if s == nil || s.fetcher == nil {
		return nil, fmt.Errorf("dnsid: c2sp-tlog scan source is required")
	}
	if err := reference.Validate(); err != nil {
		return nil, err
	}
	checkpoint, err := s.fetch(ctx, reference.LogPrefix+"/checkpoint", s.maxCheckpointBytes)
	if err != nil {
		return nil, err
	}
	verified, err := s.policy.verifyCheckpoint(reference, checkpoint)
	if err != nil {
		return nil, err
	}
	treeSize := verified.Checkpoint.Size
	if treeSize > s.maxTreeSize {
		return nil, fmt.Errorf("dnsid: c2sp-tlog checkpoint tree size %d exceeds configured maximum %d", treeSize, s.maxTreeSize)
	}

	entries := make([][]byte, 0, int(treeSize))
	var totalEntryBytes int64
	for bundle := uint64(0); uint64(len(entries)) < treeSize; bundle++ {
		width := uint64(entriesPerC2spBundle)
		if remaining := treeSize - uint64(len(entries)); remaining < width {
			width = remaining
		}
		suffix := tileNumber(bundle)
		if width < entriesPerC2spBundle {
			suffix += ".p/" + strconv.FormatUint(width, 10)
		}
		bundleBytes, err := s.fetch(ctx, reference.LogPrefix+"/tile/entries/"+suffix, s.maxEntryBundleBytes)
		if err != nil {
			return nil, err
		}
		totalEntryBytes += int64(len(bundleBytes))
		if totalEntryBytes > s.maxTotalEntryBytes {
			return nil, fmt.Errorf("dnsid: c2sp-tlog entry bundles exceed configured total byte maximum %d", s.maxTotalEntryBytes)
		}
		decoded, err := parseEntryBundle(bundleBytes)
		if err != nil {
			return nil, err
		}
		if uint64(len(decoded)) != width {
			return nil, fmt.Errorf("dnsid: c2sp-tlog entry bundle width %d, want %d", len(decoded), width)
		}
		tile, err := s.fetch(ctx, reference.LogPrefix+"/tile/0/"+suffix, int64(width)*tlog.HashSize)
		if err != nil {
			return nil, err
		}
		if len(tile) != int(width)*tlog.HashSize {
			return nil, fmt.Errorf("dnsid: c2sp-tlog level-zero tile length %d, want %d", len(tile), int(width)*tlog.HashSize)
		}
		for i, entry := range decoded {
			leaf := tlog.RecordHash(entry)
			if !bytes.Equal(tile[i*tlog.HashSize:(i+1)*tlog.HashSize], leaf[:]) {
				return nil, fmt.Errorf("dnsid: c2sp-tlog entry bundle does not match level-zero tile")
			}
			entries = append(entries, entry)
		}
	}
	levels := merkleLevels(entries)
	root := levels[len(levels)-1][0]
	if !bytes.Equal(root[:], verified.Checkpoint.Hash) {
		return nil, fmt.Errorf("dnsid: complete c2sp-tlog scan does not match checkpoint root")
	}
	return &completeScan{checkpoint: checkpoint, verified: verified, entries: entries, levels: levels}, nil
}

func (s *ScanSource) fetch(ctx context.Context, rawURL string, maximum int64) ([]byte, error) {
	return fetchBounded(s.fetcher, ctx, rawURL, maximum)
}

func (s *completeScan) provenEntry(index uint64) ProvenEntry {
	hashes := make([][tlog.HashSize]byte, 0, len(s.levels)-1)
	position := index
	for _, level := range s.levels[:len(s.levels)-1] {
		if position%2 == 1 {
			hashes = append(hashes, level[position-1])
		} else if position+1 < uint64(len(level)) {
			hashes = append(hashes, level[position+1])
		}
		position /= 2
	}
	proof := formatproof.TLogProof{Index: index, Hashes: hashes, Checkpoint: s.checkpoint}.Marshal()
	return ProvenEntry{Index: index, Entry: append([]byte(nil), s.entries[index]...), Proof: proof}
}

func merkleLevels(entries [][]byte) [][]tlog.Hash {
	level := make([]tlog.Hash, len(entries))
	for i, entry := range entries {
		level[i] = tlog.RecordHash(entry)
	}
	levels := [][]tlog.Hash{level}
	if len(level) == 0 {
		empty := tlog.Hash{}
		copy(empty[:], merkleRoot(nil))
		return append(levels, []tlog.Hash{empty})
	}
	for len(level) > 1 {
		next := make([]tlog.Hash, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			input := make([]byte, 1, 1+2*tlog.HashSize)
			input[0] = 1
			input = append(input, level[i][:]...)
			input = append(input, level[i+1][:]...)
			hash := sha256.Sum256(input)
			next = append(next, tlog.Hash(hash))
		}
		level = next
		levels = append(levels, level)
	}
	return levels
}

func candidateFQDN(entry []byte, domain string) bool {
	payload, err := payloadObjectFromEntry(entry)
	if err != nil {
		return false
	}
	fqdn, ok := payload["fqdn"].(string)
	return ok && strings.EqualFold(fqdn, domain)
}

func parseEntryBundle(data []byte) ([][]byte, error) {
	entries := make([][]byte, 0)
	for offset := 0; offset < len(data); {
		if offset+2 > len(data) {
			return nil, fmt.Errorf("dnsid: truncated c2sp-tlog entry bundle length")
		}
		length := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+length > len(data) {
			return nil, fmt.Errorf("dnsid: truncated c2sp-tlog entry bundle entry")
		}
		entries = append(entries, append([]byte(nil), data[offset:offset+length]...))
		offset += length
	}
	return entries, nil
}

func tileNumber(number uint64) string {
	digits := strconv.FormatUint(number, 10)
	if remainder := len(digits) % 3; remainder != 0 {
		digits = strings.Repeat("0", 3-remainder) + digits
	}
	groups := make([]string, 0, len(digits)/3)
	for offset := 0; offset < len(digits); offset += 3 {
		group := digits[offset : offset+3]
		if offset+3 < len(digits) {
			group = "x" + group
		}
		groups = append(groups, group)
	}
	return strings.Join(groups, "/")
}

func cloneEntries(entries [][]byte) [][]byte {
	clone := make([][]byte, len(entries))
	for i, entry := range entries {
		clone[i] = append([]byte(nil), entry...)
	}
	return clone
}
