package c2sptlog

import (
	"fmt"
	"sort"
	"time"

	formatlog "github.com/transparency-dev/formats/log"
	formatnote "github.com/transparency-dev/formats/note"
	formatproof "github.com/transparency-dev/formats/proof"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Policy is the local trust configuration for verifying c2sp-tlog
// checkpoints and inclusion proofs. LogVerifier is required and must match
// the log's signing key; WitnessVerifiers and WitnessQuorum define which
// witness cosignatures are accepted and how many are required (public
// streams require a quorum of at least 1). CheckpointTime, when set,
// overrides the default witness-timestamp rule. Now defaults to time.Now.
// MaxCheckpointAge, when positive, rejects checkpoints whose accepted
// timestamp is older; ClockSkew is the tolerated clock difference for
// witness timestamps. Prefer building a Policy with ParsePolicy from a
// tlog-policy document; the zero Policy rejects all proofs.
type Policy struct {
	LogVerifier       note.Verifier
	WitnessVerifiers  []note.Verifier
	WitnessQuorum     int
	CheckpointTime    func(*formatlog.Checkpoint, *note.Note) (time.Time, error)
	Now               func() time.Time
	MaxCheckpointAge  time.Duration
	ClockSkew         time.Duration
	quorumRule        *checkpointQuorumRule
	trustedPublicKeys [][]byte
	skipProofVerify   bool
}

// VerifiedProof is the accepted result of checkpoint and inclusion-proof
// verification: the proven entry index, the parsed checkpoint and its signed
// note, and the timestamps derived from accepted witness cosignatures
// (CheckpointIntegrationTime adds the policy's clock skew to
// CheckpointWitnessTime).
type VerifiedProof struct {
	Index                     uint64
	Checkpoint                *formatlog.Checkpoint
	CheckpointNote            *note.Note
	CheckpointWitnessTime     time.Time
	CheckpointIntegrationTime time.Time
	CheckpointFreshnessTime   time.Time
	// LogTime is retained for compatibility and equals CheckpointIntegrationTime.
	LogTime time.Time
}

func (p Policy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// VerifyProof verifies rawProof as an inclusion proof for entry in the log
// identified by ref. It parses the proof, verifies the embedded checkpoint's
// log signature, witness quorum, and freshness under the policy, and checks
// the RFC 6962 inclusion path from the entry's leaf hash to the checkpoint
// root. It returns an error if any step fails.
func (p Policy) VerifyProof(ref Reference, entry, rawProof []byte) (*VerifiedProof, error) {
	if p.skipProofVerify {
		return &VerifiedProof{}, nil
	}
	var proof formatproof.TLogProof
	if err := proof.Unmarshal(rawProof); err != nil {
		return nil, fmt.Errorf("dnsid: parsing c2sp-tlog proof: %w", err)
	}
	verified, err := p.verifyCheckpoint(ref, proof.Checkpoint)
	if err != nil {
		return nil, err
	}
	cp := verified.Checkpoint
	if proof.Index >= cp.Size {
		return nil, fmt.Errorf("dnsid: c2sp-tlog proof index %d outside checkpoint size %d", proof.Index, cp.Size)
	}
	var root tlog.Hash
	copy(root[:], cp.Hash)
	leaf := tlog.RecordHash(entry)
	recordProof := make(tlog.RecordProof, len(proof.Hashes))
	for i, hash := range proof.Hashes {
		copy(recordProof[i][:], hash[:])
	}
	if err := tlog.CheckRecord(recordProof, int64(cp.Size), root, int64(proof.Index), leaf); err != nil {
		return nil, fmt.Errorf("dnsid: c2sp-tlog inclusion proof failed: %w", err)
	}
	verified.Index = proof.Index
	return verified, nil
}

func (p Policy) verifyCheckpoint(ref Reference, rawCheckpoint []byte) (*VerifiedProof, error) {
	if p.LogVerifier == nil {
		return nil, fmt.Errorf("dnsid: c2sp-tlog policy missing log verifier")
	}
	if ref.Scope == "public" && p.WitnessQuorum <= 0 {
		return nil, fmt.Errorf("dnsid: public c2sp-tlog policy requires independent witness quorum")
	}
	origin, err := ref.Origin()
	if err != nil {
		return nil, err
	}
	cp, _, checkpointNote, err := formatlog.ParseCheckpoint(rawCheckpoint, origin, p.LogVerifier, p.WitnessVerifiers...)
	if err != nil {
		return nil, fmt.Errorf("dnsid: verifying c2sp-tlog checkpoint: %w", err)
	}
	if len(cp.Hash) != tlog.HashSize {
		return nil, fmt.Errorf("dnsid: c2sp-tlog checkpoint root length %d, want %d", len(cp.Hash), tlog.HashSize)
	}
	witnessTime, err := p.acceptedCheckpointTime(cp, checkpointNote)
	if err != nil {
		return nil, err
	}
	if p.MaxCheckpointAge > 0 {
		if witnessTime.IsZero() {
			return nil, fmt.Errorf("dnsid: c2sp-tlog accepted checkpoint timestamp is required")
		}
		if p.now().Sub(witnessTime) > p.MaxCheckpointAge {
			return nil, fmt.Errorf("dnsid: c2sp-tlog checkpoint is stale")
		}
	}
	integrationTime := witnessTime
	if !integrationTime.IsZero() {
		integrationTime = integrationTime.Add(p.ClockSkew)
	}
	return &VerifiedProof{
		Checkpoint:                cp,
		CheckpointNote:            checkpointNote,
		CheckpointWitnessTime:     witnessTime,
		CheckpointIntegrationTime: integrationTime,
		CheckpointFreshnessTime:   witnessTime,
		LogTime:                   integrationTime,
	}, nil
}

func (p Policy) acceptedCheckpointTime(cp *formatlog.Checkpoint, n *note.Note) (time.Time, error) {
	if p.CheckpointTime != nil {
		return p.CheckpointTime(cp, n)
	}
	if p.quorumRule != nil {
		times, ok := p.quorumRule.evaluate(n)
		if !ok {
			return time.Time{}, fmt.Errorf("dnsid: c2sp-tlog witness quorum not satisfied")
		}
		if len(times) == 0 {
			return time.Time{}, nil
		}
		for _, witnessTime := range times {
			if _, err := p.validateWitnessTime(witnessTime); err != nil {
				return time.Time{}, err
			}
		}
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		acceptedAt := times[0]
		return acceptedAt, nil
	}
	if p.WitnessQuorum <= 0 {
		return time.Time{}, nil
	}
	times := make([]time.Time, 0, len(n.Sigs))
	for _, sig := range n.Sigs {
		if sig.Name == p.LogVerifier.Name() && sig.Hash == p.LogVerifier.KeyHash() {
			continue
		}
		if !isAcceptedWitness(p.WitnessVerifiers, sig) {
			continue
		}
		ts, err := formatnote.CoSigV1Timestamp(sig)
		if err != nil {
			continue
		}
		times = append(times, ts)
	}
	if len(times) < p.WitnessQuorum {
		return time.Time{}, fmt.Errorf("dnsid: c2sp-tlog witness quorum not satisfied")
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	acceptedAt := times[p.WitnessQuorum-1]
	return p.validateWitnessTime(acceptedAt)
}

func (p Policy) validateWitnessTime(acceptedAt time.Time) (time.Time, error) {
	if skew := p.ClockSkew; skew > 0 {
		if acceptedAt.After(p.now().Add(skew)) {
			return time.Time{}, fmt.Errorf("dnsid: c2sp-tlog witness timestamp is in the future")
		}
		return acceptedAt, nil
	}
	if acceptedAt.After(p.now()) {
		return time.Time{}, fmt.Errorf("dnsid: c2sp-tlog witness timestamp is in the future")
	}
	return acceptedAt, nil
}

func (r *checkpointQuorumRule) evaluate(n *note.Note) ([]time.Time, bool) {
	if r.none {
		return nil, true
	}
	if r.verifier != nil {
		for _, sig := range n.Sigs {
			if sig.Name != r.verifier.Name() || sig.Hash != r.verifier.KeyHash() {
				continue
			}
			ts, err := formatnote.CoSigV1Timestamp(sig)
			return []time.Time{ts}, err == nil
		}
		return nil, false
	}
	type result struct {
		times []time.Time
		ok    bool
	}
	results := make([]result, 0, len(r.members))
	for _, member := range r.members {
		times, ok := member.evaluate(n)
		if ok {
			results = append(results, result{times: times, ok: true})
		}
	}
	if len(results) < r.threshold {
		return nil, false
	}
	// Any satisfying threshold subset is acceptable. Use the first successful
	// components in policy order; all their timestamps remain available for the
	// conservative minimum-time calculation.
	var times []time.Time
	for _, result := range results[:r.threshold] {
		times = append(times, result.times...)
	}
	return times, true
}

func isAcceptedWitness(verifiers []note.Verifier, sig note.Signature) bool {
	for _, verifier := range verifiers {
		if verifier != nil && verifier.Name() == sig.Name && verifier.KeyHash() == sig.Hash {
			return true
		}
	}
	return false
}

// LeafHash returns the RFC 6962 leaf hash of exact entry bytes, as used for
// inclusion-proof verification, not logical event identity.
func LeafHash(entry []byte) tlog.Hash {
	return tlog.RecordHash(entry)
}
