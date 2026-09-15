package c2sptlog

// Exact C2SP versions and source revisions implemented by this binding.
// Source revisions identify the named specification file in C2SP/C2SP.
const (
	C2SPCheckpointSpecification  = "https://c2sp.org/tlog-checkpoint@v1.0.0"
	C2SPTilesSpecification       = "https://c2sp.org/tlog-tiles@v0.1.0"
	C2SPProofRevision            = "ab17a74116563005f908b9167e6421cc929a5c2b"
	C2SPPolicyRevision           = "1896a5aea5559b3203d275d0206d872f59348cf5"
	C2SPWitnessSpecification     = "https://c2sp.org/tlog-witness@v1.0.0"
	C2SPCosignatureSpecification = "https://c2sp.org/tlog-cosignature@v1.0.1"
	C2SPMirrorRevision           = "d0fe789122c75b903bfc1680b0b8b8dc570f0db3"
	C2SPSignedNoteSpecification  = "https://c2sp.org/signed-note@v1.0.0"
	DNSidEventEnvelopeVersion    = 1
	// DNSidMethodRevision pins the breaking logical-identity contract in dnsid-ietf-spec.
	DNSidMethodRevision = "d5a65d06f76eff4db81e50f8767a600d2ca7fc2a"
)

// SpecificationVersions is a read-only snapshot of the exact standards
// profile implemented by this package. Mutating a returned value cannot alter
// package metadata.
type SpecificationVersions struct {
	Checkpoint    string
	Tiles         string
	Proof         string
	Policy        string
	Witness       string
	Cosignature   string
	Mirror        string
	SignedNote    string
	EventEnvelope int
}

// PinnedSpecificationVersions returns the exact C2SP and DNSid envelope
// versions implemented by this package.
func PinnedSpecificationVersions() SpecificationVersions {
	return SpecificationVersions{
		Checkpoint:    C2SPCheckpointSpecification,
		Tiles:         C2SPTilesSpecification,
		Proof:         C2SPProofRevision,
		Policy:        C2SPPolicyRevision,
		Witness:       C2SPWitnessSpecification,
		Cosignature:   C2SPCosignatureSpecification,
		Mirror:        C2SPMirrorRevision,
		SignedNote:    C2SPSignedNoteSpecification,
		EventEnvelope: DNSidEventEnvelopeVersion,
	}
}
