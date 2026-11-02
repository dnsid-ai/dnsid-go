package c2sptlog

// Exact C2SP versions and source revisions implemented by this binding.
// Source revisions identify the named specification file in C2SP/C2SP.
const (
	C2SPCheckpointSpecification  = "https://c2sp.org/tlog-checkpoint@v1.1.0"
	C2SPTilesSpecification       = "https://c2sp.org/tlog-tiles@v1.0.0"
	C2SPProofRevision            = "0fb2b5543ec04c7909dd58f00691c76dbebe4c6a"
	C2SPPolicyRevision           = "9787c327021255dc0c273a7d0e957e420256f5f8"
	C2SPWitnessSpecification     = "https://c2sp.org/tlog-witness@v1.1.0"
	C2SPCosignatureSpecification = "https://c2sp.org/tlog-cosignature@v1.1.0"
	C2SPMirrorSpecification      = "https://c2sp.org/tlog-mirror@v0.1.0"
	C2SPSignedNoteSpecification  = "https://c2sp.org/signed-note@v1.1.0"
	DNSidEventEnvelopeVersion    = 1
	// DNSidMethodRevision pins the breaking logical-identity contract in dnsid-ietf-spec.
	DNSidMethodRevision = "972f5f19222e0a55e3ee8f8be28dd087764c144e"
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
		Mirror:        C2SPMirrorSpecification,
		SignedNote:    C2SPSignedNoteSpecification,
		EventEnvelope: DNSidEventEnvelopeVersion,
	}
}
