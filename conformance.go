package dnsid

const c2spTLogBinding = "profile=1;tlog-checkpoint=https://c2sp.org/tlog-checkpoint@v1.1.0;tlog-tiles=https://c2sp.org/tlog-tiles@v1.0.0;tlog-proof=0fb2b5543ec04c7909dd58f00691c76dbebe4c6a;tlog-policy=9787c327021255dc0c273a7d0e957e420256f5f8;tlog-witness=https://c2sp.org/tlog-witness@v1.1.0;tlog-cosignature=https://c2sp.org/tlog-cosignature@v1.1.0;tlog-mirror=https://c2sp.org/tlog-mirror@v0.1.0;signed-note=https://c2sp.org/signed-note@v1.1.0;dnsid-method=972f5f19222e0a55e3ee8f8be28dd087764c144e"

// SDKConformanceMetadata describes the exact protocol behavior and log-binding
// revisions implemented by this SDK release.
type SDKConformanceMetadata struct {
	PublishProfile       string            `json:"publishProfile"`
	VerificationProfiles map[string]string `json:"verificationProfiles"`
	SpecificationStatus  string            `json:"specificationStatus"`
	LogBindings          map[string]string `json:"logBindings"`
	KnownDeviations      []string          `json:"knownDeviations"`
}

// SDKConformance returns an immutable snapshot of this release's protocol
// conformance metadata. Callers may mutate the returned maps and slice without
// changing future snapshots.
func SDKConformance() SDKConformanceMetadata {
	return SDKConformanceMetadata{
		PublishProfile: DefaultPublishProfile,
		VerificationProfiles: map[string]string{
			identityRecordDraft01: identityRecordDraft01,
			identityRecordDNSid1:  identityRecordDraft01,
		},
		SpecificationStatus: "internet-draft",
		LogBindings: map[string]string{
			"c2sp-tlog": c2spTLogBinding,
		},
		KnownDeviations: []string{},
	}
}
