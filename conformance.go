package dnsid

const c2spTLogBinding = "profile=1;tlog-checkpoint=https://c2sp.org/tlog-checkpoint@v1.0.0;tlog-tiles=https://c2sp.org/tlog-tiles@v0.1.0;tlog-proof=ab17a74116563005f908b9167e6421cc929a5c2b;tlog-policy=1896a5aea5559b3203d275d0206d872f59348cf5;tlog-witness=https://c2sp.org/tlog-witness@v1.0.0;tlog-cosignature=https://c2sp.org/tlog-cosignature@v1.0.1;tlog-mirror=d0fe789122c75b903bfc1680b0b8b8dc570f0db3;signed-note=https://c2sp.org/signed-note@v1.0.0;dnsid-method=d5a65d06f76eff4db81e50f8767a600d2ca7fc2a"

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
