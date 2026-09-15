package dnsid

import "runtime/debug"

// modulePath is the canonical import path of this module. Kept as a package
// constant so [Version] can locate this module's entry in the build info of
// any importing binary without a string repeated at every call site.
const modulePath = "github.com/dnsid-ai/dnsid-go"

// Version is the SDK release of this module — distinct from
// [DefaultPublishProfile], which is the exact TXT behavior-profile selector
// emitted by new publications.
//
// When this module is consumed as a tagged dependency (e.g.
// `go get github.com/dnsid-ai/dnsid-go@v0.1.0`), Version reports the
// module version recorded in the importing binary's build info. When the
// module IS the main module (e.g. the `dnsid` CLI built from this repo) and
// was built from a tagged commit, Version reports that tag. In all other
// cases — including `go run` from a working tree — Version reports "dev".
var Version = resolveVersion()

func resolveVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if info.Main.Path == modulePath && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	for _, dep := range info.Deps {
		if dep.Path == modulePath {
			if dep.Replace != nil && dep.Replace.Version != "" {
				return dep.Replace.Version
			}
			if dep.Version != "" {
				return dep.Version
			}
		}
	}
	return "dev"
}
