package gcpkms_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Mode: fake-only (the same local Google/publication fixtures as the registered
// consumer test). This is a separate main module outside the checkout, importing
// only public SDK packages. Local replaces select the current source revision;
// this is consumer-module composition proof, not a published-registry install.
func TestRegisteredGCPExternalConsumerModule(t *testing.T) {
	provider, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(provider, "../.."))
	consumer := t.TempDir()
	// Reuse the existing fixture sources verbatim, rather than maintaining a
	// second cloud/publication harness. Their imports cannot access SDK internals
	// from this unrelated module path. The external runner itself is not copied.
	for _, name := range []string{"provider_test.go", "lifecycle_test.go", "registered_consumer_test.go", "registered_transport_test.go", "go.sum"} {
		data, err := os.ReadFile(filepath.Join(provider, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(consumer, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	mod := fmt.Sprintf(`module example.com/dnsid-gcp-consumer

go 1.26.10

require (
 github.com/dnsid-ai/dnsid-go v0.0.0
 github.com/dnsid-ai/dnsid-go/key/gcp v0.0.0
)

replace github.com/dnsid-ai/dnsid-go => %q
replace github.com/dnsid-ai/dnsid-go/key/gcp => %q
`, root, provider)
	if err := os.WriteFile(filepath.Join(consumer, "go.mod"), []byte(mod), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-mod=mod", "-count=1", "-timeout=75s", "-run=^TestRegisteredGCPConsumer$/^success$", "-v", ".")
	cmd.Dir = consumer
	// Dependency versions come from the selected SDK modules and the existing
	// module cache. No workspace, proxy, credentials, or registry installation.
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=", "DNSID_TEST_GCP_CHILD=")
	output, err := cmd.CombinedOutput()
	t.Logf("external consumer (cwd %s):\n%s", consumer, output)
	if err != nil {
		t.Fatalf("external public-package consumer: %v", err)
	}
}
