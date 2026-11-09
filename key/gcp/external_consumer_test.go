package gcpkms_test

import (
	"context"
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
	for _, name := range []string{"provider_test.go", "lifecycle_test.go", "registered_consumer_test.go", "registered_transport_test.go", "go.mod", "go.sum"} {
		data, err := os.ReadFile(filepath.Join(provider, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(consumer, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// Start with the provider's complete pruned module graph, not just two
	// top-level requirements. Otherwise loading the dependency graph can need
	// superseded transitive go.mod files (for example logr v1.2.2 through stdr)
	// that a clean SDK build never downloads. Keep both local replacements:
	// replace directives in a dependency's go.mod are not inherited by consumers.
	env := append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=", "DNSID_TEST_GCP_CHILD=")
	edit := exec.CommandContext(ctx, "go", "mod", "edit",
		"-module=example.com/dnsid-gcp-consumer",
		"-require=github.com/dnsid-ai/dnsid-go/key/gcp@v0.0.0",
		"-replace=github.com/dnsid-ai/dnsid-go="+root,
		"-replace=github.com/dnsid-ai/dnsid-go/key/gcp="+provider)
	edit.Dir, edit.Env = consumer, env
	if output, err := edit.CombinedOutput(); err != nil {
		t.Fatalf("external consumer module setup: %v\n%s", err, output)
	}
	cmd := exec.CommandContext(ctx, "go", "test", "-mod=readonly", "-count=1", "-timeout=75s", "-run=^TestRegisteredGCPConsumer$/^success$", "-v", ".")
	cmd.Dir, cmd.Env = consumer, env

	output, err := cmd.CombinedOutput()
	t.Logf("external consumer (cwd %s):\n%s", consumer, output)
	if err != nil {
		t.Fatalf("external public-package consumer: %v", err)
	}
}
