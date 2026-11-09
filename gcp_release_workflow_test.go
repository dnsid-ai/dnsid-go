package dnsid_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These internal CI guards exercise release scripts, not a new SDK actor contract.
// Mode: fake-only (throwaway Git repository, local bare remote, fake git-cliff).
func releaseScript(t *testing.T, path, step string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	found, run := false, false
	var script []string
	for _, line := range lines {
		if strings.TrimSpace(line) == "- name: "+step {
			found = true
			continue
		}
		if found && !run && strings.TrimSpace(line) == "run: |" {
			run = true
			continue
		}
		if run {
			if strings.HasPrefix(line, "          ") {
				script = append(script, strings.TrimPrefix(line, "          "))
			} else if strings.TrimSpace(line) == "" {
				script = append(script, "")
			} else {
				break
			}
		}
	}
	if len(script) == 0 {
		t.Fatalf("no executable script found for %q in %s", step, path)
	}
	return strings.Join(script, "\n")
}
func releaseRun(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return string(out)
}
func releaseRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	remote := filepath.Join(t.TempDir(), "origin.git")
	releaseRun(t, dir, nil, "git", "init", "--bare", remote)
	releaseRun(t, dir, nil, "git", "init")
	releaseRun(t, dir, nil, "git", "config", "user.name", "Release Fixture")
	releaseRun(t, dir, nil, "git", "config", "user.email", "fixture@example.invalid")
	releaseRun(t, dir, nil, "git", "config", "commit.gpgsign", "false")
	releaseRun(t, dir, nil, "git", "config", "tag.gpgsign", "false")
	releaseRun(t, dir, nil, "git", "commit", "--allow-empty", "-m", "fixture")
	releaseRun(t, dir, nil, "git", "remote", "add", "origin", remote)
	return dir, remote
}

// Given a new release, When the workflow tags it, Then all nested module tags
// are pushed with the root tag; a partial GCP-only release must be rejected.
func TestGCPReleaseTagsIncludeOptionalModule(t *testing.T) {
	script := releaseScript(t, ".github/workflows/release.yml", "Tag release")
	// Atomic publication is an existing release convention: keep all module
	// tags in the single atomic push exercised below.
	atomicPushes := 0
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, " push ") {
			if !strings.Contains(line, "--atomic") {
				t.Error("release tag push must remain atomic")
			}
			atomicPushes++
		}
	}
	if atomicPushes != 1 {
		t.Errorf("release must publish tags with one atomic push, got %d pushes", atomicPushes)
	}
	t.Run("all modules published", func(t *testing.T) {
		dir, remote := releaseRepo(t)
		releaseRun(t, dir, []string{"VERSION=v9.9.9", "GH_TOKEN=unused"}, "bash", "-e", "-c", script)
		for _, tag := range []string{"v9.9.9", "key/aws/v9.9.9", "key/gcp/v9.9.9"} {
			cmd := exec.Command("git", "--git-dir="+remote, "show-ref", "--verify", "refs/tags/"+tag)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("release omitted module tag %q: %v\n%s", tag, err, out)
			}
		}
	})
	tags := []string{"v9.9.9", "key/aws/v9.9.9", "key/gcp/v9.9.9"}
	for mask := 1; mask < 7; mask++ {
		t.Run(fmt.Sprintf("partial_subset_%d_rejected", mask), func(t *testing.T) {
			dir, _ := releaseRepo(t)
			for i, tag := range tags {
				if mask&(1<<i) != 0 {
					releaseRun(t, dir, nil, "git", "tag", tag)
				}
			}
			cmd := exec.Command("bash", "-e", "-c", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "VERSION=v9.9.9", "GH_TOKEN=unused")
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("partial release was accepted:\n%s", out)
			}
			for i, tag := range tags {
				if mask&(1<<i) == 0 {
					cmd := exec.Command("git", "show-ref", "--verify", "refs/tags/"+tag)
					cmd.Dir = dir
					if cmd.Run() == nil {
						t.Errorf("partial release unexpectedly created %q", tag)
					}
				}
			}
		})
	}

}

// Given a bumped root release, When preparing its PR, Then each optional
// module's published root requirement moves to that release (without relying
// on a local replace directive).
func TestGCPReleasePRUpdatesPublishedRootRequirement(t *testing.T) {
	script := releaseScript(t, ".github/workflows/release-pr.yml", "Compute next version and changelog")
	dir, _ := releaseRepo(t)
	for _, module := range []string{"key/aws", "key/gcp", "examples/deployment-identity"} {
		path := filepath.Join(dir, module)
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		content := "module github.com/dnsid-ai/dnsid-go/" + module + "\n\ngo 1.26.10\n\nrequire github.com/dnsid-ai/dnsid-go v0.1.0\n"
		if err := os.WriteFile(filepath.Join(path, "go.mod"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{".release-version": "v0.1.0\n", "CHANGELOG.md": "# Changes\n"} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	// git-cliff is external release tooling, not the system under test.
	if err := os.WriteFile(filepath.Join(bin, "git-cliff"), []byte("#!/bin/sh\ncase \"$*\" in *--bumped-version*) echo v9.9.9;; *) echo 'fixture release notes';; esac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	releaseRun(t, dir, []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "GITHUB_OUTPUT=" + filepath.Join(dir, "output")}, "bash", "-e", "-c", strings.ReplaceAll(script, "/tmp/release-notes.md", filepath.Join(dir, "release-notes.md")))
	for _, module := range []string{"key/aws", "key/gcp"} {
		data, err := os.ReadFile(filepath.Join(dir, module, "go.mod"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "github.com/dnsid-ai/dnsid-go v9.9.9") {
			t.Errorf("release PR left %s published root dependency stale:\n%s", module, data)
		}
	}
}
