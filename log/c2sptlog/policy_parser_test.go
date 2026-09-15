package c2sptlog

import (
	"strings"
	"testing"

	formatnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

func TestParsePolicyNestedQuorum(t *testing.T) {
	_, logKey, err := note.GenerateKey(nil, "log.example/test")
	if err != nil {
		t.Fatal(err)
	}
	witnessKey := func(name string) string {
		t.Helper()
		_, vkey, err := note.GenerateKey(nil, name)
		if err != nil {
			t.Fatal(err)
		}
		cosignatureKey, err := formatnote.VKeyToCosignatureV1(vkey)
		if err != nil {
			t.Fatal(err)
		}
		return cosignatureKey
	}
	document := strings.Join([]string{
		"log " + logKey + " https://log.example/test",
		"witness alpha " + witnessKey("alpha"),
		"witness beta " + witnessKey("beta") + " https://beta.example/",
		"witness gamma " + witnessKey("gamma"),
		"group primary any alpha beta",
		"group nested all primary gamma",
		"quorum nested",
	}, "\n")

	policy, err := ParsePolicy([]byte(document))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if got, want := policy.LogVerifier.Name(), "log.example/test"; got != want {
		t.Fatalf("log name = %q, want %q", got, want)
	}
	if got, want := len(policy.WitnessVerifiers), 3; got != want {
		t.Fatalf("witness count = %d, want %d", got, want)
	}
	if got, want := policy.WitnessQuorum, 2; got != want {
		t.Fatalf("minimum signature count = %d, want %d", got, want)
	}
}

func TestParsePolicyRejectsForwardReference(t *testing.T) {
	_, logKey, err := note.GenerateKey(nil, "log.example/test")
	if err != nil {
		t.Fatal(err)
	}
	document := "log " + logKey + "\ngroup early any later\nquorum early\n"
	if _, err := ParsePolicy([]byte(document)); err == nil {
		t.Fatal("ParsePolicy accepted a forward reference")
	}
}

func TestParsePolicyRejectsDuplicateQuorum(t *testing.T) {
	_, logKey, err := note.GenerateKey(nil, "log.example/test")
	if err != nil {
		t.Fatal(err)
	}
	document := "log " + logKey + "\nquorum none\nquorum none\n"
	if _, err := ParsePolicy([]byte(document)); err == nil {
		t.Fatal("ParsePolicy accepted duplicate quorum directives")
	}
}
