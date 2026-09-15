package httpsig

import (
	"strings"
	"testing"
)

// componentEqual switched from
//
//	strings.ToLower(strings.TrimSpace(a.Name)) != strings.ToLower(strings.TrimSpace(b.Name))
//
// to
//
//	!strings.EqualFold(strings.TrimSpace(a.Name), strings.TrimSpace(b.Name))
//
// Those are NOT universally equivalent: ToLower does full Unicode lowercasing
// while EqualFold does simple case folding, and they disagree on characters
// like the Kelvin sign (U+212A) and long s (U+017F). RFC 9421 component names
// are ASCII in practice, but signature comparison is security-relevant enough
// that the difference is worth pinning rather than assuming.
//
// This test embeds the ORIGINAL implementation as an oracle and drives the
// real componentEqual against it over a corpus, so it runs identically before
// and after the refactor and fails if anyone swaps in EqualFold later.
//
// It caught exactly that: the EqualFold rewrite diverged on the ſ/s and İ/i
// pairs and was reverted. See the nolint comment on componentEqual.

// referenceNameEqual is the original comparison, kept verbatim as the oracle.
func referenceNameEqual(a, b string) bool {
	return strings.ToLower(strings.TrimSpace(a)) == strings.ToLower(strings.TrimSpace(b)) //nolint:staticcheck // deliberately preserves the original implementation as a test oracle
}

func TestComponentEqualNameMatchingMatchesReference(t *testing.T) {
	names := []string{
		"", " ", "content-digest", "Content-Digest", "CONTENT-DIGEST",
		" content-digest ", "\tcontent-digest\n", "@method", "@Method",
		"@target-uri", "content-type", "Content-Type", "x-custom", "X-Custom",
		"signature", "Signature", "authorization", "AUTHORIZATION",
		// Non-ASCII probes. ToLower and EqualFold genuinely disagree on the
		// last two groups; the corpus keeps that pinned.
		"K", "k", "K", // Kelvin sign vs ASCII k/K
		"ſ", "s", "S", // long s vs ASCII s/S
		"straße", "STRASSE", // eszett
		"İ", "i", "I", "ı", // dotted/dotless I
	}

	for _, a := range names {
		for _, b := range names {
			want := referenceNameEqual(a, b)
			got := componentEqual(ComponentIdentifier{Name: a}, ComponentIdentifier{Name: b})
			if got != want {
				t.Errorf("componentEqual name matching diverged for %q vs %q: got=%v want=%v", a, b, got, want)
			}
		}
	}
}

// TestComponentEqualBehavior pins the end-to-end behavior of componentEqual
// itself: case- and whitespace-insensitive on the name, exact on params.
// Passes before and after.
func TestComponentEqualBehavior(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b ComponentIdentifier
		want bool
	}{
		{
			name: "identical",
			a:    ComponentIdentifier{Name: "content-digest"},
			b:    ComponentIdentifier{Name: "content-digest"},
			want: true,
		},
		{
			name: "case-insensitive name",
			a:    ComponentIdentifier{Name: "Content-Digest"},
			b:    ComponentIdentifier{Name: "content-digest"},
			want: true,
		},
		{
			name: "surrounding whitespace ignored",
			a:    ComponentIdentifier{Name: "  content-digest  "},
			b:    ComponentIdentifier{Name: "content-digest"},
			want: true,
		},
		{
			name: "different name",
			a:    ComponentIdentifier{Name: "content-digest"},
			b:    ComponentIdentifier{Name: "content-type"},
			want: false,
		},
		{
			name: "param count differs",
			a:    ComponentIdentifier{Name: "x", Params: map[string]any{"req": true}},
			b:    ComponentIdentifier{Name: "x"},
			want: false,
		},
		{
			name: "param value differs",
			a:    ComponentIdentifier{Name: "x", Params: map[string]any{"req": true}},
			b:    ComponentIdentifier{Name: "x", Params: map[string]any{"req": false}},
			want: false,
		},
		{
			name: "param key differs",
			a:    ComponentIdentifier{Name: "x", Params: map[string]any{"req": true}},
			b:    ComponentIdentifier{Name: "x", Params: map[string]any{"sf": true}},
			want: false,
		},
		{
			name: "equal params",
			a:    ComponentIdentifier{Name: "x", Params: map[string]any{"req": true}},
			b:    ComponentIdentifier{Name: "X", Params: map[string]any{"req": true}},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := componentEqual(tc.a, tc.b); got != tc.want {
				t.Fatalf("componentEqual(%+v, %+v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
