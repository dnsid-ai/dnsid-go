package dnsid

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

const (
	maxDNSIDFQDNLength = 246
)

var fqdnIDNAProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.VerifyDNSLength(true),
)

// NormalizeFQDN returns the canonical form of the given DNS name:
//  1. Map IDNA dot-equivalent runes and strip a single trailing dot.
//  2. Apply IDNA A-label encoding (Unicode -> punycode where needed).
//  3. Lowercase all ASCII letters.
//  4. Validate label-length limits (<=63 octets per label).
//  5. Validate total length <=246 octets (DNSid agent-FQDN limit per spec).
//
// Returns the normalized FQDN or a non-nil error if input is invalid.
func NormalizeFQDN(input string) (string, error) {
	if input == "" {
		return "", invalidFQDNError(input, errors.New("empty input"))
	}

	// VerifyDNSLength rejects the empty root label under Unicode 17, so remove
	// the accepted trailing separator before passing the name to IDNA.
	mappedInput := strings.Map(mapIDNADot, input)
	if strings.HasSuffix(mappedInput, "..") {
		return "", invalidFQDNError(input, errors.New("multiple trailing dots"))
	}
	mappedInput = strings.TrimSuffix(mappedInput, ".")
	if mappedInput == "" {
		return "", invalidFQDNError(input, errors.New("empty name"))
	}

	normalized, err := fqdnIDNAProfile.ToASCII(mappedInput)
	if err != nil {
		return "", invalidFQDNError(input, err)
	}

	if len(normalized) > maxDNSIDFQDNLength {
		return "", invalidFQDNError(input, fmt.Errorf("length %d exceeds %d octets", len(normalized), maxDNSIDFQDNLength))
	}

	return normalized, nil
}

func mapIDNADot(r rune) rune {
	switch r {
	case '\u3002', '\uff0e', '\uff61':
		return '.'
	default:
		return r
	}
}

func isDomainOrSubdomain(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func invalidFQDNError(input string, err error) error {
	return NewValidationError(fmt.Sprintf("dnsid: invalid FQDN %q", input), err)
}
