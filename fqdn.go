package dnsid

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

const (
	// maxDNSIDFQDNLength is the DNSid limit on an identity (agent) FQDN: the
	// owner name _dnsid.<fqdn> must still fit the 253-octet DNS limit.
	maxDNSIDFQDNLength = 246
	// maxDNSHostLength is the DNS presentation-format limit on any other host
	// name, such as an ek or status endpoint host.
	maxDNSHostLength = 253
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
//
// NormalizeFQDN is for agent (identity) FQDNs. It enforces the 246-octet
// agent-FQDN limit, which is stricter than the 253-octet limit the
// specification allows for other DNS names. Use NormalizeDNSName for other
// names, such as a gi domain or an endpoint host.
func NormalizeFQDN(input string) (string, error) {
	normalized, err := NormalizeDNSName(input)
	if err != nil {
		return "", err
	}
	if len(normalized) > maxDNSIDFQDNLength {
		return "", invalidFQDNError(input, fmt.Errorf("length %d exceeds %d octets", len(normalized), maxDNSIDFQDNLength))
	}
	return normalized, nil
}

// NormalizeDNSName returns the canonical form of a DNS name that is not an
// agent FQDN, such as a gi (governance) domain or the host of an ek, status or
// redirect URL. It applies the same steps as NormalizeFQDN (dot mapping, single
// trailing dot stripped, UTS 46 mapping, A-label encoding, ASCII lowercase,
// label-length checks) but enforces the 253-octet DNS presentation limit
// instead of the 246-octet agent-FQDN limit.
//
// Returns the normalized name or a non-nil error if input is invalid.
func NormalizeDNSName(input string) (string, error) {
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

	if len(normalized) > maxDNSHostLength {
		return "", invalidFQDNError(input, fmt.Errorf("length %d exceeds %d octets", len(normalized), maxDNSHostLength))
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

// isDomainOrSubdomain reports whether name equals domain or lies below it on a
// DNS-label boundary. Both arguments must already be in canonical form
// (NormalizeFQDN or NormalizeDNSName): the
// comparison is byte-exact and does no case folding or dot trimming of its own,
// so a caller holding a URL host must normalize it first (see
// TXTRecord.Validate and fetchHostAllowed).
func isDomainOrSubdomain(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func invalidFQDNError(input string, err error) error {
	return NewValidationError(fmt.Sprintf("dnsid: invalid FQDN %q", input), err)
}
