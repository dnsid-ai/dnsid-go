package c2sptlog

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

const (
	// Method is the DNSid log method name this package registers.
	Method = "c2sp-tlog"
	// Kind is the required "kind" value in every c2sp-tlog event envelope.
	Kind           = "dnsid.lifecycle"
	maxEntrySize   = 65535
	maxJSONInteger = 9007199254740991
	streamIDBytes  = 16
)

// Reference is the parsed DNSid c2sp-tlog lr value:
// c2sp-tlog:<scope>:<log-prefix>#<stream-id>. Scope is "public", "testnet",
// or "private-{name}"; LogPrefix is the log's base URL; StreamID names one
// identity-instance lifecycle stream.
type Reference struct {
	Scope     string
	LogPrefix string
	StreamID  string
}

// GenerateStreamID returns an opaque identity-instance stream identifier with
// 128 bits of cryptographically secure randomness, encoded as unpadded
// base64url. Callers must generate a new value for each replacement identity.
func GenerateStreamID() (string, error) {
	entropy := make([]byte, streamIDBytes)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("dnsid: generating c2sp-tlog stream id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(entropy), nil
}

// ParseReference parses and validates an lr value into a Reference. It
// returns a *dnsid.ParseError if lr is malformed or fails Validate.
func ParseReference(lr string) (refResult Reference, err error) {
	defer func() {
		if err != nil {
			err = dnsid.NewParseError("dnsid: parsing c2sp-tlog reference", err)
		}
	}()
	method, entryRef, err := dnsidlog.ParseLogRef(lr)
	if err != nil {
		return Reference{}, err
	}
	if method != Method {
		return Reference{}, fmt.Errorf("dnsid: log method %q is not %q", method, Method)
	}
	scope, rest, ok := strings.Cut(entryRef, ":")
	if !ok || scope == "" || rest == "" {
		return Reference{}, fmt.Errorf("dnsid: malformed c2sp-tlog reference")
	}
	hash := strings.LastIndexByte(rest, '#')
	if hash <= 0 || hash == len(rest)-1 {
		return Reference{}, fmt.Errorf("dnsid: malformed c2sp-tlog reference")
	}
	ref := Reference{
		Scope:     scope,
		LogPrefix: rest[:hash],
		StreamID:  rest[hash+1:],
	}
	if err := ref.Validate(); err != nil {
		return Reference{}, err
	}
	return ref, nil
}

// Validate checks that the reference is well formed and canonical: a known
// scope, an absolute lowercase http(s) LogPrefix with no userinfo, query,
// fragment, dot segments, trailing slash, default port, or non-canonical
// percent-encodings, and a non-empty StreamID. Public scopes require https.
// It returns a *dnsid.ValidationError describing the first violation.
func (r Reference) Validate() (err error) {
	defer func() {
		if err != nil {
			err = dnsid.NewValidationError("dnsid: invalid c2sp-tlog reference", err)
		}
	}()
	switch {
	case r.Scope == "public", r.Scope == "testnet":
	case strings.HasPrefix(r.Scope, "private-") && validPrivateScope(r.Scope):
	default:
		return fmt.Errorf("dnsid: invalid c2sp-tlog scope %q", r.Scope)
	}
	u, err := url.Parse(r.LogPrefix)
	if err != nil || u == nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("dnsid: invalid c2sp-tlog log prefix")
	}
	if u.User != nil {
		return fmt.Errorf("dnsid: c2sp-tlog log prefix must not contain userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("dnsid: c2sp-tlog log prefix must not contain query or fragment")
	}
	if u.Scheme != strings.ToLower(u.Scheme) {
		return fmt.Errorf("dnsid: c2sp-tlog log prefix scheme must be lowercase")
	}
	if strings.Contains(u.EscapedPath(), "/./") || strings.Contains(u.EscapedPath(), "/../") || strings.HasSuffix(u.EscapedPath(), "/.") || strings.HasSuffix(u.EscapedPath(), "/..") {
		return fmt.Errorf("dnsid: c2sp-tlog log prefix must not contain dot segments")
	}
	if strings.HasSuffix(r.LogPrefix, "/") {
		return fmt.Errorf("dnsid: c2sp-tlog log prefix must not end with slash")
	}
	if r.Scope == "public" && u.Scheme != "https" {
		return fmt.Errorf("dnsid: public c2sp-tlog log prefix must use https")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("dnsid: c2sp-tlog log prefix must use http or https")
	}
	if u.Hostname() != strings.ToLower(u.Hostname()) {
		return fmt.Errorf("dnsid: c2sp-tlog log prefix host must be lowercase")
	}
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		return fmt.Errorf("dnsid: c2sp-tlog log prefix must omit default port")
	}
	if err := validateCanonicalEscapes(u.EscapedPath()); err != nil {
		return err
	}
	if r.StreamID == "" {
		return fmt.Errorf("dnsid: c2sp-tlog stream id is required")
	}
	return nil
}

func validPrivateScope(scope string) bool {
	if scope == "private-" {
		return false
	}
	for _, r := range strings.TrimPrefix(scope, "private-") {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validateCanonicalEscapes(path string) error {
	for i := 0; i < len(path); i++ {
		if path[i] != '%' {
			continue
		}
		if i+2 >= len(path) || !isUpperHex(path[i+1]) || !isUpperHex(path[i+2]) {
			return fmt.Errorf("dnsid: c2sp-tlog log prefix percent-encodings must use uppercase hex")
		}
		hi, lo := fromHex(path[i+1]), fromHex(path[i+2])
		b := hi<<4 | lo
		if b == '/' || b == '\\' {
			return fmt.Errorf("dnsid: c2sp-tlog log prefix must not percent-encode slash or backslash")
		}
		if isUnreserved(b) {
			return fmt.Errorf("dnsid: c2sp-tlog log prefix must decode unreserved percent-encodings")
		}
		i += 2
	}
	return nil
}

func isUpperHex(b byte) bool { return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'F') }
func fromHex(b byte) byte {
	if b <= '9' {
		return b - '0'
	}
	return b - 'A' + 10
}
func isUnreserved(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '.' || b == '_' || b == '~'
}

// String returns the reference in lr form:
// c2sp-tlog:<scope>:<log-prefix>#<stream-id>.
func (r Reference) String() string {
	return Method + ":" + r.Scope + ":" + r.LogPrefix + "#" + r.StreamID
}

// Origin returns the C2SP checkpoint origin derived from LogPrefix.
func (r Reference) Origin() (origin string, err error) {
	defer func() {
		if err != nil {
			err = dnsid.NewValidationError("dnsid: invalid c2sp-tlog reference", err)
		}
	}()
	u, err := url.Parse(r.LogPrefix)
	if err != nil || u == nil || u.Host == "" {
		return "", fmt.Errorf("dnsid: invalid c2sp-tlog log prefix")
	}
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}
	host := u.Host
	if strings.Contains(host, ":") && u.Port() != "" {
		host = net.JoinHostPort(u.Hostname(), u.Port())
	}
	return host + path, nil
}

// FinalEventRef returns the reference of the entry at index in this stream,
// in the form <lr>@<index>.
func (r Reference) FinalEventRef(index uint64) dnsidlog.LogRef {
	return dnsidlog.LogRef(r.String() + "@" + strconv.FormatUint(index, 10))
}

// ParseFinalEventRef parses a final event reference of the form <lr>@<index>
// into its Reference and entry index. The index must be decimal with no
// leading zeros. It returns a *dnsid.ParseError on any violation.
func ParseFinalEventRef(ref dnsidlog.LogRef) (reference Reference, indexResult uint64, err error) {
	defer func() {
		if err != nil {
			err = dnsid.NewParseError("dnsid: parsing c2sp-tlog final event reference", err)
		}
	}()
	s := string(ref)
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return Reference{}, 0, fmt.Errorf("dnsid: malformed c2sp-tlog final event reference")
	}
	r, err := ParseReference(s[:at])
	if err != nil {
		return Reference{}, 0, err
	}
	indexText := s[at+1:]
	if (len(indexText) > 1 && indexText[0] == '0') || !decimalDigits(indexText) {
		return Reference{}, 0, fmt.Errorf("dnsid: invalid c2sp-tlog event index")
	}
	index, err := strconv.ParseUint(indexText, 10, 64)
	if err != nil {
		return Reference{}, 0, fmt.Errorf("dnsid: invalid c2sp-tlog event index: %w", err)
	}
	return r, index, nil
}

func decimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}
