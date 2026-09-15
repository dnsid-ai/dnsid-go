package dnsid

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// DefaultPublishProfile is the current _dnsid TXT behavior profile emitted by
// this SDK. It is distinct from [Version], which reports the SDK/module release.
const DefaultPublishProfile = identityRecordDraft01

const (
	identityRecordDraft01 = "dnsid-draft-01"
	identityRecordDNSid1  = "DNSid1"
)

type identityRecordSignatureFormat uint8

const signatureFormatDraft01 identityRecordSignatureFormat = iota

type identityRecordProfile struct {
	requiredTags        []string
	alphabeticCanonical bool
	signatureFormat     identityRecordSignatureFormat
}

var draft01Profile = identityRecordProfile{
	requiredTags:        []string{irTagGovernanceID, irTagEntityKeyURI, irTagKeyURI, irTagLogRef, irTagStatusURI},
	alphabeticCanonical: true,
	signatureFormat:     signatureFormatDraft01,
}

// identityRecordProfiles maps exact wire selectors to implemented behavior.
// The parsed selector is retained separately and is never rewritten.
var identityRecordProfiles = map[string]identityRecordProfile{
	identityRecordDraft01: draft01Profile,
	identityRecordDNSid1:  draft01Profile,
}

func profileForVersion(v string) (identityRecordProfile, bool) {
	profile, ok := identityRecordProfiles[v]
	return profile, ok
}

func isSupportedVersion(v string) bool {
	_, ok := profileForVersion(v)
	return ok
}

// baseRequiredTagNames are structural inputs whose absence is a parse error.
var baseRequiredTagNames = []string{irTagKeyURI, irTagStatusURI}

// versionSpecificRequiredTagNames returns profile inputs whose absence is a
// validation error rather than a structural parse error.
func versionSpecificRequiredTagNames(v string) []string {
	profile, ok := profileForVersion(v)
	if !ok {
		return nil
	}
	var names []string
	for _, name := range profile.requiredTags {
		if name != irTagKeyURI && name != irTagStatusURI {
			names = append(names, name)
		}
	}
	return names
}

func requiredTagNamesForVersion(v string) []string {
	profile, ok := profileForVersion(v)
	if !ok {
		return nil
	}
	return profile.requiredTags
}

// Identity record tag names.
const (
	irTagVersion      = "v"
	irTagKeyURI       = "ku"
	irTagLogRef       = "lr"
	irTagStatusURI    = "su"
	irTagSignature    = "sg"
	irTagGovernanceID = "gi"
	irTagEntityKeyURI = "ek"
	irTagFlags        = "fl"
	irTagKeyAge       = "ka"
	irTagCapabilities = "cu"
)

// ValidKeyAgeValues is the enumerated set of valid ka= values.
var ValidKeyAgeValues = map[string]bool{
	"24h": true,
	"7d":  true,
	"30d": true,
	"90d": true,
}

// TXTRecord represents a parsed _dnsid TXT record.
type TXTRecord struct {
	Version      string            // v= — DNSid wire profile
	GovernanceID string            // gi= — governance identifier
	EntityKeyURI string            // ek= — accountable-entity record-signing JWKS URI
	KeyURI       string            // ku= — JWKS endpoint URL
	LogRef       string            // lr= — ledger address
	StatusURI    string            // su= — status endpoint URL
	Signature    string            // sg= — base64url owner signature
	Flags        []string          // fl= — parsed flag list (nil if absent)
	KeyAge       string            // ka= — key age policy (empty if absent)
	Capabilities string            // cu= — Agent Card URL (empty if absent)
	UnknownTags  map[string]string // syntactically valid extension tags, preserved but ignored semantically
}

// RegistrantDomain returns the registrant domain for use as gi=.
//
// It uses the public suffix list when possible. If the suffix lookup fails, it
// falls back to the final two DNS labels, or the normalized domain itself when
// fewer than two labels exist.
func RegistrantDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return ""
	}
	if registrant, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil {
		return registrant
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return domain
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// MissingRequiredField returns the first missing required non-signature DNSid
// TXT tag name, or "" if the unsigned record has all required signing inputs.
func MissingRequiredField(rec *TXTRecord) string {
	return missingRequiredRecordTag(rec)
}

func missingRequiredRecordTag(rec *TXTRecord) string {
	if rec == nil || rec.Version == "" {
		return irTagVersion
	}
	for _, name := range requiredTagNamesForVersion(rec.Version) {
		if recordValueForTag(rec, name) == "" {
			return name
		}
	}
	return ""
}

func recordValueForTag(rec *TXTRecord, name string) string {
	if rec == nil {
		return ""
	}
	var value string
	switch name {
	case irTagVersion:
		value = rec.Version
	case irTagGovernanceID:
		value = rec.GovernanceID
	case irTagEntityKeyURI:
		value = rec.EntityKeyURI
	case irTagKeyURI:
		value = rec.KeyURI
	case irTagLogRef:
		value = rec.LogRef
	case irTagStatusURI:
		value = rec.StatusURI
	case irTagSignature:
		value = rec.Signature
	case irTagFlags:
		if len(rec.Flags) > 0 {
			value = strings.Join(rec.Flags, ",")
		}
	case irTagKeyAge:
		value = rec.KeyAge
	case irTagCapabilities:
		value = rec.Capabilities
	}
	if value != "" {
		return value
	}
	return ""
}

// WithSignature returns a copy of the record with Signature set to sig.
func (r *TXTRecord) WithSignature(sig string) *TXTRecord {
	if r == nil {
		return nil
	}
	copied := *r
	copied.Signature = sig
	if len(r.Flags) > 0 {
		copied.Flags = append([]string(nil), r.Flags...)
	}
	if len(r.UnknownTags) > 0 {
		copied.UnknownTags = copyStringMap(r.UnknownTags)
	}
	return &copied
}

// Tags returns the record's tag-value pairs as a map, excluding empty optional
// fields. It always emits the current wire tag names.
func Tags(rec *TXTRecord) map[string]string {
	if rec == nil {
		return map[string]string{}
	}
	return rec.Tags()
}

// Tags returns the record's tag-value pairs as a map, excluding empty optional
// fields. It always emits the current wire tag names.
func (r *TXTRecord) Tags() map[string]string {
	tags := make(map[string]string)
	if r == nil {
		return tags
	}
	if r.Version != "" {
		tags[irTagVersion] = r.Version
	}
	if r.GovernanceID != "" {
		tags[irTagGovernanceID] = r.GovernanceID
	}
	if r.EntityKeyURI != "" {
		tags[irTagEntityKeyURI] = r.EntityKeyURI
	}
	if r.KeyURI != "" {
		tags[irTagKeyURI] = r.KeyURI
	}
	if r.LogRef != "" {
		tags[irTagLogRef] = r.LogRef
	}
	if r.StatusURI != "" {
		tags[irTagStatusURI] = r.StatusURI
	}
	if r.Signature != "" {
		tags[irTagSignature] = r.Signature
	}
	if len(r.Flags) > 0 {
		tags[irTagFlags] = strings.Join(r.Flags, ",")
	}
	if r.KeyAge != "" {
		tags[irTagKeyAge] = r.KeyAge
	}
	if r.Capabilities != "" {
		tags[irTagCapabilities] = r.Capabilities
	}
	for name, value := range r.UnknownTags {
		if name == irTagVersion || isKnownIdentityRecordTag(name) {
			continue
		}
		tags[name] = value
	}
	return tags
}

// tags is the internal alias used by serializer/canonicalization paths.
func (r *TXTRecord) tags() map[string]string {
	return r.Tags()
}

// KnownTagsCanonical returns the canonical byte string for known TXT tags only,
// excluding sg=. Unknown extension tags are ignored.
func (r *TXTRecord) KnownTagsCanonical() []byte {
	tags := r.knownTags()
	delete(tags, irTagSignature)
	if usesFullAlphabeticCanon(r.Version) {
		return []byte(serializeTagsAlphabetical(tags))
	}
	return []byte(serializeTags(tags))
}

// CanonicalContent returns the canonical byte string for signing under the
// record's declared profile. Values are signed as raw ASCII TXT tag values.
func (r *TXTRecord) CanonicalContent() []byte {
	tags := r.tags()
	delete(tags, irTagSignature)
	if usesFullAlphabeticCanon(r.Version) {
		return []byte(serializeTagsAlphabetical(tags))
	}
	return []byte(serializeTags(tags))
}

// MarshalTXT serializes the record as one _dnsid TXT value for wire output.
// It emits v= first, then all other tags sorted lexically; signing order is
// profile-defined and may differ.
func (r *TXTRecord) MarshalTXT() (string, error) {
	if err := r.validateRequiredTags(true); err != nil {
		return "", err
	}
	if err := validateTXTTagSyntax(r.tags()); err != nil {
		return "", err
	}
	return serializeTags(r.tags()), nil
}

func usesFullAlphabeticCanon(v string) bool {
	profile, ok := profileForVersion(v)
	return ok && profile.alphabeticCanonical
}

// serializeTags produces the wire-format string: v= first, then remaining
// tags sorted alphabetically. Used for MarshalTXT (wire output) and as the
// signing canonical form for dated beta profiles.
func serializeTags(tags map[string]string) string {
	parts := make([]string, 0, len(tags))
	if version, ok := tags[irTagVersion]; ok {
		parts = append(parts, fmt.Sprintf("%s=%s", irTagVersion, version))
	}
	for _, name := range orderedNonVersionTagNames(tags) {
		parts = append(parts, fmt.Sprintf("%s=%s", name, tags[name]))
	}
	return strings.Join(parts, ";")
}

// serializeTagsAlphabetical produces the draft 01 signing canonical form:
// all tags sorted alphabetically by name (v= sorts last).
func serializeTagsAlphabetical(tags map[string]string) string {
	names := make([]string, 0, len(tags))
	for name := range tags {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s=%s", name, tags[name]))
	}
	return strings.Join(parts, ";")
}

func orderedNonVersionTagNames(tags map[string]string) []string {
	names := make([]string, 0, len(tags))
	for name := range tags {
		if name != irTagVersion {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (r *TXTRecord) knownTags() map[string]string {
	tags := r.Tags()
	for name := range tags {
		if name != irTagVersion && !isKnownIdentityRecordTag(name) {
			delete(tags, name)
		}
	}
	return tags
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for name, value := range in {
		out[name] = value
	}
	return out
}

func isKnownIdentityRecordTag(name string) bool {
	switch name {
	case irTagGovernanceID,
		irTagEntityKeyURI,
		irTagKeyURI,
		irTagLogRef,
		irTagStatusURI,
		irTagSignature,
		irTagFlags,
		irTagKeyAge,
		irTagCapabilities:
		return true
	default:
		return false
	}
}

func validateTXTTagSyntax(tags map[string]string) error {
	for name, value := range tags {
		if !isValidTXTTagName(name) {
			return NewValidationError(fmt.Sprintf("dnsid: invalid tag name: %q", name), nil)
		}
		if !isValidTXTTagValue(value) {
			return NewValidationError(fmt.Sprintf("dnsid: invalid tag value for %q", name), nil)
		}
	}
	return nil
}

func isValidTXTTagName(name string) bool {
	if name == "" || !isASCIIAlpha(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !isASCIIAlpha(c) && !isASCIIDigit(c) && c != '_' {
			return false
		}
	}
	return true
}

func isValidTXTTagValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < 0x21 || c > 0x7e || c == ';' {
			return false
		}
	}
	return true
}

func isASCIIAlpha(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isASCIIDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// ParseTXTRecord parses a concatenated TXT record string into a TXTRecord.
func ParseTXTRecord(txt string) (*TXTRecord, error) {
	return parseTXTRecord(txt, true)
}

// ParseUnsignedCanonical parses registry-supplied unsigned canonical TXT
// content. It accepts required non-signature inputs and extension tags, but
// rejects sg=.
func ParseUnsignedCanonical(txt string) (*TXTRecord, error) {
	if strings.HasPrefix(txt, irTagVersion+"=") {
		value := strings.TrimPrefix(strings.SplitN(txt, ";", 2)[0], irTagVersion+"=")
		profile, ok := profileForVersion(value)
		if !ok {
			return nil, NewParseError(fmt.Sprintf("dnsid: unsupported version: %q", value), nil)
		}
		if !profile.alphabeticCanonical {
			rec, err := parseTXTRecord(txt, false)
			if err != nil {
				return nil, err
			}
			if string(rec.CanonicalContent()) != txt {
				return nil, NewParseError("dnsid: unsigned canonical content is not in canonical order", nil)
			}
			return rec, nil
		}
	}
	return parseUnsignedCanonicalAlpha(txt)
}

func parseUnsignedCanonicalAlpha(txt string) (*TXTRecord, error) {
	if txt == "" {
		return nil, NewParseError("dnsid: empty TXT content", nil)
	}
	pairs := strings.Split(txt, ";")
	tags := make(map[string]string, len(pairs))

	for i, pair := range pairs {
		if pair == "" {
			if i == len(pairs)-1 {
				continue
			}
			return nil, NewParseError("dnsid: empty tag-value element", nil)
		}
		if i > 0 && strings.HasPrefix(pair, " ") {
			pair = strings.TrimPrefix(pair, " ")
		}
		idx := strings.IndexByte(pair, '=')
		if idx <= 0 {
			return nil, NewParseError(fmt.Sprintf("dnsid: invalid tag-value pair: %q", pair), nil)
		}
		name := pair[:idx]
		value := pair[idx+1:]
		if !isValidTXTTagName(name) {
			return nil, NewParseError(fmt.Sprintf("dnsid: invalid tag name: %q", name), nil)
		}
		if !isValidTXTTagValue(value) {
			return nil, NewParseError(fmt.Sprintf("dnsid: invalid tag value for %q", name), nil)
		}
		if _, exists := tags[name]; exists {
			return nil, NewParseError(fmt.Sprintf("dnsid: duplicate tag %q", name), nil)
		}
		if name == irTagSignature {
			return nil, NewParseError(fmt.Sprintf("dnsid: unsigned canonical content must not include %q", irTagSignature), nil)
		}
		tags[name] = value
	}

	v := tags[irTagVersion]
	if v == "" {
		return nil, NewParseError("dnsid: v= tag not found", nil)
	}
	if !isSupportedVersion(v) {
		return nil, NewParseError(fmt.Sprintf("dnsid: unsupported version: %q", v), nil)
	}
	if !usesFullAlphabeticCanon(v) {
		return nil, NewParseError("dnsid: unsigned canonical content is not in canonical order", nil)
	}

	for _, name := range baseRequiredTagNames {
		if tags[name] == "" {
			return nil, NewParseError(fmt.Sprintf("dnsid: required tag %q is missing", name), nil)
		}
	}
	for _, name := range versionSpecificRequiredTagNames(v) {
		if tags[name] == "" {
			return nil, NewParseError(fmt.Sprintf("dnsid: required tag %q is missing", name), nil)
		}
	}

	ka := tags[irTagKeyAge]
	if ka != "" && !ValidKeyAgeValues[ka] {
		return nil, NewValidationError(fmt.Sprintf("dnsid: invalid %s value: %q", irTagKeyAge, ka), nil)
	}

	var flags []string
	if fl := tags[irTagFlags]; fl != "" {
		flags = strings.Split(fl, ",")
	}
	unknownTags := make(map[string]string)
	for name, value := range tags {
		if name != irTagVersion && !isKnownIdentityRecordTag(name) {
			unknownTags[name] = value
		}
	}

	rec := &TXTRecord{
		Version:      v,
		GovernanceID: tags[irTagGovernanceID],
		EntityKeyURI: tags[irTagEntityKeyURI],
		KeyURI:       tags[irTagKeyURI],
		StatusURI:    tags[irTagStatusURI],
		LogRef:       tags[irTagLogRef],
		Flags:        flags,
		KeyAge:       ka,
		Capabilities: tags[irTagCapabilities],
		UnknownTags:  copyStringMap(unknownTags),
	}

	if got := string(rec.CanonicalContent()); got != txt {
		return nil, NewParseError("dnsid: unsigned canonical content is not in canonical order", nil)
	}
	return rec, nil
}

func parseTXTRecord(txt string, requireSignature bool) (*TXTRecord, error) {
	if txt == "" {
		return nil, NewParseError("dnsid: empty TXT content", nil)
	}

	pairs := strings.Split(txt, ";")
	tags := make(map[string]string, len(pairs))
	var orderedNames []string

	for i, pair := range pairs {
		if pair == "" {
			if i == len(pairs)-1 {
				continue
			}
			return nil, NewParseError("dnsid: empty tag-value element", nil)
		}
		if i > 0 && strings.HasPrefix(pair, " ") {
			pair = strings.TrimPrefix(pair, " ")
		}
		idx := strings.IndexByte(pair, '=')
		if idx <= 0 {
			return nil, NewParseError(fmt.Sprintf("dnsid: invalid tag-value pair: %q", pair), nil)
		}
		name := pair[:idx]
		value := pair[idx+1:]
		if !isValidTXTTagName(name) {
			return nil, NewParseError(fmt.Sprintf("dnsid: invalid tag name: %q", name), nil)
		}
		if !isValidTXTTagValue(value) {
			return nil, NewParseError(fmt.Sprintf("dnsid: invalid tag value for %q", name), nil)
		}
		// Duplicate tags are rejected: the spec allows exactly one
		// occurrence per tag, and a silent overwrite would let an
		// adversarial record smuggle a second `ku=` past any value
		// checks on the first occurrence.
		if _, exists := tags[name]; exists {
			return nil, NewParseError(fmt.Sprintf("dnsid: duplicate tag %q", name), nil)
		}
		tags[name] = value
		orderedNames = append(orderedNames, name)
	}

	if len(orderedNames) == 0 || orderedNames[0] != irTagVersion {
		return nil, NewParseError("dnsid: v= must be the first tag", nil)
	}

	v := tags[irTagVersion]
	if !isSupportedVersion(v) {
		return nil, NewParseError(fmt.Sprintf("dnsid: unsupported version: %q", v), nil)
	}

	// Check universally-required tags first (structural parse errors).
	for _, name := range baseRequiredTagNames {
		if tags[name] == "" {
			return nil, NewParseError(fmt.Sprintf("dnsid: required tag %q is missing", name), nil)
		}
	}
	// Check profile-required tags as structural parse errors.
	for _, name := range versionSpecificRequiredTagNames(v) {
		if tags[name] == "" {
			return nil, NewParseError(fmt.Sprintf("dnsid: required tag %q is missing", name), nil)
		}
	}

	if requireSignature {
		if tags[irTagSignature] == "" {
			return nil, NewParseError(fmt.Sprintf("dnsid: required tag %q is missing", irTagSignature), nil)
		}
	} else if tags[irTagSignature] != "" {
		return nil, NewParseError(fmt.Sprintf("dnsid: unsigned canonical content must not include %q", irTagSignature), nil)
	}

	ka := tags[irTagKeyAge]
	if ka != "" && !ValidKeyAgeValues[ka] {
		return nil, NewValidationError(fmt.Sprintf("dnsid: invalid %s value: %q", irTagKeyAge, ka), nil)
	}

	var flags []string
	if fl := tags[irTagFlags]; fl != "" {
		flags = strings.Split(fl, ",")
	}
	unknownTags := make(map[string]string)
	for name, value := range tags {
		if name != irTagVersion && !isKnownIdentityRecordTag(name) {
			unknownTags[name] = value
		}
	}

	return &TXTRecord{
		Version:      v,
		GovernanceID: tags[irTagGovernanceID],
		EntityKeyURI: tags[irTagEntityKeyURI],
		KeyURI:       tags[irTagKeyURI],
		Signature:    tags[irTagSignature],
		StatusURI:    tags[irTagStatusURI],
		LogRef:       tags[irTagLogRef],
		Flags:        flags,
		KeyAge:       ka,
		Capabilities: tags[irTagCapabilities],
		UnknownTags:  copyStringMap(unknownTags),
	}, nil
}

// signRecordWithKeyProvider signs r with kp's active key and sets sg=.
func signRecordWithKeyProvider(r *TXTRecord, kp KeyProvider) (string, error) {
	if kp == nil {
		return "", NewArgumentError("dnsid: nil KeyProvider", nil)
	}
	if err := r.validateRequiredTags(false); err != nil {
		return "", err
	}
	tags := r.tags()
	delete(tags, irTagSignature)
	if err := validateTXTTagSyntax(tags); err != nil {
		return "", err
	}
	sig, err := kp.Sign(r.CanonicalContent())
	if err != nil {
		return "", fmt.Errorf("dnsid: record signing failed: %w", err)
	}
	if sig == nil {
		return "", NewArgumentError("dnsid: KeyProvider returned no signature", nil)
	}
	if !sig.Alg.Valid() {
		return "", NewArgumentError(fmt.Sprintf("dnsid: unsupported JOSE alg %q", sig.Alg), nil)
	}
	encoded, err := encodeRecordSignatureForProfile(r.Version, sig.Alg, sig.Signature)
	if err != nil {
		return "", NewArgumentError("dnsid: encoding record signature", err)
	}
	keyAlg, ok := jwkAlg(kp.JWK())
	if !ok || !keyAlg.Valid() {
		return "", NewArgumentError("dnsid: draft 01 record-signing key must include alg", nil)
	}
	if keyAlg != sig.Alg {
		return "", NewArgumentError(fmt.Sprintf("dnsid: draft 01 signature alg %q does not match record-signing key alg %q", sig.Alg, keyAlg), nil)
	}
	r.Signature = encoded
	return encoded, nil
}

func (r *TXTRecord) validateRequiredTags(includeSignature bool) error {
	if r == nil || r.Version == "" {
		return NewValidationError(fmt.Sprintf("dnsid: required tag %q is missing", irTagVersion), nil)
	}
	if !isSupportedVersion(r.Version) {
		return NewValidationError(fmt.Sprintf("dnsid: unrecognized version: %q", r.Version), nil)
	}
	if name := missingRequiredRecordTag(r); name != "" {
		return NewValidationError(fmt.Sprintf("dnsid: required tag %q is missing", name), nil)
	}
	if includeSignature && r.Signature == "" {
		return NewValidationError(fmt.Sprintf("dnsid: required tag %q is missing", irTagSignature), nil)
	}
	return nil
}
