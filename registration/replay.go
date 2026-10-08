package registration

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"unicode/utf8"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/jsonutil"
)

// Scope isolates a named operation within an authenticated registry account.
// Stores must persist and verify this tuple, never use raw names as paths.
type Scope struct {
	RegistryURL    string
	OrganizationID string
	Name           string
}

func normalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || name == "" || utf8.RuneCountInString(name) > 255 {
		return "", dnsid.NewArgumentError("dnsid: name must contain 1 to 255 Unicode code points after trimming", nil)
	}
	return name, nil
}

func digestStrings(fields ...string) (string, error) {
	var buffer bytes.Buffer
	buffer.WriteByte('[')
	for i, value := range fields {
		if i != 0 {
			buffer.WriteByte(',')
		}
		if err := jsonutil.WriteCanonicalString(&buffer, value); err != nil {
			return "", err
		}
	}
	buffer.WriteByte(']')
	sum := sha256.Sum256(buffer.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func (s *State) replayKeys() (string, string, error) {
	key, err := parsePublic(s.OperationalKey)
	if err != nil {
		return "", "", err
	}
	initialKeyID, err := thumbprint(key)
	if err != nil {
		return "", "", err
	}
	registration, err := digestStrings("dnsid-managed-registration-v1", s.OrganizationID, s.Name, initialKeyID)
	if err != nil {
		return "", "", err
	}
	issuance, err := digestStrings("dnsid-managed-issuance-v1", registration)
	return registration, issuance, err
}

func (s *State) creationInput() *dnsid.AgentRegistrationInput {
	input := dnsid.AgentRegistrationInput{}
	if s.Input != nil {
		input = *s.Input
	}
	input.Name = s.Name
	input.PublicKeyJWK = s.OperationalKey
	return &input
}
