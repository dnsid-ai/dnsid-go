//go:build dnsid_foundry

package foundry

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/dnsid-ai/dnsid-go/internal/jsonutil"
)

// ValidateName checks exact Unicode names without trimming or normalization.
func ValidateName(name string) error {
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 255 {
		return fmt.Errorf("foundry: name must contain 1–255 Unicode scalar values")
	}
	return nil
}

func digest(fields ...string) string {
	var b bytes.Buffer
	b.WriteByte('[')
	for i, s := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		quote(&b, s)
	}
	b.WriteByte(']')
	sum := sha256.Sum256(b.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RegistrationKey derives the stable caller-key Live request ID.
func RegistrationKey(organizationID, name, initialKeyID string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	if organizationID == "" || initialKeyID == "" || !utf8.ValidString(organizationID) || !utf8.ValidString(initialKeyID) {
		return "", fmt.Errorf("foundry: organization and initial key ID are required")
	}
	return digest("dnsid-managed-registration-v1", organizationID, name, initialKeyID), nil
}

// IssuanceKey derives the stable ISSUANCE submission key.
func IssuanceKey(registrationKey string) string {
	return digest("dnsid-managed-issuance-v1", registrationKey)
}

func quote(b *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hex[r>>4])
				b.WriteByte(hex[r&15])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func canonical(value any) ([]byte, error) {
	var b bytes.Buffer
	var write func(any) error
	write = func(v any) error {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				a, b := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
				for n := 0; n < len(a) && n < len(b); n++ {
					if a[n] != b[n] {
						return a[n] < b[n]
					}
				}
				return len(a) < len(b)
			})
			b.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					b.WriteByte(',')
				}
				quote(&b, k)
				b.WriteByte(':')
				if err := write(x[k]); err != nil {
					return err
				}
			}
			b.WriteByte('}')
		case []any:
			b.WriteByte('[')
			for i, v := range x {
				if i > 0 {
					b.WriteByte(',')
				}
				if err := write(v); err != nil {
					return err
				}
			}
			b.WriteByte(']')
		case string:
			quote(&b, x)
		case json.Number:
			f, err := x.Float64()
			if err != nil {
				return err
			}
			if f == 0 {
				b.WriteByte('0')
				break
			}
			data, err := json.Marshal(f)
			if err != nil {
				return err
			}
			b.Write(data)
		case nil:
			b.WriteString("null")
		case bool:
			b.WriteString(strconv.FormatBool(x))
		default:
			return fmt.Errorf("foundry: unsupported recovery JSON value %T", v)
		}
		return nil
	}
	if err := write(value); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func decodeObject(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("foundry: invalid UTF-8")
	}
	// encoding/json replaces unpaired UTF-16 surrogates; reject them before decoding.
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			break
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			break
		}
		n, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return nil, err
		}
		i += 4
		if n >= 0xDC00 && n <= 0xDFFF {
			return nil, fmt.Errorf("foundry: unpaired Unicode surrogate")
		}
		if n >= 0xD800 && n <= 0xDBFF {
			if i+6 >= len(data) || string(data[i+1:i+3]) != `\u` {
				return nil, fmt.Errorf("foundry: unpaired Unicode surrogate")
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return nil, fmt.Errorf("foundry: unpaired Unicode surrogate")
			}
			i += 6
		}
	}
	return jsonutil.DecodeObject(data, true)
}

func publicJWK(data json.RawMessage) error {
	obj, err := decodeObject(data)
	if err != nil {
		return err
	}
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "keys"} {
		if _, ok := obj[name]; ok {
			return fmt.Errorf("foundry: public JWK contains forbidden member %q", name)
		}
	}
	return nil
}

func noSecrets(value any) error {
	switch x := value.(type) {
	case map[string]any:
		if _, isJWK := x["kty"]; isJWK {
			for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
				if _, present := x[member]; present {
					return fmt.Errorf("foundry: recovery document contains private JWK material")
				}
			}
		}
		for k, v := range x {
			switch strings.ToLower(k) {
			case "password", "credential", "credentials", "apikey", "api_key", "authorization", "access_token", "privatekey", "private_key":
				return fmt.Errorf("foundry: recovery document contains secret member %q", k)
			}
			if err := noSecrets(v); err != nil {
				return err
			}
		}
	case []any:
		for _, v := range x {
			if err := noSecrets(v); err != nil {
				return err
			}
		}
	}
	return nil
}
