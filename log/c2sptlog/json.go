package c2sptlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/dnsid-ai/dnsid-go/internal/jsonutil"
)

func canonicalJSON(v any) ([]byte, error) {
	if err := rejectUnsupportedJSON(v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if value {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		if err := writeCanonicalString(buf, value); err != nil {
			return err
		}
	case json.Number:
		buf.WriteString(value.String())
	case int:
		buf.WriteString(strconv.Itoa(value))
	case int64:
		buf.WriteString(strconv.FormatInt(value, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(value, 10))
	case []any:
		buf.WriteByte('[')
		for i, item := range value {
			if i != 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		buf.WriteByte('{')
		for i, key := range sortedKeys(value) {
			if i != 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalString(buf, key); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, value[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("dnsid: unsupported JSON value %T in c2sp-tlog event", value)
	}
	return nil
}

func writeCanonicalString(buf *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("dnsid: invalid UTF-8 string in c2sp-tlog event")
	}
	const hex = "0123456789abcdef"
	buf.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			buf.WriteByte('\\')
			buf.WriteRune(r)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hex[byte(r)>>4])
				buf.WriteByte(hex[byte(r)&0x0f])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

func rejectUnsupportedJSON(v any) error {
	switch x := v.(type) {
	case nil, string, bool:
		return nil
	case json.Number:
		i, err := x.Int64()
		if err != nil || strconv.FormatInt(i, 10) != x.String() || i < -maxJSONInteger || i > maxJSONInteger {
			return fmt.Errorf("dnsid: unsupported non-canonical JSON number %q in c2sp-tlog event", x.String())
		}
		return nil
	case int:
		if int64(x) < -maxJSONInteger || int64(x) > maxJSONInteger {
			return fmt.Errorf("dnsid: JSON integer outside safe range in c2sp-tlog event")
		}
		return nil
	case int64:
		if x < -maxJSONInteger || x > maxJSONInteger {
			return fmt.Errorf("dnsid: JSON integer outside safe range in c2sp-tlog event")
		}
		return nil
	case uint64:
		if x > maxJSONInteger {
			return fmt.Errorf("dnsid: JSON integer outside safe range in c2sp-tlog event")
		}
		return nil
	case map[string]any:
		for _, value := range x {
			if err := rejectUnsupportedJSON(value); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for _, value := range x {
			if err := rejectUnsupportedJSON(value); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("dnsid: unsupported JSON value %T in c2sp-tlog event", v)
	}
}

func decodeJSONObject(data []byte) (map[string]any, error) {
	return jsonutil.DecodeObject(data, true)
}

func validatePayloadJSON(obj map[string]any) error {
	for key, value := range obj {
		if key == "sigs" {
			if err := rejectUnknownSigFields(value); err != nil {
				return err
			}
			continue
		}
		if err := rejectUnsupportedJSON(value); err != nil {
			return err
		}
	}
	return nil
}

func rejectUnknownSigFields(value any) error {
	sigs, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("dnsid: c2sp-tlog sigs field must be an object")
	}
	for name, raw := range sigs {
		if name != "ae" && name != "op" && name != "prev_op" && name != "new_op" {
			return fmt.Errorf("dnsid: unsupported c2sp-tlog signature field %q", name)
		}
		sig, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("dnsid: c2sp-tlog signature %q must be an object", name)
		}
		for key, value := range sig {
			if key != "kid" && key != "sig" {
				return fmt.Errorf("dnsid: unsupported c2sp-tlog signature member %q", key)
			}
			if _, ok := value.(string); !ok {
				return fmt.Errorf("dnsid: c2sp-tlog signature member %q must be a string", key)
			}
		}
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a := utf16.Encode([]rune(keys[i]))
		b := utf16.Encode([]rune(keys[j]))
		for k := 0; k < len(a) && k < len(b); k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return len(a) < len(b)
	})
	return keys
}
