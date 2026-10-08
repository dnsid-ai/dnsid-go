package jsonutil

import (
	"bytes"
	"fmt"
	"unicode/utf8"
)

// WriteCanonicalString writes an RFC 8785 JSON string without HTML or Unicode escapes.
func WriteCanonicalString(buf *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("dnsid: invalid UTF-8 string")
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
