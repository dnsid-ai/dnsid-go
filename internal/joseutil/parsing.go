package joseutil

import (
	"encoding/base64"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/dnsid-ai/dnsid-go/internal/jsonutil"
)

const MaxTokenBytes = 1 << 20
const MaxHeaderBytes = 16 << 10
const MaxPayloadBytes = 768 << 10

// DecodeBase64URL rejects padding, whitespace and non-canonical trailing bits.
func DecodeBase64URL(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("invalid base64url")
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// Compact checks every component before discovery or signature work.
func Compact(token string) ([]string, []byte, []byte, error) {
	if len(token) > MaxTokenBytes {
		return nil, nil, nil, fmt.Errorf("token exceeds size limit")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(parts[0]) > (MaxHeaderBytes+2)/3*4 || parts[0] == "" || parts[2] == "" {
		return nil, nil, nil, fmt.Errorf("invalid compact serialization")
	}
	header, err := DecodeBase64URL(parts[0])
	if err != nil {
		return nil, nil, nil, err
	}
	payload, err := DecodeBase64URL(parts[1])
	if err != nil {
		return nil, nil, nil, err
	}
	if len(header) > MaxHeaderBytes || len(payload) > MaxPayloadBytes {
		return nil, nil, nil, fmt.Errorf("decoded token exceeds size limit")
	}
	if _, err := DecodeBase64URL(parts[2]); err != nil {
		return nil, nil, nil, err
	}
	return parts, header, payload, nil
}

// DecodeObject enforces the JOSE payload bound and strict JSON object parsing.
func DecodeObject(data []byte) (map[string]any, error) {
	if len(data) > MaxPayloadBytes {
		return nil, fmt.Errorf("JSON exceeds size limit")
	}
	return jsonutil.DecodeObject(data, false)
}

// NumericDate preserves fractional seconds and does not coerce strings or booleans.
func NumericDate(value any) (time.Time, bool) {
	n, ok := value.(float64)
	if !ok || math.IsNaN(n) || math.IsInf(n, 0) || n <= -1<<62 || n >= 1<<62 {
		return time.Time{}, false
	}
	seconds, fraction := math.Modf(n)
	return time.Unix(int64(seconds), int64(fraction*1e9)), true
}
