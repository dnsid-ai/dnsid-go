package jose

import (
	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/joseutil"
)

func validateClaimTypes(raw map[string]any) error {
	invalid := func() error {
		return dnsid.NewVerificationError(dnsid.VerificationCodeInvalidClaims, false, "dnsid: invalid JWT claim type or missing claim", nil)
	}
	for _, name := range []string{"iss", "sub"} {
		if v, ok := raw[name].(string); !ok || v == "" {
			return invalid()
		}
	}
	if value, exists := raw["jti"]; exists {
		if _, ok := value.(string); !ok {
			return invalid()
		}
	}
	for _, name := range []string{"iat", "exp", "nbf"} {
		value, exists := raw[name]
		if name == "nbf" && !exists {
			continue
		}
		if _, ok := joseutil.NumericDate(value); !ok {
			return invalid()
		}
	}
	switch value := raw["aud"].(type) {
	case string:
		if value == "" {
			return invalid()
		}
	case []any:
		if len(value) == 0 {
			return invalid()
		}
		for _, aud := range value {
			if s, ok := aud.(string); !ok || s == "" {
				return invalid()
			}
		}
	default:
		return invalid()
	}
	return nil
}
