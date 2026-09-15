package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/jose"
)

// The Go A2A SDK does not yet expose A2A 1.0 types, so the card is represented
// as maps matching the A2A 1.0 JSON wire format.
func signedAgentCard(idm *dnsid.IdentityManager, publicURL string) (map[string]any, error) {
	providerURL := "https://" + os.Getenv("DNSID_GOVERNANCE_ID")
	if providerURL == "https://" {
		providerURL = publicURL
	}

	securityRequirement := map[string]any{
		"schemes": map[string]any{
			"dnsidHttpSignatures": map[string]any{"list": []string{}},
		},
	}
	card := map[string]any{
		"name":        "Example DNSid Echo Agent",
		"description": "A minimal A2A agent that echoes text input and requires DNSid-bound HTTP Message Signatures.",
		"version":     "0.2.0",
		"supportedInterfaces": []any{map[string]any{
			"url": publicURL, "protocolBinding": "JSONRPC", "protocolVersion": a2aVersion, "tenant": "",
		}},
		"provider":         map[string]any{"organization": "Example Provider", "url": providerURL},
		"documentationUrl": strings.TrimRight(providerURL, "/") + "/docs/echo-agent",
		"capabilities": map[string]any{
			"streaming": false, "pushNotifications": false,
			"extensions": []any{dnsidExtension()},
		},
		"defaultInputModes":  []string{"text/plain"},
		"defaultOutputModes": []string{"text/plain"},
		"skills": []any{map[string]any{
			"id": "echo", "name": "Echo", "description": "Returns the input text unchanged.",
			"tags":       []string{"echo", "test", "diagnostic"},
			"examples":   []string{"Echo: hello world", "Return this exact text: ping"},
			"inputModes": []string{"text/plain"}, "outputModes": []string{"text/plain"},
			"securityRequirements": []any{securityRequirement},
		}},
		"securitySchemes": map[string]any{
			"dnsidHttpSignatures": map[string]any{
				"apiKeySecurityScheme": map[string]any{
					"description": "DNSid-bound RFC 9421 HTTP Message Signatures using Signature-Input and Signature headers.",
					"location":    "header", "name": "Signature",
				},
			},
		},
		"securityRequirements": []any{securityRequirement},
	}

	// A2A verifiers normalize the card and sign its canonical JSON form.
	// In particular, empty protobuf fields are omitted from the payload.
	canonical, err := canonicalizeAgentCard(card)
	if err != nil {
		return nil, err
	}
	compact, err := jose.NewFromIdentityManagerKeyProvider(idm, jose.Config{}).CreateJWS(canonical)
	if err != nil {
		return nil, err
	}
	segments := strings.Split(compact, ".")
	card["signatures"] = []any{map[string]any{
		"protected": segments[0],
		"signature": segments[2],
	}}
	return card, nil
}

func canonicalizeAgentCard(card map[string]any) ([]byte, error) {
	cleaned, _ := cleanEmpty(card)
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(cleaned); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(canonical.Bytes(), []byte("\n")), nil
}

// cleanEmpty matches the normalization performed by the A2A SDK before it
// verifies an agent-card signature.
func cleanEmpty(value any) (any, bool) {
	switch value := value.(type) {
	case nil:
		return nil, false
	case string:
		return value, value != ""
	case []string:
		cleaned := make([]string, 0, len(value))
		for _, item := range value {
			if item != "" {
				cleaned = append(cleaned, item)
			}
		}
		return cleaned, len(cleaned) != 0
	case []any:
		cleaned := make([]any, 0, len(value))
		for _, item := range value {
			if item, ok := cleanEmpty(item); ok {
				cleaned = append(cleaned, item)
			}
		}
		return cleaned, len(cleaned) != 0
	case map[string]any:
		cleaned := make(map[string]any, len(value))
		for key, item := range value {
			if item, ok := cleanEmpty(item); ok {
				cleaned[key] = item
			}
		}
		return cleaned, len(cleaned) != 0
	default:
		return value, true
	}
}

func dnsidExtension() map[string]any {
	return map[string]any{
		"uri":         extensionURI,
		"required":    true,
		"description": "Requires DNSid validation and RFC 9421 HTTP Message Signatures for inbound requests.",
		"params": map[string]any{
			"dnsidSubject":                "selected-interface-host",
			"runtimeProof":                "http-message-signature",
			"signatureInputHeader":        "Signature-Input",
			"signatureHeader":             "Signature",
			"requiredSignatureTag":        signatureTag,
			"keyidSyntax":                 "<caller-dnsid-subject>#<jwks-kid>",
			"keyResolution":               "dnsid-ku-jwks",
			"requiredCoveredComponents":   requiredComponents,
			"requiredSignatureParameters": []string{"keyid", "alg", "created", "expires", "nonce", "tag"},
			"contentDigest":               "sha-256-required",
			"statusCheck":                 "dnsid-su-active-required",
			"providerPolicy":              "provider-url-host-must-equal-or-be-subdomain-of-gi",
			"mtls":                        "not-used-in-this-example-first-release-sdk-defers-fl-mtls",
		},
	}
}
