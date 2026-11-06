//go:build dnsid_foundry

package foundry

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/internal/joseutil"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// RecoveryDocument is the non-secret, portable recovery state for an exact name.
// Use ParseRecoveryDocument and Export to validate imported and exported state.
type RecoveryDocument struct {
	SchemaVersion     int                      `json:"schemaVersion"`
	Phase             string                   `json:"phase"`
	RegistryURL       string                   `json:"registryUrl"`
	OrganizationID    string                   `json:"organizationId"`
	Name              string                   `json:"name"`
	GovernanceID      string                   `json:"governanceId"`
	LogTrust          json.RawMessage          `json:"logTrust,omitempty"`
	KeySource         config.KeySource         `json:"keySource"`
	CurrentKeySource  *config.KeySource        `json:"currentKeySource,omitempty"`
	InitialPublicKey  json.RawMessage          `json:"initialPublicKey"`
	CurrentPublicKey  json.RawMessage          `json:"currentPublicKey,omitempty"`
	CreationInput     CreationInput            `json:"creationInput"`
	IdentityID        string                   `json:"identityId,omitempty"`
	Domain            string                   `json:"domain,omitempty"`
	RequestID         string                   `json:"requestId,omitempty"`
	RegistryStatus    string                   `json:"registryStatus,omitempty"`
	RegistryError     *dnsid.AgentError        `json:"registryError,omitempty"`
	ProtocolState     string                   `json:"protocolState,omitempty"`
	SigningPaused     bool                     `json:"signingPaused,omitempty"`
	Proof             *ProofState              `json:"proof,omitempty"`
	PublicationConfig *dnsid.PublicationConfig `json:"publicationConfig,omitempty"`
	OIDCIssuerURL     string                   `json:"oidcIssuerUrl,omitempty"`
	EntityPublicKey   json.RawMessage          `json:"entityPublicKey,omitempty"`
	Issuance          *IssuanceState           `json:"issuance,omitempty"`
	original          map[string]any
}

// CreationInput freezes the complete non-secret Live wire request.
type CreationInput struct {
	Name            string          `json:"name"`
	PublicKey       json.RawMessage `json:"public_key"`
	Environment     string          `json:"environment"`
	CapabilitiesURL string          `json:"capabilities_url,omitempty"`
	Tier            string          `json:"tier"`
	Managed         bool            `json:"managed"`
}

// ProofState retains the exact server challenge and completed request.
type ProofState struct {
	Challenge        string `json:"challenge"`
	ChallengeMessage string `json:"challengeMessage"`
	Signature        string `json:"signature,omitempty"`
	Outcome          string `json:"outcome,omitempty"`
}

// IssuanceState retains local coordinator state separately from a verified
// accepted entry recovered from another replica. Its receipt never acknowledges
// the local entry bytes.
type IssuanceState struct {
	Operation         *c2sptlog.ManagedIssuanceState `json:"operation,omitempty"`
	Recovered         bool                           `json:"recovered,omitempty"`
	AcceptedReference string                         `json:"acceptedReference,omitempty"`
	PreparedBytes     string                         `json:"preparedBytes,omitempty"`
	StatusCode        int                            `json:"statusCode,omitempty"`
}

// ParseRecoveryDocument rejects corrupt, duplicate, invalid-Unicode, and
// unsupported recovery documents. Unknown members are retained on export.
func ParseRecoveryDocument(data []byte) (*RecoveryDocument, error) {
	obj, err := decodeObject(data)
	if err != nil {
		return nil, err
	}
	// Coordinator byte strings use portable unpadded base64url, not Go's base64.
	normalized, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var doc RecoveryDocument
	// Decode coordinator bytes separately so the public representation stays portable.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(normalized, &fields); err != nil {
		return nil, err
	}
	if raw, ok := fields["issuance"]; ok {
		var issuance map[string]json.RawMessage
		if err := json.Unmarshal(raw, &issuance); err != nil {
			return nil, err
		}
		if op, ok := issuance["operation"]; ok {
			var operation map[string]json.RawMessage
			if err := json.Unmarshal(op, &operation); err != nil {
				return nil, err
			}
			if encoded, ok := operation["entry_bytes"]; ok {
				var s string
				if err := json.Unmarshal(encoded, &s); err != nil {
					return nil, err
				}
				b, err := base64.RawURLEncoding.Strict().DecodeString(s)
				if err != nil {
					return nil, err
				}
				operation["entry_bytes"], err = json.Marshal(b)
				if err != nil {
					return nil, err
				}
			}
			var err error
			issuance["operation"], err = json.Marshal(operation)
			if err != nil {
				return nil, err
			}
		}
		fields["issuance"], err = json.Marshal(issuance)
		if err != nil {
			return nil, err
		}
	}
	normalized, err = json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(normalized, &doc); err != nil {
		return nil, err
	}
	if err := noSecrets(obj); err != nil {
		return nil, err
	}
	doc.original = obj
	if err := doc.validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

// Export returns UTF-8 RFC 8785 JSON without private keys or credentials.
func (d *RecoveryDocument) Export() ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	obj, err := decodeObject(data)
	if err != nil {
		return nil, err
	}
	if d.Issuance != nil && d.Issuance.Operation != nil && len(d.Issuance.Operation.EntryBytes) > 0 {
		issuance, _ := obj["issuance"].(map[string]any)
		operation, _ := issuance["operation"].(map[string]any)
		operation["entry_bytes"] = base64.RawURLEncoding.EncodeToString(d.Issuance.Operation.EntryBytes)
	}
	preserveUnknown(d.original, obj, reflect.TypeFor[RecoveryDocument]())
	if err := noSecrets(obj); err != nil {
		return nil, err
	}
	return canonical(obj)
}

// preserveUnknown keeps extension fields, including nested extensions. Known
// optional fields remain controlled by the typed document, not stale JSON.
func preserveUnknown(old, next map[string]any, schema reflect.Type) {
	for schema.Kind() == reflect.Pointer {
		schema = schema.Elem()
	}
	if schema.Kind() != reflect.Struct {
		return
	}
	fields := make(map[string]reflect.Type)
	for n := 0; n < schema.NumField(); n++ {
		field := schema.Field(n)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			fields[name] = field.Type
		}
	}
	for name, value := range old {
		field, known := fields[name]
		if !known {
			next[name] = value
			continue
		}
		previous, wasObject := value.(map[string]any)
		current, isObject := next[name].(map[string]any)
		if wasObject && isObject {
			preserveUnknown(previous, current, field)
		}
	}
}

func (d *RecoveryDocument) validate() error {
	if d == nil || d.SchemaVersion != 1 {
		return fmt.Errorf("foundry: unsupported recovery schema")
	}
	switch d.Phase {
	case "creation-pending", "identity-known", "proof-pending", "issuance-accepted", "complete":
	default:
		return fmt.Errorf("foundry: unknown recovery phase %q", d.Phase)
	}
	if err := ValidateName(d.Name); err != nil {
		return err
	}
	if d.RegistryURL == "" || d.OrganizationID == "" || d.GovernanceID == "" {
		return fmt.Errorf("foundry: missing recovery bindings")
	}
	gi, err := dnsid.NormalizeFQDN(d.GovernanceID)
	if err != nil || gi != d.GovernanceID {
		return fmt.Errorf("foundry: invalid recovery governance domain")
	}
	initial, err := parsePublicKey(d.InitialPublicKey)
	if err != nil {
		return err
	}
	thumb, err := keyThumb(initial)
	if err != nil {
		return err
	}
	requestID, err := RegistrationKey(d.OrganizationID, d.Name, thumb)
	if err != nil {
		return err
	}
	if d.RequestID != requestID || d.CreationInput.Name != d.Name {
		return fmt.Errorf("foundry: creation input or request ID conflicts with bindings")
	}
	input, err := json.Marshal(d.CreationInput.PublicKey)
	if err != nil {
		return err
	}
	key, err := parsePublicKey(input)
	if err != nil {
		return err
	}
	inputThumb, err := keyThumb(key)
	if err != nil || inputThumb != thumb {
		return fmt.Errorf("foundry: frozen public key conflicts with initial binding")
	}
	if d.CreationInput.Environment != "production" || d.CreationInput.Tier != "live" || !d.CreationInput.Managed {
		return fmt.Errorf("foundry: invalid frozen Live environment")
	}
	if len(d.CurrentPublicKey) > 0 {
		if _, err := parsePublicKey(d.CurrentPublicKey); err != nil {
			return err
		}
	}
	if d.Domain != "" {
		normalized, err := dnsid.NormalizeFQDN(d.Domain)
		if err != nil || normalized != d.Domain {
			return fmt.Errorf("foundry: invalid saved domain")
		}
	}
	if d.Domain != "" && d.IdentityID == "" {
		return fmt.Errorf("foundry: saved domain requires an identity ID")
	}
	if d.Phase != "creation-pending" && (d.Domain == "" || d.IdentityID == "") {
		return fmt.Errorf("foundry: recovery phase requires identity and domain")
	}
	if d.Phase == "proof-pending" && d.Proof != nil && d.Proof.Outcome == "accepted" {
		return fmt.Errorf("foundry: settled proof must advance to identity-known")
	}
	if d.Proof != nil && d.Proof.Outcome != "accepted" && d.Phase != "proof-pending" {
		return fmt.Errorf("foundry: unsettled proof requires proof-pending")
	}
	if d.Issuance != nil && (d.Phase == "proof-pending" || d.Phase == "creation-pending") {
		return fmt.Errorf("foundry: issuance requires identity-known or a later phase")
	}
	if d.Phase == "proof-pending" && d.Proof == nil {
		return fmt.Errorf("foundry: proof phase requires challenge")
	}
	if d.PublicationConfig != nil {
		p := d.PublicationConfig
		cfg := publicationIdentity(d.Domain, p)
		if err := cfg.Validate(); err != nil {
			return err
		}
		if p.PublishProfile != dnsid.DefaultPublishProfile || p.GovernanceID != d.GovernanceID || p.EntityKeyURL == "" || p.KeyURL == "" {
			return fmt.Errorf("foundry: invalid saved publication bindings")
		}
	}
	if len(d.EntityPublicKey) > 0 {
		if _, err := parsePublicKey(d.EntityPublicKey); err != nil {
			return err
		}
	}
	if d.Phase == "issuance-accepted" || d.Phase == "complete" {
		if d.PublicationConfig == nil || len(d.EntityPublicKey) == 0 || d.Issuance == nil {
			return fmt.Errorf("foundry: accepted phase lacks publication and issuance")
		}
		if d.Phase == "complete" && !d.Issuance.Recovered && d.Issuance.Operation != nil && (!d.Issuance.Operation.Complete || d.Issuance.Operation.ActivationBlocked) {
			return fmt.Errorf("foundry: complete phase has unfinished coordinator state")
		}
		if !d.Issuance.Recovered && (d.Issuance.Operation == nil || d.Issuance.Operation.Submission == nil || d.Issuance.Operation.Submission.State != dnsid.SubmissionStateAccepted) {
			return fmt.Errorf("foundry: accepted phase lacks accepted issuance")
		}
		if d.Issuance.Recovered && d.Issuance.AcceptedReference != d.PublicationConfig.LogRef {
			return fmt.Errorf("foundry: recovered issuance lacks inclusion reference")
		}
	}
	if d.Proof != nil {
		if _, err := challengeTranscript(d, d.Proof.Challenge, d.Proof.ChallengeMessage); err != nil {
			return err
		}
		if d.Proof.Outcome == "submitting" && d.Proof.Signature == "" {
			return fmt.Errorf("foundry: submitted proof lacks exact signature")
		}
		if d.Proof.Signature != "" {
			signature, err := base64.RawURLEncoding.Strict().DecodeString(d.Proof.Signature)
			if err != nil {
				return err
			}
			message, err := base64.RawURLEncoding.Strict().DecodeString(d.Proof.ChallengeMessage)
			if err != nil {
				return err
			}
			if !joseutil.VerifySignature(joseutil.ProtectedHeader{Alg: dnsid.JoseAlgEdDSA}, joseutil.SignatureParts{SigningInput: message, Signature: signature}, []jwk.Key{initial}) {
				return fmt.Errorf("foundry: persisted proof signature does not match initial key")
			}
		}
		switch d.Proof.Outcome {
		case "", "submitting", "accepted":
		default:
			return fmt.Errorf("foundry: unknown proof outcome")
		}
	}
	if d.Issuance != nil && d.Issuance.PreparedBytes != "" {
		data, err := base64.RawURLEncoding.Strict().DecodeString(d.Issuance.PreparedBytes)
		if err != nil {
			return err
		}
		_, prepared, err := c2sptlog.ParsePreparedIssuance(data)
		if err != nil {
			return err
		}
		event, err := prepared.Event()
		if err != nil {
			return err
		}
		if d.PublicationConfig == nil || prepared.Reference().String() != d.PublicationConfig.LogRef || event.Domain != d.Domain || event.GovernanceID != d.GovernanceID || event.InitialOperationalThumbprint != thumb {
			return fmt.Errorf("foundry: persisted preparation binding mismatch")
		}
		ek, err := parsePublicKey(d.EntityPublicKey)
		if err != nil {
			return err
		}
		et, err := keyThumb(ek)
		if err != nil || event.InitialEntityThumbprint != et {
			return fmt.Errorf("foundry: persisted preparation entity mismatch")
		}
	}
	if d.Issuance != nil && d.Issuance.Operation != nil {
		op := d.Issuance.Operation
		initialKid, _ := initial.KeyID()
		if op.OperationalKid == "" || (initialKid != "" && op.OperationalKid != initialKid) {
			return fmt.Errorf("foundry: issuance key ID conflicts with initial key")
		}
		if op.Submission != nil && op.Submission.KeyID != "" && op.Submission.KeyID != op.OperationalKid {
			return fmt.Errorf("foundry: issuance receipt key ID mismatch")
		}
		if op.TerminalFailure && !issuanceRejection(d.Issuance.StatusCode, op.LastErrorCode) {
			return fmt.Errorf("foundry: admission error cannot be an issuance rejection")
		}
		if op.Submission != nil && op.Submission.State == dnsid.SubmissionStateRejected && !issuanceRejection(d.Issuance.StatusCode, op.Submission.ErrorCode) {
			return fmt.Errorf("foundry: unknown issuance rejection")
		}
		if len(op.EntryBytes) == 0 && (op.EntryHash != "" || op.Submission != nil) {
			return fmt.Errorf("foundry: submission facts lack exact entry bytes")
		}
		if op.Submission != nil {
			switch op.Submission.State {
			case dnsid.SubmissionStatePrepared, dnsid.SubmissionStateSubmitting, dnsid.SubmissionStatePending, dnsid.SubmissionStateIndeterminate, dnsid.SubmissionStateAccepted, dnsid.SubmissionStateRejected:
			default:
				return fmt.Errorf("foundry: unknown submission state")
			}
			if op.Submission.State == dnsid.SubmissionStateAccepted {
				if op.Submission.EntryHash != op.EntryHash || op.Submission.Index == nil {
					return fmt.Errorf("foundry: accepted receipt conflicts with exact bytes")
				}
				ref, index, err := c2sptlog.ParseFinalEventRef(dnsidlog.LogRef(op.Submission.LogRef))
				if err != nil || ref.String() != op.LogReference || index != *op.Submission.Index {
					return fmt.Errorf("foundry: accepted receipt conflicts with log reference")
				}
			}
		}
		if op.Domain != d.Domain || op.GovernanceID != d.GovernanceID || op.IdempotencyKey != IssuanceKey(d.RequestID) || op.OperationalThumbprint != thumb || d.PublicationConfig == nil || op.LogReference != d.PublicationConfig.LogRef {
			return fmt.Errorf("foundry: issuance metadata conflicts with saved bindings")
		}
		if len(op.EntryBytes) > 0 {
			sum := sha256.Sum256(op.EntryBytes)
			if op.EntryHash != hex.EncodeToString(sum[:]) {
				return fmt.Errorf("foundry: issuance entry hash mismatch")
			}
			c, p, err := c2sptlog.ParsePreparedIssuance(op.EntryBytes)
			if err != nil {
				return err
			}
			validated, err := c.PreparedEntryBytes(context.Background(), p)
			if err != nil || !bytes.Equal(validated, op.EntryBytes) {
				return fmt.Errorf("foundry: invalid persisted issuance signatures: %w", err)
			}
			event, err := p.Event()
			if err != nil {
				return err
			}
			if event.Domain != d.Domain || event.GovernanceID != d.GovernanceID || event.InitialOperationalThumbprint != thumb || p.Reference().String() != op.LogReference {
				return fmt.Errorf("foundry: persisted issuance binding mismatch")
			}
			ek, err := parsePublicKey(d.EntityPublicKey)
			if err != nil {
				return err
			}
			et, err := keyThumb(ek)
			if err != nil || event.InitialEntityThumbprint != et || op.EntityThumbprint != et {
				return fmt.Errorf("foundry: persisted issuance entity mismatch")
			}
		}
	}
	return nil
}

func parsePublicKey(raw json.RawMessage) (jwk.Key, error) {
	if err := publicJWK(raw); err != nil {
		return nil, err
	}
	return jwk.ParseKey(raw)
}

func keyThumb(key jwk.Key) (string, error) {
	if key == nil {
		return "", fmt.Errorf("foundry: public key is missing")
	}
	b, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func publicationIdentity(domain string, p *dnsid.PublicationConfig) dnsid.IdentityConfig {
	return dnsid.IdentityConfig{Domain: domain, GovernanceID: p.GovernanceID, LogRef: p.LogRef, StatusURL: p.StatusURL, KeyURL: p.KeyURL, EntityKeyURL: p.EntityKeyURL, PublishProfile: p.PublishProfile, CapabilitiesURL: p.CapabilitiesURL, MaxKeyAge: dnsid.KeyAge(p.MaxKeyAge)}
}
