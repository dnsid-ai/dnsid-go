//go:build dnsid_foundry

package foundry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/joseutil"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func challengeTranscript(doc *RecoveryDocument, challenge, message string) (*dnsid.LiveChallengeTranscript, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(message)
	if err != nil {
		return nil, err
	}
	if _, err := decodeObject(decoded); err != nil {
		return nil, err
	}
	var transcript dnsid.LiveChallengeTranscript
	if err := json.Unmarshal(decoded, &transcript); err != nil {
		return nil, err
	}
	initial, err := parsePublicKey(doc.InitialPublicKey)
	if err != nil {
		return nil, err
	}
	thumb, err := keyThumb(initial)
	if err != nil {
		return nil, err
	}
	domain, err := dnsid.NormalizeFQDN(transcript.FQDN)
	if err != nil || transcript.Protocol != "dnsid-live-provisioning-pop/v1" || transcript.OrgID != doc.OrganizationID || transcript.AgentID != doc.IdentityID || transcript.KeyID != thumb || transcript.Nonce != challenge || challenge == "" || transcript.ExpiresAt.IsZero() || (doc.Domain != "" && doc.Domain != domain) {
		return nil, fmt.Errorf("foundry: Live challenge does not match account, identity, key, domain, or nonce")
	}
	transcript.FQDN = domain
	return &transcript, nil
}

func recordChallenge(doc *RecoveryDocument, response *dnsid.LiveProvisioningResponse) error {
	domain := ""
	if response.Domain != "" {
		normalized, err := dnsid.NormalizeFQDN(response.Domain)
		if err != nil {
			return failure(Integrity, doc, err)
		}
		domain = normalized
	}
	if response.Challenge != "" || response.ChallengeMessage != "" || response.Status == "challenge_pending" {
		transcript, err := challengeTranscript(doc, response.Challenge, response.ChallengeMessage)
		if err != nil {
			return failure(Integrity, doc, err)
		}
		if domain != "" && domain != transcript.FQDN {
			return failure(Integrity, doc, fmt.Errorf("wire domain conflicts with challenge"))
		}
		domain = transcript.FQDN
		doc.Proof = &ProofState{Challenge: response.Challenge, ChallengeMessage: response.ChallengeMessage}
		doc.Phase = "proof-pending"
	} else if domain != "" {
		doc.Phase = "identity-known"
	}
	if doc.Domain != "" && domain != "" && domain != doc.Domain {
		return failure(Integrity, doc, fmt.Errorf("live response changed domain"))
	}
	if domain != "" {
		doc.Domain = domain
	}
	return nil
}

func (i *FoundryIdentity) prove(ctx context.Context, lease FoundryLease, doc *RecoveryDocument) error {
	// A lost proof response may already have advanced the server workflow.
	if doc.Proof.Outcome == "submitting" {
		detail, err := i.client.readDetail(ctx, lease, doc)
		if err != nil {
			return err
		}
		if detail.Status == "VERIFIED" || detail.Status == "READY" {
			doc.Proof.Outcome = "accepted"
			doc.Phase = "identity-known"
			return lease.Save(ctx, doc)
		}
	}
	transcript, err := challengeTranscript(doc, doc.Proof.Challenge, doc.Proof.ChallengeMessage)
	if err != nil {
		return failure(Integrity, doc, err)
	}
	if !time.Now().Before(transcript.ExpiresAt) {
		response, err := i.client.deps.RegistryClient.ReissueLiveProof(ctx, doc.Domain, &dnsid.LiveProofReissueRequest{RequestID: doc.RequestID, PublicKey: doc.InitialPublicKey})
		var api *dnsid.RegistryAPIError
		if errors.As(err, &api) && api.StatusCode == http.StatusConflict {
			if _, err := i.client.waitForRegistryReady(ctx, lease, doc); err != nil {
				return err
			}
			doc.Proof.Outcome = "accepted"
			doc.Phase = "identity-known"
			return lease.Save(ctx, doc)
		}
		if err != nil {
			return i.client.wrap(doc, err)
		}
		if response == nil || response.RequestID != doc.RequestID || response.AgentID != doc.IdentityID || response.Status != "challenge_pending" {
			return failure(Integrity, doc, fmt.Errorf("invalid proof reissue response"))
		}
		if err := recordChallenge(doc, &dnsid.LiveProvisioningResponse{RequestID: response.RequestID, AgentID: response.AgentID, Status: response.Status, Challenge: response.Challenge, ChallengeMessage: response.ChallengeMessage, Domain: response.Domain}); err != nil {
			return err
		}
		if err := lease.Save(ctx, doc); err != nil {
			return i.client.wrap(doc, err)
		}
	}
	if doc.Proof.Signature == "" {
		message, err := base64.RawURLEncoding.Strict().DecodeString(doc.Proof.ChallengeMessage)
		if err != nil {
			return failure(Integrity, doc, err)
		}
		signature, err := (deadlineProvider{KeyProvider: i.signer.KeyProvider, ctx: ctx}).Sign(message)
		if err != nil {
			return i.client.wrap(doc, err)
		}
		if signature == nil {
			return failure(Integrity, doc, fmt.Errorf("provider returned no proof signature"))
		}
		key, err := parsePublicKey(doc.InitialPublicKey)
		if err != nil {
			return err
		}
		kid, _ := key.KeyID()
		if signature.Kid != kid || signature.Alg != dnsid.JoseAlgEdDSA {
			return failure(KeyMismatch, doc, fmt.Errorf("proof signer differs from initial key"))
		}
		if !joseutil.VerifySignature(joseutil.ProtectedHeader{Alg: signature.Alg}, joseutil.SignatureParts{SigningInput: message, Signature: signature.Signature}, []jwk.Key{key}) {
			return failure(Integrity, doc, fmt.Errorf("provider returned an invalid proof signature"))
		}
		doc.Proof.Signature = base64.RawURLEncoding.EncodeToString(signature.Signature)
	}
	doc.Proof.Outcome = "submitting"
	if err := lease.Save(ctx, doc); err != nil {
		return i.client.wrap(doc, err)
	}
	response, err := i.client.deps.RegistryClient.SubmitLiveProof(ctx, doc.Domain, &dnsid.LiveProofRequest{RequestID: doc.RequestID, Challenge: doc.Proof.Challenge, PublicKey: doc.InitialPublicKey, Signature: doc.Proof.Signature})
	if err != nil {
		return i.client.wrap(doc, err)
	}
	if response == nil || response.RequestID != doc.RequestID || response.AgentID != doc.IdentityID || response.Status == "" {
		return failure(Integrity, doc, fmt.Errorf("invalid proof response"))
	}
	doc.Proof.Outcome = "accepted"
	doc.Phase = "identity-known"
	return lease.Save(ctx, doc)
}
