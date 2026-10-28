package httpsig

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/httputil"
	"github.com/dnsid-ai/dnsid-go/internal/joseutil"
	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/digest"
	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/sfv"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const (
	maximumResponseNonceLength = 1024
	maximumResponseComponents  = 64
	// responseSignatureLifetime is fixed so peers with different MaxAge values interoperate.
	responseSignatureLifetime = 60
)

// ResponseSignatureOptions configures opt-in RFC 9421 negotiated response
// authentication. Only covered fields are authenticated: Content-Type,
// Content-Encoding, and Location are not covered unless requested explicitly.
// ExpectedDomain is local policy, independent of the HTTP endpoint hostname.
// Configure entity acceptance separately on the identity resolver.
type ResponseSignatureOptions struct {
	// ExpectedDomain is the required locally selected DNSid agent FQDN.
	ExpectedDomain string
	// AdditionalComponents requests extra authenticated metadata in caller order.
	AdditionalComponents []ComponentIdentifier
}

// requiredResponseComponents binds the response to the client's own request
// signature member, selected by key so intermediary signatures do not affect it.
func requiredResponseComponents(requestLabel string) []ComponentIdentifier {
	return []ComponentIdentifier{
		{Name: "@status"},
		{Name: "@method", Params: map[string]any{"req": true}},
		{Name: "@authority", Params: map[string]any{"req": true}},
		{Name: "@target-uri", Params: map[string]any{"req": true}},
		{Name: "accept-signature", Params: map[string]any{"req": true}},
		{Name: "signature-input", Params: map[string]any{"req": true, "key": requestLabel}},
		{Name: "signature", Params: map[string]any{"req": true, "key": requestLabel}},
		{Name: "content-digest"}, {Name: "cache-control"},
	}
}

func responsePolicy(opts ResponseSignatureOptions, requestLabel string) (ResponseSignatureOptions, []ComponentIdentifier, error) {
	domain, err := dnsid.NormalizeFQDN(opts.ExpectedDomain)
	if err != nil {
		return opts, nil, dnsid.NewArgumentError("dnsid: invalid expected response domain", err)
	}
	opts.ExpectedDomain = domain
	components := requiredResponseComponents(requestLabel)
	limits := sfv.DefaultLimits()
	if len(opts.AdditionalComponents) > maximumResponseComponents-len(components) {
		return opts, nil, dnsid.NewArgumentError("dnsid: too many response components", nil)
	}
	for _, component := range opts.AdditionalComponents {
		if len(component.Name) > limits.MaxStringLength || len(component.ParamOrder) > limits.MaxParameters {
			return opts, nil, dnsid.NewArgumentError("dnsid: response component exceeds limits", nil)
		}
		for _, value := range component.Params {
			if text, ok := value.(string); ok && len(text) > limits.MaxStringLength {
				return opts, nil, dnsid.NewArgumentError("dnsid: response component parameter exceeds limits", nil)
			}
		}
		if err := AppendComponent(&components, component); err != nil {
			return opts, nil, err
		}
		if err := checkResponseComponent(components[len(components)-1]); err != nil {
			return opts, nil, dnsid.NewArgumentError(err.Error(), nil)
		}
	}
	return opts, components, nil
}

func checkResponseComponent(component ComponentIdentifier) error {
	req := component.Params["req"] == true
	if strings.HasPrefix(component.Name, "@") && component.Name != "@status" && !req {
		return errors.New("response request-derived components require req")
	}
	// The response signature fields are written by signing, so they cannot cover themselves.
	if (component.Name == "signature" || component.Name == "signature-input") && !req {
		return errors.New("response components cannot cover response signature fields")
	}
	return nil
}

func prepareResponseNegotiation(req *http.Request, opts ResponseSignatureOptions, requestLabel string) error {
	if hasResponseHeader(req.Header, "Accept-Signature") {
		return dnsid.NewArgumentError("dnsid: Accept-Signature is already present", nil)
	}
	if req.URL == nil || req.URL.Scheme != "https" || req.URL.Host == "" {
		return dnsid.NewArgumentError("dnsid: negotiated responses require an HTTPS target", nil)
	}
	if err := boundedResponseRequest(req); err != nil {
		return dnsid.NewArgumentError("dnsid: response request exceeds input limits", err)
	}
	_, components, err := responsePolicy(opts, requestLabel)
	if err != nil {
		return err
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	inner, err := signatureParamsInnerList(SignatureParams{Components: components})
	if err != nil {
		return dnsid.NewArgumentError("dnsid: invalid response components", err)
	}
	inner.Parameters = []sfv.Parameter{{Key: "created", Value: true}, {Key: "expires", Value: true}, {Key: "nonce", Value: base64.RawURLEncoding.EncodeToString(random[:])}}
	value, err := sfv.SerializeDictionary(&sfv.Dictionary{Keys: []string{dnsidHTTPSigLabel}, Values: map[string]interface{}{dnsidHTTPSigLabel: inner}})
	if err != nil {
		return dnsid.NewArgumentError("dnsid: invalid response negotiation", err)
	}
	if len(value) > 16<<10 {
		return dnsid.NewArgumentError("dnsid: response negotiation exceeds limits", nil)
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Accept-Signature", value)
	return nil
}

func hasResponseHeader(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func responseVerificationError(message string, cause error) error {
	return dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: "+message, cause)
}

// boundedResponseHeaders applies limits before joining or parsing field values.
func boundedResponseHeaders(header http.Header) error {
	total := 0
	for name, values := range header {
		size := 0
		total += len(name)
		for _, value := range values {
			size += len(value) + 2
		}
		total += size
		if total > 1<<20 || (strings.EqualFold(name, "Accept-Signature") || strings.EqualFold(name, "Signature-Input") || strings.EqualFold(name, "Signature")) && size > 16<<10 {
			return responseVerificationError("response authentication headers exceed limits", nil)
		}
	}
	return nil
}

func boundedResponseRequest(req *http.Request) error {
	if err := boundedResponseHeaders(req.Header); err != nil {
		return err
	}
	if req.URL == nil || len(req.RequestURI)+len(req.URL.Path)+len(req.URL.RawPath)+len(req.URL.RawQuery)+len(req.URL.Host)+len(req.URL.Opaque)+len(req.Host)+len(req.Method) > 64<<10 {
		return responseVerificationError("invalid originating request target", nil)
	}
	return nil
}

func parseResponseNegotiation(req *http.Request) (SignatureParams, error) {
	if req == nil {
		return SignatureParams{}, dnsid.NewArgumentError("dnsid: nil originating request", nil)
	}
	if err := boundedResponseRequest(req); err != nil {
		return SignatureParams{}, err
	}
	value := strings.Join(req.Header.Values("Accept-Signature"), ", ")
	if err := validateUniqueDictionaryLabels(value, "Accept-Signature"); err != nil {
		return SignatureParams{}, responseVerificationError("malformed response signature request", err)
	}
	dict, err := sfv.NewParser(value, sfv.DefaultLimits()).ParseDictionary()
	if err != nil || len(dict.Keys) != 1 {
		return SignatureParams{}, responseVerificationError("expected one response signature request", err)
	}
	label := dict.Keys[0]
	inner, ok := dict.Values[label].(sfv.InnerList)
	if !ok || len(inner.Parameters) != 3 {
		return SignatureParams{}, responseVerificationError("invalid response signature request", nil)
	}
	params := SignatureParams{Label: label}
	seen := map[string]bool{}
	for _, parameter := range inner.Parameters {
		if seen[parameter.Key] {
			return params, responseVerificationError("duplicate response request parameter", nil)
		}
		seen[parameter.Key] = true
		switch parameter.Key {
		case "created", "expires":
			if parameter.Value != true {
				return params, responseVerificationError("response timestamp requests must be true", nil)
			}
		case "nonce":
			nonce, ok := parameter.Value.(string)
			if !ok || len(nonce) > maximumResponseNonceLength {
				return params, responseVerificationError("invalid response challenge", nil)
			}
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
			if err != nil || len(decoded) < 32 || base64.RawURLEncoding.EncodeToString(decoded) != nonce {
				return params, responseVerificationError("response challenge must be canonical base64url of at least 32 bytes", err)
			}
			params.Nonce = nonce
		default:
			return params, responseVerificationError("unsupported response request constraint", nil)
		}
	}
	if !seen["created"] || !seen["expires"] || !seen["nonce"] {
		return params, responseVerificationError("missing response request parameter", nil)
	}
	for _, item := range inner.Items {
		seen := map[string]bool{}
		for _, parameter := range item.Parameters {
			if seen[parameter.Key] {
				return params, responseVerificationError("duplicate response component parameter", nil)
			}
			seen[parameter.Key] = true
		}
		if name, _ := item.Value.(string); name != strings.TrimSpace(name) {
			return params, responseVerificationError("invalid response component", nil)
		}
		wire, err := sfv.SerializeItem(item)
		if err != nil {
			return params, responseVerificationError("invalid response component", err)
		}
		component, err := parseComponentIdentifier(wire)
		if err != nil {
			return params, err
		}
		if containsComponent(params.Components, component) {
			return params, responseVerificationError("duplicate response component", nil)
		}
		if err := checkResponseComponent(component); err != nil {
			return params, responseVerificationError(err.Error(), nil)
		}
		params.Components = append(params.Components, component)
	}
	if len(params.Components) > maximumResponseComponents {
		return params, responseVerificationError("too many requested response components", nil)
	}
	requestLabel, err := requestedSignatureMember(params.Components)
	if err != nil {
		return params, err
	}
	for _, required := range requiredResponseComponents(requestLabel) {
		if !containsComponent(params.Components, required) {
			return params, responseVerificationError("missing required response component", nil)
		}
	}
	return params, nil
}

// requestedSignatureMember returns the one request signature member that the
// negotiation binds through matching signature-input and signature keys.
func requestedSignatureMember(components []ComponentIdentifier) (string, error) {
	keys := map[string][]string{}
	for _, component := range components {
		key, keyed := component.Params["key"].(string)
		if component.Params["req"] == true && keyed && (component.Name == "signature-input" || component.Name == "signature") {
			keys[component.Name] = append(keys[component.Name], key)
		}
	}
	if len(keys["signature-input"]) != 1 || len(keys["signature"]) != 1 || keys["signature-input"][0] != keys["signature"][0] {
		return "", responseVerificationError("response negotiation must bind one request signature member", nil)
	}
	return keys["signature"][0], nil
}

func checkHTTPSignatureFreshness(created, expires int64, hasExpires bool, cfg Config, now time.Time) error {
	start := time.Unix(created, 0)
	if start.After(now.Add(cfg.ClockSkew)) || now.Sub(start) > cfg.MaxAge {
		return dnsid.NewVerificationError(dnsid.VerificationCodeTokenExpired, false, "dnsid: HTTP signature is outside freshness window", nil)
	}
	if hasExpires && (expires < created || expires-created > int64(cfg.MaxAge/time.Second) || now.After(time.Unix(expires, 0).Add(cfg.ClockSkew))) {
		return dnsid.NewVerificationError(dnsid.VerificationCodeTokenExpired, false, "dnsid: HTTP signature has invalid or expired lifetime", nil)
	}
	return nil
}

// checkResponseFreshness applies the fixed response lifetime and local freshness.
func checkResponseFreshness(params SignatureParams, cfg Config, now time.Time) error {
	if lifetime := params.Expires - params.Created; lifetime <= 0 || lifetime > responseSignatureLifetime {
		return dnsid.NewVerificationError(dnsid.VerificationCodeTokenExpired, false, "dnsid: response signature lifetime must be 1 to 60 seconds", nil)
	}
	if err := checkHTTPSignatureFreshness(params.Created, 0, false, cfg, now); err != nil {
		return err
	}
	if now.After(time.Unix(params.Expires, 0).Add(cfg.ClockSkew)) {
		return dnsid.NewVerificationError(dnsid.VerificationCodeTokenExpired, false, "dnsid: response signature has expired", nil)
	}
	return nil
}

// finalResponse rejects informational responses and tunnels. An Upgrade field on
// a final response only advertises protocols, so it is not rejected.
func finalResponse(req *http.Request, res *http.Response) error {
	if res == nil {
		return dnsid.NewArgumentError("dnsid: nil HTTP response", nil)
	}
	if res.StatusCode < 200 || res.StatusCode > 599 || req.Method == http.MethodConnect && res.StatusCode < 300 {
		return responseVerificationError("response is not an ordinary final HTTP response", nil)
	}
	if res.Uncompressed {
		return responseVerificationError("response content was transparently decoded", nil)
	}
	return boundedResponseHeaders(res.Header)
}

func responseContent(ctx context.Context, req *http.Request, res *http.Response) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Method == http.MethodHead || noResponseContent(res.StatusCode) {
		return []byte{}, nil
	}
	if res.Body == nil {
		return nil, responseVerificationError("ordinary response content is unavailable", nil)
	}
	original := res.Body
	stop := context.AfterFunc(ctx, func() { _ = original.Close() })
	defer stop()
	body, err := readBoundedBody(original)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return body, err
}

func verifyResponseContentDigest(body []byte, value string) error {
	if err := validateUniqueDictionaryLabels(value, "Content-Digest"); err != nil {
		return err
	}
	dict, err := sfv.NewParser(value, sfv.DefaultLimits()).ParseDictionary()
	if err != nil {
		return err
	}
	for _, member := range dict.Values {
		item, ok := member.(sfv.Item)
		if !ok {
			return fmt.Errorf("content digest member must be a byte sequence")
		}
		if _, ok := item.Value.([]byte); !ok {
			return fmt.Errorf("content digest member must be a byte sequence")
		}
	}
	item, ok := dict.Values["sha-256"].(sfv.Item)
	if !ok {
		return fmt.Errorf("missing SHA-256 content digest")
	}
	selected, err := sfv.SerializeItem(sfv.Item{Value: item.Value})
	if err != nil {
		return err
	}
	return digest.VerifyContentDigestBytes(body, "sha-256="+selected, []string{"sha-256"})
}

func replayResponseContent(res *http.Response, body []byte) {
	original := res.Body
	if original == nil {
		original = http.NoBody
	}
	res.Body = httputil.ReplayBody(body, original)
}

// hasNoStore recognizes an unvalued directive outside quoted cache extensions.
func hasNoStore(value string) bool {
	quoted, escaped, start := false, false, 0
	for i := 0; i <= len(value); i++ {
		if i == len(value) || value[i] == ',' && !quoted {
			if strings.ToLower(strings.Trim(value[start:i], " \t")) == "no-store" {
				return true
			}
			start = i + 1
			continue
		}
		if escaped {
			escaped = false
		} else if quoted && value[i] == '\\' {
			escaped = true
		} else if value[i] == '"' {
			quoted = !quoted
		}
	}
	return false
}

// SignRequestedHTTPResponse fulfills one DNSid Accept-Signature request using
// the current operational key. No negotiation returns res unchanged, even for
// verification-only profiles. On success it returns a copy with finalized fields
// and replayable content. Call before sending headers, after content coding;
// middleware must not change covered bytes afterward. It does not authenticate
// or authorize the caller. Failures must not become unsigned-success fallbacks.
func (p *Profile) SignRequestedHTTPResponse(req *http.Request, res *http.Response) (*http.Response, error) {
	if req == nil || res == nil {
		return nil, dnsid.NewArgumentError("dnsid: request and response are required", nil)
	}
	if !hasResponseHeader(req.Header, "Accept-Signature") {
		return res, nil
	}
	params, err := parseResponseNegotiation(req)
	if err != nil {
		return nil, err
	}
	if err := finalResponse(req, res); err != nil {
		return nil, err
	}
	if err := p.requireLocalIdentity(); err != nil {
		return nil, err
	}
	if _, err := p.httpSignatureConfig(); err != nil {
		return nil, err
	}
	for _, name := range []string{"Signature-Input", "Signature"} {
		value := strings.Join(res.Header.Values(name), ", ")
		if value == "" {
			continue
		}
		if name == "Signature-Input" {
			members, err := ParseSignatureInput(value)
			if err != nil {
				return nil, err
			}
			if _, collision := members[params.Label]; collision {
				return nil, responseVerificationError("requested response label already exists", nil)
			}
		} else {
			members, err := ParseSignature(value)
			if err != nil {
				return nil, err
			}
			if _, collision := members[params.Label]; collision {
				return nil, responseVerificationError("requested response label already exists", nil)
			}
		}
	}
	kid, alg, err := joseutil.ActiveSigningMetadata(p.keys)
	if err != nil {
		return nil, err
	}
	if strings.Contains(kid, "#") {
		return nil, dnsid.NewArgumentError("dnsid: signing key kid must not contain '#'", nil)
	}
	params.Alg, err = JoseAlgToHTTPSigAlg(alg)
	if err != nil {
		return nil, err
	}
	params.KeyID = p.localDomain + "#" + kid
	params.ExpectedSignerKid, params.ExpectedSignerAlg = kid, alg
	params.Created = time.Now().Unix()
	params.Expires = params.Created + responseSignatureLifetime
	ctx, cancel := dnsid.VerificationContext(req.Context())
	defer cancel()
	body, err := responseContent(ctx, req, res)
	if err != nil {
		return nil, err
	}
	// Retain the caller's stream and cleanup if signing fails after buffering.
	replayResponseContent(res, body)
	signed := *res
	signed.Header = res.Header.Clone()
	if signed.Header == nil {
		signed.Header = make(http.Header)
	}
	signed.Request = req
	signed.Header.Set("Content-Digest", contentDigest(body))
	cache := strings.Join(signed.Header.Values("Cache-Control"), ", ")
	if !hasNoStore(cache) {
		if cache != "" {
			cache += ", "
		}
		cache += "no-store"
	}
	if !hasNoStore(cache) {
		return nil, responseVerificationError("cannot append no-store to malformed cache policy", nil)
	}
	signed.Header.Set("Cache-Control", cache)
	if _, err := BuildSignatureInput(&signed, params); err != nil {
		return nil, responseVerificationError("cannot resolve requested response components", err)
	}
	if err := SignHTTPMessage(&signed, params, p.keys); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := boundedResponseHeaders(signed.Header); err != nil {
		return nil, err
	}
	return &signed, nil
}

// VerifySignedHTTPResponse verifies the requested label against local policy and
// the saved originating request, never res.Request. The caller must retain an
// unmodified prepared request and an independent original options snapshot when
// using standalone helpers. Supply only trusted current-connection peer evidence
// in peer; discovery certificates cannot substitute for it. Response TLS evidence
// is used when peer is omitted. Rejected response bodies are closed. On success
// the content is restored for the caller, who owns closing it.
func (p *Profile) VerifySignedHTTPResponse(ctx context.Context, req *http.Request, res *http.Response, opts ResponseSignatureOptions, peer ...dnsid.VerifyDomainOpts) (verified *dnsid.VerifiedDomain, err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	defer func() {
		if err != nil && res != nil && res.Body != nil {
			_ = res.Body.Close()
		}
	}()
	if _, _, err := responsePolicy(opts, dnsidHTTPSigLabel); err != nil {
		return nil, err
	}
	requested, err := parseResponseNegotiation(req)
	if err != nil {
		return nil, err
	}
	requestLabel, err := requestedSignatureMember(requested.Components)
	if err != nil {
		return nil, err
	}
	opts, required, err := responsePolicy(opts, requestLabel)
	if err != nil {
		return nil, err
	}
	if scheme, _ := httpScheme(req); scheme != "https" {
		return nil, dnsid.NewArgumentError("dnsid: negotiated responses require HTTPS", nil)
	}
	for _, component := range required {
		if !containsComponent(requested.Components, component) {
			return nil, responseVerificationError("saved negotiation omits local response policy", nil)
		}
	}
	if err := finalResponse(req, res); err != nil {
		return nil, err
	}
	inputs, err := ParseSignatureInput(strings.Join(res.Header.Values("Signature-Input"), ", "))
	if err != nil {
		return nil, err
	}
	signatures, err := ParseSignature(strings.Join(res.Header.Values("Signature"), ", "))
	if err != nil {
		return nil, err
	}
	params, found := inputs[requested.Label]
	signature, complete := signatures[requested.Label]
	if !found || !complete || !slices.EqualFunc(params.Components, requested.Components, componentEqual) || params.Nonce != requested.Nonce {
		return nil, responseVerificationError("response label, components, or challenge do not match", nil)
	}
	cfg, err := p.httpSignatureConfig()
	if err != nil {
		return nil, err
	}
	if !hasSignatureParameter(params, "created") || !hasSignatureParameter(params, "expires") || (params.Alg != "ed25519" && params.Alg != "ecdsa-p256-sha256") {
		return nil, responseVerificationError("response requires timestamps and a supported algorithm", nil)
	}
	if err := checkResponseFreshness(params, cfg, time.Now()); err != nil {
		return nil, err
	}
	domain, kid, err := joseutil.SplitDNSIDKid(params.KeyID)
	if err != nil || domain != opts.ExpectedDomain {
		return nil, responseVerificationError("unexpected response signer domain", err)
	}
	if len(peer) > 1 {
		return nil, dnsid.NewArgumentError("dnsid: at most one current-peer context is supported", nil)
	}
	peerOpts := dnsid.VerifyDomainOpts{}
	if len(peer) == 1 {
		peerOpts = peer[0]
	} else if res.TLS != nil {
		peerOpts.PeerCertificate = peerCertificateFromRequest(&http.Request{TLS: res.TLS})
		peerOpts.VerifiedPeerCertificateChains = res.TLS.VerifiedChains
	}
	acquiredAfter := time.Now()
	vd, err := dnsid.VerifyIdentity(ctx, p.resolver, opts.ExpectedDomain, peerOpts)
	if err != nil {
		return nil, err
	}
	key, ok := joseutil.LookupJWKByKid(vd.KeySet().Raw(), kid)
	if !ok || !joseutil.SigningKeyEligible(key) {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeKeyNotFound, false, "dnsid: response operational key not found", nil)
	}
	keyAlg, ok := joseutil.AlgForJWK(key)
	httpAlg, algErr := JoseAlgToHTTPSigAlg(keyAlg)
	if !ok || !joseutil.JWKMatchesAlg(key, keyAlg) || algErr != nil || params.Alg != httpAlg {
		return nil, responseVerificationError("response key algorithm mismatch", algErr)
	}
	actual := *res
	actual.Request = req
	base, err := BuildSignatureInput(&actual, params)
	if err != nil {
		return nil, responseVerificationError("cannot resolve response components", err)
	}
	parts := joseutil.SignatureParts{SigningInput: []byte(base), Signature: signature}
	if !joseutil.VerifySignature(joseutil.ProtectedHeader{Alg: keyAlg, Kid: kid}, parts, []jwk.Key{key}) {
		return nil, responseVerificationError("invalid response signature", nil)
	}
	body, err := responseContent(ctx, req, res)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var verification *dnsid.VerificationError
		if errors.As(err, &verification) {
			return nil, err
		}
		return nil, responseVerificationError("cannot read response content", err)
	}
	if err := verifyResponseContentDigest(body, strings.Join(res.Header.Values("Content-Digest"), ", ")); err != nil {
		return nil, responseVerificationError("response content-digest mismatch", err)
	}
	if !hasNoStore(strings.Join(res.Header.Values("Cache-Control"), ", ")) {
		return nil, responseVerificationError("response requires signed Cache-Control: no-store", nil)
	}
	if err := checkResponseFreshness(params, cfg, time.Now()); err != nil {
		return nil, err
	}
	if err := vd.CheckFreshness(acquiredAfter); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	replayResponseContent(res, body)
	return vd, nil
}

func snapshotComponents(components []ComponentIdentifier) []ComponentIdentifier {
	out := slices.Clone(components)
	for i := range out {
		out[i].ParamOrder = slices.Clone(out[i].ParamOrder)
		if out[i].Params != nil {
			out[i].Params = make(map[string]any, len(components[i].Params))
			for key, value := range components[i].Params {
				out[i].Params[key] = value
			}
		}
	}
	return out
}

func (p *Profile) negotiatedHTTPClient(base *http.Client, opts SigningOptions) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	policy := *opts.ResponseSignature
	policy.AdditionalComponents = snapshotComponents(policy.AdditionalComponents)
	opts.ResponseSignature = &policy
	opts.AdditionalComponents = slices.Clone(opts.AdditionalComponents)
	opts.AdditionalComponentIDs = snapshotComponents(opts.AdditionalComponentIDs)
	transport := base.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if standard, ok := transport.(*http.Transport); ok {
		// Verification needs the exact content bytes, so the SDK never decodes them.
		isolated := standard.Clone()
		isolated.DisableCompression = true
		if isolated.MaxResponseHeaderBytes <= 0 || isolated.MaxResponseHeaderBytes > 1<<20 {
			isolated.MaxResponseHeaderBytes = 1 << 20
		}
		transport = isolated
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Transport = httpRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		dispatched := false
		defer func() {
			if !dispatched && req.Body != nil {
				_ = req.Body.Close()
			}
		}()
		if p == nil || p.resolver == nil {
			return nil, dnsid.NewArgumentError("dnsid: IdentityResolver is required for negotiated clients", nil)
		}
		ctx, cancel := dnsid.VerificationContext(req.Context())
		defer cancel()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		originalBody := req.Body
		stop := context.AfterFunc(ctx, func() {
			if originalBody != nil {
				_ = originalBody.Close()
			}
		})
		signed, err := p.CreateSignedHTTPRequest(req, opts)
		stop()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, err
		}
		signed = signed.WithContext(ctx)
		snapshot := signed.Clone(ctx)
		snapshot.Body, snapshot.GetBody = nil, nil
		signed.GetBody = nil
		dispatched = true
		res, err := transport.RoundTrip(signed)
		if err != nil {
			if res != nil && res.Body != nil {
				_ = res.Body.Close()
			}
			return nil, err
		}
		if _, err := p.VerifySignedHTTPResponse(ctx, snapshot, res, policy); err != nil {
			return nil, fmt.Errorf("dnsid: negotiated response rejected: %w", err)
		}
		// The full bounded body has been verified. Release the connection before
		// ending its budget; the application receives only an owned memory reader.
		body, readErr := readBoundedBody(res.Body)
		closeErr := res.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		res.Body = io.NopCloser(bytes.NewReader(body))
		return res, nil
	})
	return &client
}
