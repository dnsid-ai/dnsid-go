#!/usr/bin/env bash
# Regenerates the committed markdown API reference in docs/reference/.
#
# Output is consumed by the docs site (docs.dnsid.ai) under
# src/content/docs/reference/go/ and also
# renders on GitHub. Never hand-edit docs/reference/ — edit the Go doc
# comments and re-run this script. See docs/AGENTS.md.
set -euo pipefail

cd "$(dirname "$0")/.."

GOMARKDOC="go run github.com/princjef/gomarkdoc/cmd/gomarkdoc@v1.1.0"
REPO_URL=https://github.com/dnsid-ai/dnsid-go
OUT_DIR=docs/reference
SITE=https://docs.dnsid.ai

# Nav labels follow the reader-topic naming shared with the TypeScript and
# Python references ("Profile: JOSE", "Registry", ...); NAV_ORDER below gives
# the shared cross-SDK ordering.

# The root package is large, so its single gomarkdoc page is split into topic
# pages (scripts/split-root-reference.awk): slug | nav label | title | description
ROOT_PAGES=(
	"dnsid|Core: IdentityManager|Go: package dnsid|IdentityManager, domain verification, configuration, transport, and caching for the DNSid Go SDK."
	"dnsid-records|Records & keys|Go: dnsid — records & keys|TXT identity records, JWKS and JWK types, policy flags, and record parsing helpers."
	"dnsid-keys|Key providers|Go: dnsid — key providers|KeyProvider implementations, key metadata, and log-event signing."
	"dnsid-registry|Registry|Go: dnsid — registry client|HTTPRegistryClient, publication workflows, and registry request/response types."
	"dnsid-errors|Errors & enums|Go: dnsid — errors|Typed errors and verification codes returned across the SDK."
)

# Every top-level section of the root package page must be assigned a topic
# page here; the splitter fails on unmapped sections so new exports can't
# silently land on the wrong page. "Constants" and "Variables" are the
# gomarkdoc section names.
root_map() {
	cat <<'EOF'
Constants dnsid
Variables dnsid
CreateDnsidHTTPClient dnsid
NewVerifier dnsid
NormalizeFQDN dnsid
RegistrantDomain dnsid
SafeDialerTransport dnsid
SDKConformanceMetadata dnsid
Tags dnsid
AgentState dnsid
AgentStatus dnsid
DNSResolver dnsid
DNSSECMode dnsid
DNSSECState dnsid
FetchOptions dnsid
HTTPSFetcher dnsid
IdentityCache dnsid
IdentityManager dnsid
IdentityManagerOption dnsid
IdentityResolver dnsid
Config dnsid
IdentityConfig dnsid
VerificationConfig dnsid
TrustedEntity dnsid
RedirectPolicy dnsid
RegistryConfig dnsid
TransportConfig dnsid
VerifiedDomain dnsid
VerificationContext dnsid
VerifyIdentity dnsid
VerifyDomainOpts dnsid
ParseJWKSet dnsid-records
ParseLogRef dnsid-records
DNSRecord dnsid-records
JWK dnsid-records
JWKS dnsid-records
JoseAlg dnsid-records
PolicyFlag dnsid-records
TXTRecord dnsid-records
TXTRecordRData dnsid-records
SignLogEventWithKey dnsid-keys
KeyAge dnsid-keys
KeyProvider dnsid-keys
KeySignature dnsid-keys
LocalKeyProvider dnsid-keys
LogEventCanonicalizer dnsid-keys
LogSignerRole dnsid-keys
AgentDetail dnsid-registry
AgentEvent dnsid-registry
AgentListItem dnsid-registry
AgentListResponse dnsid-registry
AgentRegistration dnsid-registry
AgentRegistrationInput dnsid-registry
CanonicalRecordContentResponse dnsid-registry
ChallengeRequest dnsid-registry
CreateAgentRequest dnsid-registry
CreateAgentResponse dnsid-registry
LiveAgentRegistrationInput dnsid-registry
LiveChallengeTranscript dnsid-registry
LiveProvisioningResponse dnsid-registry
LiveProofRequest dnsid-registry
LiveProofResponse dnsid-registry
LiveProofReissueRequest dnsid-registry
LiveProofReissueResponse dnsid-registry
PublicationConfig dnsid-registry
EventListOptions dnsid-registry
EventListResponse dnsid-registry
HTTPRegistryClient dnsid-registry
IdentityRecordRequest dnsid-registry
IdentityRecordResponse dnsid-registry
KeyRotationPreparationRequest dnsid-registry
LifecycleResponse dnsid-registry
ListAgentsOptions dnsid-registry
OperationsAgent dnsid-registry
OperationsAgentListResponse dnsid-registry
PreparedRegistryEvent dnsid-registry
PublicationAuthority dnsid-registry
PublishedRecord dnsid-registry
RegistryClient dnsid-registry
RegistryClientControlledPublisher dnsid-registry
RegistryClientOption dnsid-registry
RegistryPreparedEventClient dnsid-registry
RegistryPublisher dnsid-registry
RegistryRegistrationReader dnsid-registry
RegistryRevoker dnsid-registry
RegistryRevocationReason dnsid-registry
RegistryStatusReader dnsid-registry
RetireAgentRequest dnsid-registry
RevokeAgentRequest dnsid-registry
SignatureRequest dnsid-registry
SignatureResponse dnsid-registry
SubmissionResult dnsid-registry
SubmissionState dnsid-registry
VerifyDomainRequest dnsid-registry
VerifyDomainResponse dnsid-registry
WaitForStatusOptions dnsid-registry
NewArgumentError dnsid-errors
NewParseError dnsid-errors
MissingRequiredField dnsid-errors
AgentError dnsid-errors
ArgumentError dnsid-errors
ParseError dnsid-errors
RegistryAPIError dnsid-errors
RegistryWorkflowError dnsid-errors
ValidationError dnsid-errors
VerificationCode dnsid-errors
VerificationError dnsid-errors
VerificationErrorOption dnsid-errors
EOF
}

# page slug | module dir | package dir within module | nav label | description
PACKAGES=(
	"config|.|./config|Configuration|Load DNSid SDK configuration from DNSID_* environment variables and DNSid CLI directories; loaders parse, constructors default."
	"jose|.|./jose|Profile: JOSE|DNSid JOSE profile: create and verify DNSid JWTs and compact JWS."
	"oidc|.|./oidc|Profile: OIDC|Mint and verify DNSid OIDC tokens."
	"httpsig|.|./httpsig|Profile: HTTP signatures|RFC 9421 HTTP Message Signatures for DNSid agents."
	"webbotauth|.|./webbotauth|Profile: Web Bot Auth|Web Bot Auth profile: RFC 9421-signed HTTP requests identifying a DNSid agent."
	"log|.|./log|Lifecycle log|Agent lifecycle log abstractions for DNSid."
	"log-c2sptlog|.|./log/c2sptlog|Transparency log|C2SP transparency-log (tlog) client support for DNSid lifecycle logs."
	"key-aws|key/aws|.|Key providers: AWS KMS|AWS KMS-backed key provider for DNSid."
)

# Docs-site nav (and overview package-map) order — the shared cross-SDK
# topical ordering. Must contain every generated page exactly once.
NAV_ORDER=(
	overview
	dnsid
	config
	dnsid-records
	jose
	httpsig
	webbotauth
	oidc
	dnsid-keys
	key-aws
	dnsid-registry
	log
	log-c2sptlog
	dnsid-errors
)

mkdir -p "$OUT_DIR"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ROOT_MODULE="$(go list -m)"

banner() { # import path of the package the page documents
	printf '> Generated from the Go source by scripts/gen-docs.sh — do not edit; run it to regenerate.\n'
	printf '> Canonical deep reference: [pkg.go.dev/%s](https://pkg.go.dev/%s).\n' "$1" "$1"
	printf '> Guides and account setup: [https://docs.dnsid.ai](https://docs.dnsid.ai).\n\n'
}

frontmatter() { # title, description
	printf -- '---\n'
	printf 'title: "%s"\n' "$1"
	printf 'description: "%s"\n' "$2"
	printf -- '---\n\n'
}

# slug|label|description for every generated page, for nav + overview assembly.
pages_meta=("overview|Overview|Package map for the DNSid Go SDK and where to start.")

# --- root package: generate once, split into topic pages --------------------

$GOMARKDOC \
	--output "$tmp/root-raw.md" \
	--repository.url "$REPO_URL" \
	--repository.default-branch main \
	--repository.path "/" \
	.

root_map >"$tmp/root-map"
awk -v outdir="$tmp" -v site="$SITE" \
	-f scripts/split-root-reference.awk "$tmp/root-map" "$tmp/root-raw.md"

for entry in "${ROOT_PAGES[@]}"; do
	IFS='|' read -r slug label title desc <<<"$entry"
	body="$tmp/body-$slug.md"
	if [ ! -s "$body" ]; then
		echo "gen-docs.sh: no content routed to root topic page '$slug'" >&2
		exit 1
	fi
	{
		frontmatter "$title" "$desc"
		banner "$ROOT_MODULE"
		if [ "$slug" != "dnsid" ]; then
			printf 'Part of the root package `%s` — see [Core: IdentityManager](%s/reference/go/dnsid) for the package overview.\n\n' "$ROOT_MODULE" "$SITE"
		fi
		# Drop gomarkdoc's own H1 — the frontmatter title is the page heading.
		awk 'firsth1==0 && /^# / {firsth1=1; next} {print}' "$body"
	} >"$OUT_DIR/$slug.md"
	pages_meta+=("$slug|$label|$desc")
done

# --- remaining packages: one page each ---------------------------------------

for entry in "${PACKAGES[@]}"; do
	IFS='|' read -r slug moddir pkgdir label desc <<<"$entry"

	# Import path of the documented package, e.g.
	# github.com/dnsid-ai/dnsid-go/log/c2sptlog
	modpath="$(cd "$moddir" && go list -m)"
	if [ "$pkgdir" = "." ]; then
		import="$modpath"
	else
		import="$modpath/${pkgdir#./}"
	fi

	pkgname="$(cd "$moddir" && go list -f '{{.Name}}' "$pkgdir")"

	repo_path="/"
	[ "$moddir" != "." ] && repo_path="/$moddir/"

	raw="$tmp/$slug.md"
	(cd "$moddir" && $GOMARKDOC \
		--output "$raw" \
		--repository.url "$REPO_URL" \
		--repository.default-branch main \
		--repository.path "$repo_path" \
		"$pkgdir")

	out="$OUT_DIR/$slug.md"
	{
		frontmatter "Go: package $pkgname" "$desc"
		banner "$import"
		# Drop gomarkdoc's own H1 ("# pkgname") — the docs site renders the
		# frontmatter title as the page heading.
		awk 'firsth1==0 && /^# / {firsth1=1; next} {print}' "$raw"
	} >"$out"

	pages_meta+=("$slug|$label|$desc")
done

# --- overview + nav in NAV_ORDER ---------------------------------------------

meta_for() { # slug -> "slug|label|desc"; fails if unknown
	local want=$1 entry
	for entry in "${pages_meta[@]}"; do
		[ "${entry%%|*}" = "$want" ] && { printf '%s' "$entry"; return 0; }
	done
	echo "gen-docs.sh: NAV_ORDER references unknown page '$want'" >&2
	exit 1
}

if [ "${#NAV_ORDER[@]}" -ne "${#pages_meta[@]}" ]; then
	echo "gen-docs.sh: NAV_ORDER (${#NAV_ORDER[@]}) and generated pages (${#pages_meta[@]}) disagree — every page must appear exactly once" >&2
	exit 1
fi

{
	frontmatter "Go: SDK overview" "Package map for the DNSid Go SDK and where to start."
	banner "$ROOT_MODULE"
	printf 'The Go SDK is the module `%s`, plus the separately tagged `key/aws` submodule. Install it with:\n\n' "$ROOT_MODULE"
	printf '```bash\ngo get %s\n```\n\n' "$ROOT_MODULE"
	printf 'Start with the root package: `IdentityManager` is the facade for verifying domains, creating and publishing identity records, and loading the agent identity your application acts as. The root package is documented across the `dnsid` pages below; the other packages are application profiles and infrastructure you pull in as needed.\n\n'
	printf '| Page | What it covers |\n'
	printf '| --- | --- |\n'
	for slug in "${NAV_ORDER[@]}"; do
		[ "$slug" = "overview" ] && continue
		IFS='|' read -r _ label desc <<<"$(meta_for "$slug")"
		printf '| [%s](%s/reference/go/%s) | %s |\n' "$label" "$SITE" "$slug" "$desc"
	done
	printf '\nFor a guided first verification see the [Quickstart](%s/quickstart); for multi-language walkthroughs of verification, OIDC tokens, and freshness see the [Libraries overview](%s/sdk-overview).\n' "$SITE" "$SITE"
} >"$OUT_DIR/overview.md"

# Ordered nav fragment imported by the docs site's nav.mjs.
{
	printf '[\n'
	last=$((${#NAV_ORDER[@]} - 1))
	for i in "${!NAV_ORDER[@]}"; do
		IFS='|' read -r slug label _ <<<"$(meta_for "${NAV_ORDER[$i]}")"
		sep=','
		[ "$i" -eq "$last" ] && sep=''
		printf '  { "label": "%s", "slug": "reference/go/%s" }%s\n' "$label" "$slug" "$sep"
	done
	printf ']\n'
} >"$OUT_DIR/nav.json"

echo "Generated ${#pages_meta[@]} reference pages + nav.json in $OUT_DIR/"
