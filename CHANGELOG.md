# Changelog

## [0.33.2] - 2026-09-21

### Bug Fixes

- fix: correct codeowners ([#9](https://github.com/dnsid-ai/dnsid-go/pull/9))

### Documentation

- docs: describe registration positively ([#15](https://github.com/dnsid-ai/dnsid-go/pull/15))

### Testing

- ci: use sdk-compliance workflow from main instead of pinned sha ([#10](https://github.com/dnsid-ai/dnsid-go/pull/10))
- ci: sign release PR commits via GitHub API ([#12](https://github.com/dnsid-ai/dnsid-go/pull/12))
- ci: sign regenerated-docs commits via GitHub API ([#13](https://github.com/dnsid-ai/dnsid-go/pull/13))

### Chores

- Bump golang.org/x/mod from 0.38.0 to 0.41.0 ([#4](https://github.com/dnsid-ai/dnsid-go/pull/4))
- Chore/public release cleanup ([#16](https://github.com/dnsid-ai/dnsid-go/pull/16))

### Other

- registry: default CreateAgent environment to production ([#14](https://github.com/dnsid-ai/dnsid-go/pull/14))
- Release readiness ([#11](https://github.com/dnsid-ai/dnsid-go/pull/11))
- examples(validate-domain): support the local registry via dnsid local env ([#17](https://github.com/dnsid-ai/dnsid-go/pull/17))

## [0.33.1] - 2026-09-15

### Features

- Add security baseline config ([#289](https://github.com/dnsid-ai/dnsid-go/pull/289))

### Chores

- chore: add copyright line to NOTICE header ([#276](https://github.com/dnsid-ai/dnsid-go/pull/276))

## [0.33.0] - 2026-09-15

### Features

- feat: add typed checkpoint errors and recovery guidance ([#321](https://github.com/dnsid-ai/dnsid-go/pull/321))
- feat: consolidate Config and add counterparty acceptance ([#323](https://github.com/dnsid-ai/dnsid-go/pull/323))

### Bug Fixes

- fix: sync local key stores before acknowledging durability ([#320](https://github.com/dnsid-ai/dnsid-go/pull/320))
- fix: pinned DNS server resolver honours TCP retry; typed OIDC exchange error ([#313](https://github.com/dnsid-ai/dnsid-go/pull/313))

### Chores

- chore(deps): bump github.com/aws/aws-sdk-go-v2/service/kms in /key/aws ([#311](https://github.com/dnsid-ai/dnsid-go/pull/311))
- chore(deps): bump github.com/aws/aws-sdk-go-v2 in /key/aws ([#310](https://github.com/dnsid-ai/dnsid-go/pull/310))
- chore(deps): bump taiki-e/install-action from 2.85.10 to 2.87.5 ([#309](https://github.com/dnsid-ai/dnsid-go/pull/309))
- chore(deps): bump github.com/WebDecoy/web-bot-auth from 0.2.0 to 0.4.1 ([#308](https://github.com/dnsid-ai/dnsid-go/pull/308))

## [0.32.0] - 2026-09-09

### Bug Fixes

- fix: bind Live proof reissue to original key ([#306](https://github.com/dnsid-ai/dnsid-go/pull/306))
- fix: align verification and C2SP design ([#312](https://github.com/dnsid-ai/dnsid-go/pull/312))

## [0.31.0] - 2026-09-03

### Features

- feat: add managed C2SP trust registry ([#291](https://github.com/dnsid-ai/dnsid-go/pull/291))
- feat: complete migrated-history verification and parallel domain checks ([#303](https://github.com/dnsid-ai/dnsid-go/pull/303))
- feat: align registry client with current API ([#304](https://github.com/dnsid-ai/dnsid-go/pull/304))
- feat: trust production stream bundles ([#305](https://github.com/dnsid-ai/dnsid-go/pull/305))

### Bug Fixes

- fix: restrict stream bundle fallback to valid 5xx statuses ([#297](https://github.com/dnsid-ai/dnsid-go/pull/297))
- fix: bound C2SP migration and scan resources ([#298](https://github.com/dnsid-ai/dnsid-go/pull/298))
- fix: harden SSRF destination validation ([#299](https://github.com/dnsid-ai/dnsid-go/pull/299))
- fix: move log checks to operation boundary ([#300](https://github.com/dnsid-ai/dnsid-go/pull/300))
- fix: align status expiry and verification coalescing ([#302](https://github.com/dnsid-ai/dnsid-go/pull/302))

## [0.30.0] - 2026-08-28

### Features

- feat: verify C2SP stream bundles with trust profiles ([#290](https://github.com/dnsid-ai/dnsid-go/pull/290))

### Other

- perf: coalesce verification and reuse HTTP connections ([#287](https://github.com/dnsid-ai/dnsid-go/pull/287))

## [0.29.0] - 2026-08-24

### Features

- feat: add c2sp-tlog verifier stuff ([#281](https://github.com/dnsid-ai/dnsid-go/pull/281))

### Bug Fixes

- fix: trust testnet log policy URL from environment ([#282](https://github.com/dnsid-ai/dnsid-go/pull/282))
- fix: correct status freshness and enforce log checks ([#283](https://github.com/dnsid-ai/dnsid-go/pull/283))

### Documentation

- docs: document SDK production operations ([#266](https://github.com/dnsid-ai/dnsid-go/pull/266))

### Testing

- ci: call the compliance suite from its standalone repo ([#273](https://github.com/dnsid-ai/dnsid-go/pull/273))

### Chores

- chore: add golangci-lint and fix the issues it reports ([#265](https://github.com/dnsid-ai/dnsid-go/pull/265))
- chore(deps): bump github.com/aws/aws-sdk-go-v2/service/kms in /key/aws ([#271](https://github.com/dnsid-ai/dnsid-go/pull/271))
- chore: point CODEOWNERS at the sdk-maintainers team ([#274](https://github.com/dnsid-ai/dnsid-go/pull/274))
- chore(deps): bump golangci/golangci-lint-action from 9.2.1 to 9.3.0 ([#268](https://github.com/dnsid-ai/dnsid-go/pull/268))
- chore(deps): bump taiki-e/install-action from 2.85.5 to 2.85.10 ([#269](https://github.com/dnsid-ai/dnsid-go/pull/269))
- chore(deps): bump jwx to 3.2.0 and x/net to 0.58.0 ([#275](https://github.com/dnsid-ai/dnsid-go/pull/275))

## [0.28.0] - 2026-08-07

### Features

- feat: add revoke ops ([#262](https://github.com/dnsid-ai/dnsid-go/pull/262))

### Chores

- chore: add NOTICE ([#261](https://github.com/dnsid-ai/dnsid-go/pull/261))

## [0.27.0] - 2026-08-07

### Bug Fixes

- fix!: bind non-revocation to fresh log evidence ([#258](https://github.com/dnsid-ai/dnsid-go/pull/258))

### Testing

- ci: auto-regenerate reference docs on PR branches ([#259](https://github.com/dnsid-ai/dnsid-go/pull/259))

## [0.26.0] - 2026-08-07

### Features

- feat: add a2a example ([#250](https://github.com/dnsid-ai/dnsid-go/pull/250))

### Bug Fixes

- fix: align HTTP signatures with corrected profile ([#248](https://github.com/dnsid-ai/dnsid-go/pull/248))
- fix: a2a example ([#257](https://github.com/dnsid-ai/dnsid-go/pull/257))

### Chores

- refactor: classify public API errors ([#252](https://github.com/dnsid-ai/dnsid-go/pull/252))
- refactor: move entity keys into manager dependencies ([#253](https://github.com/dnsid-ai/dnsid-go/pull/253))
- refactor!: clarify lifecycle event key roles ([#255](https://github.com/dnsid-ai/dnsid-go/pull/255))
- chore: remove deprecated API aliases ([#256](https://github.com/dnsid-ai/dnsid-go/pull/256))

## [0.25.0] - 2026-08-04

### Features

- feat!: remove published dnsid-testgo binary ([#246](https://github.com/dnsid-ai/dnsid-go/pull/246))
- feat: prepare for public release ([#237](https://github.com/dnsid-ai/dnsid-go/pull/237))

### Bug Fixes

- fix: load authoritative publication configuration ([#247](https://github.com/dnsid-ai/dnsid-go/pull/247))

### Chores

- chore(deps): bump github.com/aws/aws-sdk-go-v2 in /key/aws ([#243](https://github.com/dnsid-ai/dnsid-go/pull/243))
- chore(deps): bump taiki-e/install-action from 2.85.2 to 2.85.5 ([#241](https://github.com/dnsid-ai/dnsid-go/pull/241))
- chore(deps): bump github.com/aws/aws-sdk-go-v2/service/kms in /key/aws ([#242](https://github.com/dnsid-ai/dnsid-go/pull/242))

## [0.24.0] - 2026-08-03

### Features

- feat: align registry and verifier APIs ([#240](https://github.com/dnsid-ai/dnsid-go/pull/240))

### Bug Fixes

- fix: skip empty release PRs ([#239](https://github.com/dnsid-ai/dnsid-go/pull/239))

## [0.23.1] - 2026-08-03

### Chores

- refactor: shrink log reader contract ([#236](https://github.com/dnsid-ai/dnsid-go/pull/236))

## [0.23.0] - 2026-07-31

### Features

- feat: expose SDK conformance metadata and JWKS helpers ([#231](https://github.com/dnsid-ai/dnsid-go/pull/231))
- feat: add durable managed issuance coordination ([#234](https://github.com/dnsid-ai/dnsid-go/pull/234))

### Bug Fixes

- fix: correct c2sp lifecycle semantics ([#232](https://github.com/dnsid-ai/dnsid-go/pull/232))
- fix: remove CONTENT_SIG event type ([#233](https://github.com/dnsid-ai/dnsid-go/pull/233))

### Documentation

- docs: harmonize reference nav with the TypeScript/Python naming and order ([#230](https://github.com/dnsid-ai/dnsid-go/pull/230))

### Chores

- chore(deps): bump github.com/lestrrat-go/jwx/v3 in /key/aws ([#220](https://github.com/dnsid-ai/dnsid-go/pull/220))
- chore(deps): bump taiki-e/install-action from 2.84.1 to 2.85.2 ([#219](https://github.com/dnsid-ai/dnsid-go/pull/219))

## [0.22.0] - 2026-07-29

### Bug Fixes

- fix: restore default domain verification ([#224](https://github.com/dnsid-ai/dnsid-go/pull/224))
- fix: bugs identified during compliance testing ([#226](https://github.com/dnsid-ai/dnsid-go/pull/226))

### Documentation

- docs: package docs, godoc examples, generated reference, and doc lint gates ([#223](https://github.com/dnsid-ai/dnsid-go/pull/223))
- docs: regenerate reference after #224 ([#225](https://github.com/dnsid-ai/dnsid-go/pull/225))
- docs: add a generated overview landing page to the API reference ([#227](https://github.com/dnsid-ai/dnsid-go/pull/227))
- docs: split the root-package reference page into topic pages ([#228](https://github.com/dnsid-ai/dnsid-go/pull/228))

## [0.21.0] - 2026-07-28

### Features

- feat: enforce strict lifecycle state machine ([#221](https://github.com/dnsid-ai/dnsid-go/pull/221))

## [0.20.1] - 2026-07-27

### Bug Fixes

- fix: address outstanding c2sp issues ([#216](https://github.com/dnsid-ai/dnsid-go/pull/216))

## [0.20.0] - 2026-07-27

### Other

- Align/sdk design complete ([#214](https://github.com/dnsid-ai/dnsid-go/pull/214))

## [0.19.0] - 2026-07-24

### Features

- feat: remove old profiles ([#202](https://github.com/dnsid-ai/dnsid-go/pull/202))

### Chores

- chore(deps): bump github.com/aws/aws-sdk-go-v2 in /key/aws ([#205](https://github.com/dnsid-ai/dnsid-go/pull/205))
- chore(deps): bump taiki-e/install-action from 2.84.0 to 2.84.1 ([#204](https://github.com/dnsid-ai/dnsid-go/pull/204))
- chore(deps): bump github.com/aws/aws-sdk-go-v2/service/kms in /key/aws ([#207](https://github.com/dnsid-ai/dnsid-go/pull/207))
- chore: update docs ([#208](https://github.com/dnsid-ai/dnsid-go/pull/208))

## [0.18.0] - 2026-07-22

### Bug Fixes

- fix: refactor errors to match sdk design ([#197](https://github.com/dnsid-ai/dnsid-go/pull/197))
- fix: handful of small changes to prepare for release ([#200](https://github.com/dnsid-ai/dnsid-go/pull/200))
- fix: address remaining gaps from design doc ([#201](https://github.com/dnsid-ai/dnsid-go/pull/201))

### Chores

- chore(deps): bump taiki-e/install-action from 2.83.0 to 2.84.0 ([#195](https://github.com/dnsid-ai/dnsid-go/pull/195))
- chore(deps): bump actions/checkout from 7.0.0 to 7.0.1 ([#194](https://github.com/dnsid-ai/dnsid-go/pull/194))
- chore(deps): bump actions/setup-go from 6.5.0 to 7.0.0 ([#193](https://github.com/dnsid-ai/dnsid-go/pull/193))
- refactor: fold c2sp log into root module ([#203](https://github.com/dnsid-ai/dnsid-go/pull/203))

## [0.17.0] - 2026-07-21

### Testing

- ci!: release pre-1.0 breaking changes as minor versions ([#198](https://github.com/dnsid-ai/dnsid-go/pull/198))

### Chores

- [**breaking**] refactor: split log binding and continuity verification ([#192](https://github.com/dnsid-ai/dnsid-go/pull/192))

## [0.16.0] - 2026-07-20

### Features

- feat: fully support dnsid1 ([#187](https://github.com/dnsid-ai/dnsid-go/pull/187))

### Bug Fixes

- fix: remove use owner ([#183](https://github.com/dnsid-ai/dnsid-go/pull/183))
- fix: various cleanup towards design doc completeness ([#189](https://github.com/dnsid-ai/dnsid-go/pull/189))
- fix: ensure correct log ordering ([#190](https://github.com/dnsid-ai/dnsid-go/pull/190))

## [0.15.0] - 2026-07-15

### Features

- feat: split log signing ([#180](https://github.com/dnsid-ai/dnsid-go/pull/180))

### Bug Fixes

- fix: sort all tags alphabetically in DNSid1 signing canonicalization (v= last) ([#177](https://github.com/dnsid-ai/dnsid-go/pull/177))

### Chores

- chore(deps): bump github.com/aws/aws-sdk-go-v2/service/kms in /key/aws ([#179](https://github.com/dnsid-ai/dnsid-go/pull/179))

## [0.14.0] - 2026-07-13

### Features

- feat: accept submitted-spec wire literal v=DNSid1 ([#174](https://github.com/dnsid-ai/dnsid-go/pull/174))

### Bug Fixes

- fix: classify TXT parse-time required-tag failures as ParseError ([#172](https://github.com/dnsid-ai/dnsid-go/pull/172))
- fix: validate malformed lr values during validation, not parse (#170) ([#173](https://github.com/dnsid-ai/dnsid-go/pull/173))

## [0.13.0] - 2026-07-10

### Features

- feat: introduce typed AgentState for agent lifecycle states (#135) ([#140](https://github.com/dnsid-ai/dnsid-go/pull/140))

## [0.12.0] - 2026-07-10

### Features

- feat: add dnsid-draft-01-20260626 TXT record version support ([#118](https://github.com/dnsid-ai/dnsid-go/pull/118))
- feat: extend lifecycle log signing model ([#121](https://github.com/dnsid-ai/dnsid-go/pull/121))
- feat: add c2sp log method ([#124](https://github.com/dnsid-ai/dnsid-go/pull/124))
- feat(c2sptlog): add tile appender ([#143](https://github.com/dnsid-ai/dnsid-go/pull/143))

### Bug Fixes

- fix: add 202 status and SignatureResponseSelfManaged to POST /agent/{fqdn}/signature spec ([#119](https://github.com/dnsid-ai/dnsid-go/pull/119))
- fix: separate ek/ku JWKS and enforce unfiltered single-key check for 20260626 ([#123](https://github.com/dnsid-ai/dnsid-go/pull/123))
- fix: enforce ek≠ku thumbprint distinctness across all two-key profiles ([#137](https://github.com/dnsid-ai/dnsid-go/pull/137))
- fix: remove legacy fetchJWKSSet TOCTOU path (M1, #92) ([#144](https://github.com/dnsid-ai/dnsid-go/pull/144))
- fix: return *ValidationError from all TXTRecord.Validate failure paths ([#139](https://github.com/dnsid-ai/dnsid-go/pull/139))
- fix: close three draft-01 verification gaps (#136) ([#151](https://github.com/dnsid-ai/dnsid-go/pull/151))
- fix: unconditional step-5 bilateral binding, widen VerifyIssuance inputs ([#138](https://github.com/dnsid-ai/dnsid-go/pull/138))

### Documentation

- docs/public-readiness-cleanup ([#127](https://github.com/dnsid-ai/dnsid-go/pull/127))
- docs: add Go/dependency/platform compatibility baseline (#149) ([#156](https://github.com/dnsid-ai/dnsid-go/pull/156))
- docs: expand SECURITY.md  ([#155](https://github.com/dnsid-ai/dnsid-go/pull/155))
- docs: document signed commit setup ([#157](https://github.com/dnsid-ai/dnsid-go/pull/157))

### Chores

- chore(deps): bump taiki-e/install-action from 2.81.11 to 2.82.6 ([#114](https://github.com/dnsid-ai/dnsid-go/pull/114))
- chore(deps): bump actions/setup-go from 6.4.0 to 6.5.0 ([#115](https://github.com/dnsid-ai/dnsid-go/pull/115))
- chore(deps): bump goreleaser/goreleaser-action from 7.2.2 to 7.2.3 ([#116](https://github.com/dnsid-ai/dnsid-go/pull/116))
- chore: add .github/CODEOWNERS for public hardening
- chore: add SECURITY.md for public hardening
- chore: add CONTRIBUTING.md for public hardening
- chore(deps): bump actions/checkout from 6.0.3 to 7.0.0 ([#111](https://github.com/dnsid-ai/dnsid-go/pull/111))
- chore(deps): bump taiki-e/install-action from 2.82.6 to 2.82.9 ([#130](https://github.com/dnsid-ai/dnsid-go/pull/130))
- chore(deps): bump taiki-e/install-action from 2.82.9 to 2.83.0 ([#161](https://github.com/dnsid-ai/dnsid-go/pull/161))
- chore(deps): bump golang.org/x/mod in /log/c2sptlog ([#159](https://github.com/dnsid-ai/dnsid-go/pull/159))
- chore(deps): bump github.com/aws/aws-sdk-go-v2/service/kms in /key/aws ([#162](https://github.com/dnsid-ai/dnsid-go/pull/162))

### Other

- claude/feat-remaining-dnsid-draft-01-changes-in-dnsid-go-125-t-3izf ([#126](https://github.com/dnsid-ai/dnsid-go/pull/126))

## [0.11.0] - 2026-06-26

### Features

- feat: aws kms support ([#106](https://github.com/dnsid-ai/dnsid-go/pull/106))
- feat: add helper to init idm from config ([#109](https://github.com/dnsid-ai/dnsid-go/pull/109))
- feat: web both auth support ([#113](https://github.com/dnsid-ai/dnsid-go/pull/113))

## [0.10.0] - 2026-06-17

### Features

- Add private DNSid evaluation license ([#87](https://github.com/dnsid-ai/dnsid-go/pull/87))
- feat: add oidc support ([#99](https://github.com/dnsid-ai/dnsid-go/pull/99))
- feat: add LoadOrCreate fn, format key file like other SDKs ([#102](https://github.com/dnsid-ai/dnsid-go/pull/102))
- feat: local key provider example ([#103](https://github.com/dnsid-ai/dnsid-go/pull/103))
- feat: add multi-version protocol field handling (draft-00, draft-01-20260527) ([#104](https://github.com/dnsid-ai/dnsid-go/pull/104))

### Bug Fixes

- fix: delete dep, refactor registry calls ([#89](https://github.com/dnsid-ai/dnsid-go/pull/89))
- fix: SetAuthToken rejects bearer tokens over plaintext HTTP ([#67](https://github.com/dnsid-ai/dnsid-go/pull/67))

### Chores

- chore: add simple validate domain example ([#88](https://github.com/dnsid-ai/dnsid-go/pull/88))
- chore(deps): bump golang.org/x/net from 0.55.0 to 0.56.0 ([#98](https://github.com/dnsid-ai/dnsid-go/pull/98))
- chore(deps): bump taiki-e/install-action from 2.81.8 to 2.81.11 ([#97](https://github.com/dnsid-ai/dnsid-go/pull/97))

### Other

- rename-binary-dnsid-testgo ([#80](https://github.com/dnsid-ai/dnsid-go/pull/80))
- claude/replace-sync-mutex-with-sync-rwmutex-in-cache-91-t-6abu ([#94](https://github.com/dnsid-ai/dnsid-go/pull/94))
- claude/upgrade-go-toolchain-1-26-4-for-go-2026-5039-90-t-cbuq ([#95](https://github.com/dnsid-ai/dnsid-go/pull/95))
- remove internal docs ([#105](https://github.com/dnsid-ai/dnsid-go/pull/105))

## [0.9.0] - 2026-06-11

### Features

- feat: allow dnsid-draft01 as an alias for the 0504 protocol version ([#76](https://github.com/dnsid-ai/dnsid-go/pull/76))

### Bug Fixes

- fix: make status endpoint call request json ([#78](https://github.com/dnsid-ai/dnsid-go/pull/78))

## [0.8.0] - 2026-06-10

### Features

- feat: add registry lifecycle methods ([#73](https://github.com/dnsid-ai/dnsid-go/pull/73))

### Bug Fixes

- fix: changelog lists Features first and groups ci under Testing ([#71](https://github.com/dnsid-ai/dnsid-go/pull/71))

## [0.7.0] - 2026-06-10

### Bug Fixes

- fix: complete alignment to design doc
- fix: complete alignment to design doc ([#55](https://github.com/dnsid-ai/dnsid-go/pull/55))
- fix: align jwt and jwks handling ([#66](https://github.com/dnsid-ai/dnsid-go/pull/66))
- fix: add WithRegistryHTTPClient, SetAuthToken, and fix error parsing for server error format

### Chores

- chore: pin workflow actions and goreleaser to exact versions ([#60](https://github.com/dnsid-ai/dnsid-go/pull/60))
- chore(deps): bump golang.org/x/text from 0.37.0 to 0.38.0 ([#54](https://github.com/dnsid-ai/dnsid-go/pull/54))

### Features

- feat: expand RegistryClient and convert CLI to use SDK ([#65](https://github.com/dnsid-ai/dnsid-go/pull/65))

## [0.6.0] - 2026-06-08

### Bug Fixes

- fix: add go test and tweak release logic in workflows ([#53](https://github.com/dnsid-ai/dnsid-go/pull/53))

### Chores

- chore: fix agents doc to reflect current state ([#52](https://github.com/dnsid-ai/dnsid-go/pull/52))

### Features

- feat: refactor sdk to match design doc

## [0.5.1] - 2026-05-27

### Chores

- chore(deps): bump golang.org/x/net from 0.54.0 to 0.55.0 ([#45](https://github.com/dnsid-ai/dnsid-go/pull/45))

## [0.5.0] - 2026-05-19

### Chores

- chore: include squash-merged PRs in changelog ([#40](https://github.com/dnsid-ai/dnsid-go/pull/40))

### Features

- feat: structured error types (ParseError, ValidationError, VerificationError) + code enum ([#42](https://github.com/dnsid-ai/dnsid-go/pull/42))
- added mise.toml ([#44](https://github.com/dnsid-ai/dnsid-go/pull/44))

### Other

- Export DNSID record helper APIs ([#43](https://github.com/dnsid-ai/dnsid-go/pull/43))

## [0.4.0] - 2026-05-14

### Features

- feat: ES256 signing and verification (paired with dnsid server PR) ([#35](https://github.com/dnsid-ai/dnsid-go/pull/35))
- feat: extensible version registry with per-version required tags ([#39](https://github.com/dnsid-ai/dnsid-go/pull/39))

### Bug Fixes

- fix: prevent DNS rebinding in JWKS fetch by dialing validated IPs ([#36](https://github.com/dnsid-ai/dnsid-go/pull/36))

## [0.3.0] - 2026-05-13

### Chores

- chore(deps): bump goreleaser/goreleaser-action from 6 to 7 ([#30](https://github.com/dnsid-ai/dnsid-go/pull/30))
- chore(deps): bump actions/setup-go from 5 to 6 ([#31](https://github.com/dnsid-ai/dnsid-go/pull/31))
- chore(deps): bump peter-evans/create-pull-request from 7 to 8 ([#33](https://github.com/dnsid-ai/dnsid-go/pull/33))
- chore(deps): bump golang.org/x/net from 0.52.0 to 0.54.0 ([#34](https://github.com/dnsid-ai/dnsid-go/pull/34))
- chore(deps): bump actions/checkout from 4 to 6 ([#32](https://github.com/dnsid-ai/dnsid-go/pull/32))

### Features

- feat: add NormalizeFQDN per SDK design spec ([#26](https://github.com/dnsid-ai/dnsid-go/pull/26))
- feat: add JWKS/JWK wrapper with Thumbprint helper per SDK design ([#29](https://github.com/dnsid-ai/dnsid-go/pull/29))

### Other

- Replace release-please with git-cliff + goreleaser ([#25](https://github.com/dnsid-ai/dnsid-go/pull/25))

## [0.2.0](https://github.com/dnsid-ai/dnsid-go/compare/v0.1.0...v0.2.0) (2026-05-11)


### ⚠ BREAKING CHANGES

* MarshalTXT now returns (string, error) instead of string. Legacy oi= records without gi= will fail parse. Drop TXT-level p= and exp= tags.

### Features

* rename TXT governance tag oi= to gi= and update schema ([36ab8b7](https://github.com/dnsid-ai/dnsid-go/commit/36ab8b755afe9893996bb24085eeaa30e1ae11d5))

## 0.1.0 (2026-05-11)


### Features

* AgentStatusResponse dev-tier discriminator + identity-record expiry ([07077fe](https://github.com/dnsid-ai/dnsid-go/commit/07077fe651f2fcd8d14a63c471950a87132f35c3))
* **cmd/dnsid:** Phase 0 CLI — sign, verify, resolve ([a9d68d3](https://github.com/dnsid-ai/dnsid-go/commit/a9d68d3993c43d1ae71b605207214f35c22f707f))
* **cmd/dnsid:** Phase 0 CLI — sign, verify, resolve ([78024d9](https://github.com/dnsid-ai/dnsid-go/commit/78024d9fbbe0a560a9b527b1d85ebbbfede4394b))
* DNSID identity record SDK ([099955a](https://github.com/dnsid-ai/dnsid-go/commit/099955a1243507aae1ca5612d5fde1d959abe172))
* DNSID identity record SDK functions ([927eb15](https://github.com/dnsid-ai/dnsid-go/commit/927eb15c4b0264970281149b24511ef8f9f7efc5))
* expose SDK Version and add `dnsid version` subcommand ([f482a49](https://github.com/dnsid-ai/dnsid-go/commit/f482a496e5b860e7ac552412c1c5a02317861cc3))
* tighten RequireCosigned — typed errors, schema validation, integration test ([ecfe72b](https://github.com/dnsid-ai/dnsid-go/commit/ecfe72b008e6f6953eb1d06d8a3732f20685aed6))
* Verifier struct for _dnsid + _dnsidsig verification ([f517bb3](https://github.com/dnsid-ai/dnsid-go/commit/f517bb31b75acf97546581fbb3531e5f07f438e3))
* Verifier struct for _dnsid + _dnsidsig verification ([cdd1f96](https://github.com/dnsid-ai/dnsid-go/commit/cdd1f96dd0f258baaf2afbfeb36fe87920b51469))


### Bug Fixes

* add context param to VerifyJWT, validate Ed25519 curve in key provider ([14681ea](https://github.com/dnsid-ai/dnsid-go/commit/14681eace94ecef618a53954e069f49352372faa))
* add context params to GetOIDCToken/IsRevoked/RequireCosigned, validate RenewalLeadTime ([5f51f7c](https://github.com/dnsid-ai/dnsid-go/commit/5f51f7c1f694f4d850a5280c1bbe39a317a7f5e3))
* add inflight coalescing to RevocationCache to prevent thundering herd ([1a5fa27](https://github.com/dnsid-ai/dnsid-go/commit/1a5fa27254ac2fa9613d4bf3192fa2bbc8b7bd5d))
* add response body size limit to GetAgentStatus, document WitnessToken trust model ([42330fe](https://github.com/dnsid-ai/dnsid-go/commit/42330fe3e47636f4efd8701294ea29d01a389c3f))
* address PR [#5](https://github.com/dnsid-ai/dnsid-go/issues/5) review comments ([fef78a4](https://github.com/dnsid-ai/dnsid-go/commit/fef78a43c05dfc42c7a1f442fc20fdaca8df7f69))
* detach inflight fetch contexts, validate JWT audience ([6772447](https://github.com/dnsid-ai/dnsid-go/commit/677244733f5eda90eae09c09a16d9bda06efcc8d))
* make Unverifiable the zero value, add enforcing middleware, drain RenewBinding body ([0018d07](https://github.com/dnsid-ai/dnsid-go/commit/0018d07d2488d630c5807c1935f749c3b27aa3bb))
* preserve context errors in ErrCosignExchange chain ([3e77dda](https://github.com/dnsid-ai/dnsid-go/commit/3e77dda06efe760a31e8dea4af001d7dbb883679))
* reject reserved claims in AdditionalClaims, fix renewer Start() race ([37d22d8](https://github.com/dnsid-ai/dnsid-go/commit/37d22d86616f702a969563cc89c73fc7572e4b9f))
* replace http.DefaultClient with 30s-timeout client in registry ([3db1a66](https://github.com/dnsid-ai/dnsid-go/commit/3db1a66d66978a5b700a1e39a7f6d1f16fc94b03))
* **security:** merge SSRF validators and address PR review comments ([c651c21](https://github.com/dnsid-ai/dnsid-go/commit/c651c21f6bc7d7f52e4c7032f820eb303a9d1ddf))
* use ku= URL from TXT record for JWKS fetch ([38c5d45](https://github.com/dnsid-ai/dnsid-go/commit/38c5d45f540d06012bce09768b3a3e9ea63c9651))
* use ku= URL from TXT record for JWKS fetch ([4e4089f](https://github.com/dnsid-ai/dnsid-go/commit/4e4089fc127689a78bf3c9526ec0808e5df14388)), closes [#14](https://github.com/dnsid-ai/dnsid-go/issues/14)
* **verifier:** clarify unreachable-wrap invariant ([22e0552](https://github.com/dnsid-ai/dnsid-go/commit/22e0552d3fb9ea917ab89c23bc156d9d9961f279))
