module github.com/dnsid-ai/dnsid-go/key/aws

go 1.26.5

require (
	github.com/aws/aws-sdk-go-v2 v1.47.0
	github.com/aws/aws-sdk-go-v2/service/kms v1.59.0
	github.com/dnsid-ai/dnsid-go v0.33.2
	github.com/lestrrat-go/jwx/v3 v3.2.0
)

require (
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.2 // indirect
	github.com/aws/smithy-go v1.28.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.6 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

replace github.com/dnsid-ai/dnsid-go => ../..
