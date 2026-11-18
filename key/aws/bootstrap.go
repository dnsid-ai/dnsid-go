package awskms

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// CreateAliasInput names an alias and its immutable target key reference.
type CreateAliasInput struct {
	AliasName   string
	TargetKeyID string
}

// BootstrapClient is the KMS surface consumed by [CreateOrReuse]. Ordinary
// [Client] implementations do not need to support alias creation.
type BootstrapClient interface {
	Client
	CreateAlias(context.Context, CreateAliasInput) error
}

// BootstrapConfig selects an explicit alias in the injected client's account
// and region. AliasName must start with alias/ and have a nonempty suffix;
// surrounding whitespace, #, and reserved alias/aws/ names are rejected.
// Algorithm defaults to ECDSA_SHA_256; ED25519_SHA_512 is also supported.
type BootstrapConfig struct {
	AliasName string
	Algorithm types.SigningAlgorithmSpec
}

// BootstrapResult holds only the validated winner, active with no retained or
// pending keys. KeyRef is its canonical KMS identifier, never the alias.
type BootstrapResult struct {
	KeyRef      string
	KeyProvider *Provider
}

// CreateOrReuse explicitly opens an alias or creates one initial signing key
// when the initial read returns a native KMS NotFoundException (possibly
// wrapped). It attempts CreateAlias once; native AlreadyExistsException is
// contention, not failure. After either acquisition outcome it reads the alias
// exactly once to resolve the winner. Other dependency errors are returned
// unchanged. There is no polling or same-invocation recovery from response loss.
//
// The winner's canonical identity, metadata and public key are validated before
// constructing a standalone provider. Bootstrap never deletes or retargets keys
// or aliases, including losing or ambiguous candidates; their disposition is
// deferred to the caller's resource-management policy. It does not register an
// agent or publish an identity. [Load], configuration loading and [Provider.GenerateKey]
// remain separate existing-key and rotation operations.
func CreateOrReuse(ctx context.Context, client BootstrapClient, cfg BootstrapConfig) (*BootstrapResult, error) {
	if client == nil {
		return nil, dnsid.NewArgumentError("dnsid/awskms: nil bootstrap client", nil)
	}
	if !strings.HasPrefix(cfg.AliasName, "alias/") || len(cfg.AliasName) == len("alias/") ||
		strings.HasPrefix(cfg.AliasName, "alias/aws/") || strings.Contains(cfg.AliasName, "#") ||
		strings.TrimSpace(cfg.AliasName) != cfg.AliasName {
		return nil, dnsid.NewArgumentError("dnsid/awskms: invalid bootstrap alias", nil)
	}
	if cfg.Algorithm == "" {
		cfg.Algorithm = types.SigningAlgorithmSpecEcdsaSha256
	}
	spec, err := defaultKeySpec(cfg.Algorithm)
	if err != nil {
		return nil, dnsid.NewArgumentError("dnsid/awskms: unsupported bootstrap algorithm", err)
	}
	out, err := client.GetPublicKey(ctx, GetPublicKeyInput{KeyID: cfg.AliasName})
	if err != nil {
		var absent *types.NotFoundException
		if !errors.As(err, &absent) {
			return nil, err
		}
		candidate, err := client.CreateSigningKey(ctx, CreateSigningKeyInput{KeySpec: spec})
		if err != nil {
			return nil, err
		}
		if !bootstrapCanonicalRef(candidate.KeyID) {
			return nil, fmt.Errorf("dnsid/awskms: invalid created key reference")
		}
		if err := client.CreateAlias(ctx, CreateAliasInput{AliasName: cfg.AliasName, TargetKeyID: candidate.KeyID}); err != nil {
			var conflict *types.AlreadyExistsException
			if !errors.As(err, &conflict) {
				return nil, err
			}
		}
		out, err = client.GetPublicKey(ctx, GetPublicKeyInput{KeyID: cfg.AliasName})
		if err != nil {
			return nil, err
		}
	}
	// Validate this response directly: publicJWK permits an empty returned ID
	// fallback for ordinary loading, which is not permitted during bootstrap.
	if !bootstrapCanonicalRef(out.KeyID) {
		return nil, fmt.Errorf("dnsid/awskms: invalid winner key reference")
	}
	if out.KeyUsage != types.KeyUsageTypeSignVerify || out.KeySpec != spec || !containsAlg(out.SigningAlgorithms, cfg.Algorithm) {
		return nil, fmt.Errorf("dnsid/awskms: incompatible bootstrap winner metadata")
	}
	key, err := spkiToJWK(out.PublicKey, cfg.Algorithm, out.KeyID)
	if err != nil {
		return nil, err
	}
	state := State{ActiveKeyID: out.KeyID}
	p := &Provider{
		client: client,
		state:  state,
		cfg: Config{State: state, Algorithm: cfg.Algorithm, KeySpec: spec,
			DeletionWindowInDays: 30, OperationTimeout: 30 * time.Second},
		cache: map[string]jwk.Key{out.KeyID: key},
	}
	return &BootstrapResult{KeyRef: out.KeyID, KeyProvider: p}, nil
}

var bootstrapKeyID = regexp.MustCompile(`\A(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|mrk-[0-9a-fA-F]{32})\z`)
var bootstrapAccountID = regexp.MustCompile(`\A[0-9]{12}\z`)

// bootstrapCanonicalRef checks the entire value without normalization. ARN
// partitions are deliberately not allowlisted; KMS defines their availability.
func bootstrapCanonicalRef(ref string) bool {
	if strings.ContainsRune(ref, '#') || strings.ContainsFunc(ref, unicode.IsSpace) {
		return false
	}
	if bootstrapKeyID.MatchString(ref) {
		return true
	}
	parts := strings.Split(ref, ":")
	return len(parts) == 6 && parts[0] == "arn" && parts[1] != "" && parts[2] == "kms" &&
		parts[3] != "" && bootstrapAccountID.MatchString(parts[4]) &&
		strings.HasPrefix(parts[5], "key/") && bootstrapKeyID.MatchString(strings.TrimPrefix(parts[5], "key/"))
}

// CreateAlias maps to KMS CreateAlias, never UpdateAlias, and preserves the
// original AWS SDK error value.
func (c SDKClient) CreateAlias(ctx context.Context, in CreateAliasInput) error {
	_, err := c.Client.CreateAlias(ctx, &kms.CreateAliasInput{
		AliasName: aws.String(in.AliasName), TargetKeyId: aws.String(in.TargetKeyID),
	})
	return err
}
