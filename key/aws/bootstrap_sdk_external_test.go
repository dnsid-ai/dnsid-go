package awskms_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	awskms "github.com/dnsid-ai/dnsid-go/key/aws"
)

// These fake-only tests exercise the official SDK serializer/deserializer, not
// a substitute for kms.Client. Wire expectations are AWS KMS JSON 1.1 API
// contracts (CreateAlias, CreateKey, GetPublicKey); bootstrap expectations are
// README.md and docs/reference/key-aws.md. No live KMS behavior is claimed.
const sdkAlias = "alias/dnsid/example/worker"
const sdkCandidate = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
const sdkWinner = "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

type sdkRoundTrip func(*http.Request) (*http.Response, error)

func (f sdkRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func sdkAdapter(f sdkRoundTrip) awskms.SDKClient {
	return awskms.SDKClient{Client: kms.New(kms.Options{
		Region: "us-east-1", BaseEndpoint: aws.String("https://kms.fixture.invalid"),
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "FAKEACCESS", SecretAccessKey: "fake-secret-for-offline-tests"}, nil
		}),
		HTTPClient: &http.Client{Transport: f}, RetryMaxAttempts: 1,
	})}
}

func sdkRequest(t *testing.T, r *http.Request) (string, map[string]any) {
	t.Helper()
	if r.Method != http.MethodPost || r.URL.String() != "https://kms.fixture.invalid/" {
		t.Fatalf("unexpected endpoint: %s %s", r.Method, r.URL)
	}
	if r.Header.Get("Content-Type") != "application/x-amz-json-1.1" {
		t.Fatalf("content type: %q", r.Header.Get("Content-Type"))
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService."), body
}

func sdkResponse(status int, value any) (*http.Response, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/x-amz-json-1.1"}}, Body: io.NopCloser(bytes.NewReader(b))}, nil
}
func sdkNativeError(name string) (*http.Response, error) {
	return sdkResponse(400, map[string]any{"__type": name, "message": "offline fixture"})
}
func sdkEqual(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}

func TestBootstrapSDK_CreateAliasWire(t *testing.T) {
	// Given an official client with a single expected request, when creating an
	// alias, then CreateAlias (never UpdateAlias) carries both exact identifiers.
	calls := 0
	client := sdkAdapter(func(r *http.Request) (*http.Response, error) {
		calls++
		action, body := sdkRequest(t, r)
		sdkEqual(t, action, "CreateAlias")
		sdkEqual(t, body, map[string]any{"AliasName": sdkAlias, "TargetKeyId": sdkCandidate})
		return sdkResponse(200, map[string]any{})
	})
	if err := client.CreateAlias(context.Background(), awskms.CreateAliasInput{AliasName: sdkAlias, TargetKeyID: sdkCandidate}); err != nil {
		t.Fatal(err)
	}
	sdkEqual(t, calls, 1)
}

func TestBootstrapSDK_CreateSigningKeyWire(t *testing.T) {
	for _, spec := range []types.KeySpec{types.KeySpecEccNistP256, types.KeySpecEccNistEdwards25519} {
		t.Run(string(spec), func(t *testing.T) {
			// Given each supported spec, when allocating, then native CreateKey uses
			// SIGN_VERIFY and preserves the requested spec and canonical returned ARN.
			calls := 0
			client := sdkAdapter(func(r *http.Request) (*http.Response, error) {
				calls++
				action, body := sdkRequest(t, r)
				sdkEqual(t, action, "CreateKey")
				sdkEqual(t, body["KeySpec"], string(spec))
				sdkEqual(t, body["KeyUsage"], "SIGN_VERIFY")
				return sdkResponse(200, map[string]any{"KeyMetadata": map[string]any{"Arn": sdkCandidate, "KeyId": "11111111-2222-3333-4444-555555555555"}})
			})
			out, err := client.CreateSigningKey(context.Background(), awskms.CreateSigningKeyInput{KeySpec: spec})
			if err != nil {
				t.Fatal(err)
			}
			sdkEqual(t, out.KeyID, sdkCandidate)
			sdkEqual(t, calls, 1)
		})
	}
}

func TestBootstrapSDK_CreateOrReuseWire(t *testing.T) {
	for _, branch := range []string{"existing", "missing", "conflict"} {
		t.Run(branch, func(t *testing.T) {
			// Given independent stdlib SPKI and native KMS responses, when explicitly
			// bootstrapping, then only finite acquisition actions occur and the public
			// result identifies the resolved winner, not a presumed candidate.
			pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
			der, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			var actions []string
			aliasReads, canonicalReads := 0, 0
			client := sdkAdapter(func(r *http.Request) (*http.Response, error) {
				action, body := sdkRequest(t, r)
				actions = append(actions, action)
				if len(actions) > 5 {
					t.Fatal("unbounded native actions")
				}
				switch action {
				case "GetPublicKey":
					id, _ := body["KeyId"].(string)
					sdkEqual(t, body, map[string]any{"KeyId": id})
					if id == sdkAlias {
						aliasReads++
						if branch != "existing" && aliasReads == 1 {
							return sdkNativeError("NotFoundException")
						}
						if aliasReads > 2 || (branch == "existing" && aliasReads > 1) {
							t.Fatal("extra alias read")
						}
					} else {
						sdkEqual(t, id, sdkWinner)
						canonicalReads++
						if canonicalReads > 1 {
							t.Fatal("extra immutable validation read")
						}
					}
					return sdkResponse(200, map[string]any{"KeyId": sdkWinner, "PublicKey": der, "KeySpec": "ECC_NIST_EDWARDS25519", "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": []string{"ED25519_SHA_512"}})
				case "CreateKey":
					if branch == "existing" {
						t.Fatal("allocation for existing alias")
					}
					sdkEqual(t, actions, []string{"GetPublicKey", "CreateKey"})
					sdkEqual(t, body["KeySpec"], "ECC_NIST_EDWARDS25519")
					sdkEqual(t, body["KeyUsage"], "SIGN_VERIFY")
					return sdkResponse(200, map[string]any{"KeyMetadata": map[string]any{"Arn": sdkCandidate}})
				case "CreateAlias":
					sdkEqual(t, actions, []string{"GetPublicKey", "CreateKey", "CreateAlias"})
					sdkEqual(t, body, map[string]any{"AliasName": sdkAlias, "TargetKeyId": sdkCandidate})
					if branch == "conflict" {
						return sdkNativeError("AlreadyExistsException")
					}
					return sdkResponse(200, map[string]any{})
				default:
					t.Fatalf("forbidden native action %q", action)
					return nil, errors.New("unreachable")
				}
			})
			out, err := awskms.CreateOrReuse(context.Background(), client, awskms.BootstrapConfig{AliasName: sdkAlias, Algorithm: types.SigningAlgorithmSpecEd25519Sha512})
			if err != nil {
				t.Fatal(err)
			}
			if out == nil || out.KeyProvider == nil {
				t.Fatal("missing public result")
			}
			sdkEqual(t, out.KeyRef, sdkWinner)
			state := out.KeyProvider.State()
			sdkEqual(t, state.ActiveKeyID, sdkWinner)
			if len(state.PendingKeyIDs) != 0 || len(state.RetainedKeyIDs) != 0 {
				t.Fatalf("unexpected state: %+v", state)
			}
			sdkEqual(t, out.KeyProvider.ListKeyIds(), []string{sdkWinner})
			key, err := out.KeyProvider.JWKWithError()
			if err != nil || key == nil {
				t.Fatalf("public JWK: %v", err)
			}
			encoded, err := json.Marshal(key)
			if err != nil {
				t.Fatal(err)
			}
			var jwk map[string]any
			if err := json.Unmarshal(encoded, &jwk); err != nil {
				t.Fatal(err)
			}
			for k, v := range map[string]any{"kid": sdkWinner, "kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)} {
				sdkEqual(t, jwk[k], v)
			}
			if _, exists := jwk["d"]; exists {
				t.Fatal("private material exposed")
			}
			want := []string{"GetPublicKey"}
			if branch != "existing" {
				want = []string{"GetPublicKey", "CreateKey", "CreateAlias", "GetPublicKey"}
			}
			if canonicalReads == 1 {
				want = append(want, "GetPublicKey")
			}
			sdkEqual(t, actions, want)
			expectedReads := 1
			if branch != "existing" {
				expectedReads = 2
			}
			sdkEqual(t, aliasReads, expectedReads)
		})
	}
}

// Capture the actual adapter return value without replacing/wrapping it. The
// official SDK adds an operation wrapper: identity is required at the bootstrap
// boundary, not between that wrapper and a low-level transport sentinel.
type sdkObservedClient struct {
	awskms.SDKClient
	observed error
}

func (c *sdkObservedClient) GetPublicKey(ctx context.Context, in awskms.GetPublicKeyInput) (awskms.GetPublicKeyOutput, error) {
	out, err := c.SDKClient.GetPublicKey(ctx, in)
	c.observed = err
	return out, err
}

func TestBootstrapSDK_NativeErrorChainsAndIdentity(t *testing.T) {
	t.Run("native_absence", func(t *testing.T) {
		calls := 0
		client := sdkAdapter(func(r *http.Request) (*http.Response, error) {
			calls++
			action, body := sdkRequest(t, r)
			sdkEqual(t, action, "GetPublicKey")
			sdkEqual(t, body, map[string]any{"KeyId": sdkAlias})
			return sdkNativeError("NotFoundException")
		})
		_, err := client.GetPublicKey(context.Background(), awskms.GetPublicKeyInput{KeyID: sdkAlias})
		var missing *types.NotFoundException
		var operation *smithy.OperationError
		if !errors.As(err, &missing) || !errors.As(err, &operation) {
			t.Fatalf("missing native wrapped absence: %T %v", err, err)
		}
		sdkEqual(t, calls, 1)
	})
	t.Run("native_conflict", func(t *testing.T) {
		calls := 0
		client := sdkAdapter(func(r *http.Request) (*http.Response, error) {
			calls++
			action, body := sdkRequest(t, r)
			sdkEqual(t, action, "CreateAlias")
			sdkEqual(t, body, map[string]any{"AliasName": sdkAlias, "TargetKeyId": sdkCandidate})
			return sdkNativeError("AlreadyExistsException")
		})
		err := client.CreateAlias(context.Background(), awskms.CreateAliasInput{AliasName: sdkAlias, TargetKeyID: sdkCandidate})
		var conflict *types.AlreadyExistsException
		var operation *smithy.OperationError
		if !errors.As(err, &conflict) || !errors.As(err, &operation) {
			t.Fatalf("missing native wrapped conflict: %T %v", err, err)
		}
		sdkEqual(t, calls, 1)
	})
	for _, mode := range []string{"access_denied", "transport"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			sentinel := errors.New("offline transport sentinel")
			client := &sdkObservedClient{SDKClient: sdkAdapter(func(r *http.Request) (*http.Response, error) {
				calls++
				action, body := sdkRequest(t, r)
				sdkEqual(t, action, "GetPublicKey")
				sdkEqual(t, body, map[string]any{"KeyId": sdkAlias})
				if mode == "transport" {
					return nil, sentinel
				}
				return sdkNativeError("AccessDeniedException")
			})}
			out, err := awskms.CreateOrReuse(context.Background(), client, awskms.BootstrapConfig{AliasName: sdkAlias})
			if out != nil || err == nil || err != client.observed { //nolint:errorlint // Bootstrap must return the exact SDK adapter error object, not just its cause.
				t.Fatalf("original adapter error not preserved: result=%v error=%v observed=%v", out, err, client.observed)
			}
			var operation *smithy.OperationError
			if !errors.As(err, &operation) {
				t.Fatalf("missing SDK operation wrapper: %T", err)
			}
			if mode == "transport" && !errors.Is(err, sentinel) {
				t.Fatal("transport cause lost")
			}
			if mode == "access_denied" {
				var api smithy.APIError
				if !errors.As(err, &api) || api.ErrorCode() != "AccessDeniedException" {
					t.Fatalf("native API chain: %v", err)
				}
			}
			sdkEqual(t, calls, 1)
		})
	}
}
