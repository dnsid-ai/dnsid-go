package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	dnsid "github.com/dnsid-ai/dnsid-go"
	joseprofile "github.com/dnsid-ai/dnsid-go/jose"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const keyStorePath = "keys.json"

func main() {
	keyProvider, err := dnsid.LoadOrCreateLocalKeyProvider(keyStorePath, dnsid.JoseAlgEdDSA)
	if err != nil {
		die("loading key provider", err)
	}

	initialSigningKid := activeKid(keyProvider)
	fmt.Println("loaded active key:")
	printJSON(keyProvider.JWK())
	fmt.Println("visible key ids:", keyProvider.ListKeyIds())

	fmt.Println("\nget jwk by kid:")
	printJSON(keyProvider.JWK(initialSigningKid))

	pendingKid, err := keyProvider.GenerateKey(dnsid.JoseAlgEdDSA)
	if err != nil {
		die("generating pending key", err)
	}
	fmt.Println("\ngenerated pending kid:", pendingKid)
	fmt.Println("visible key ids before activation:", keyProvider.ListKeyIds())

	if err := keyProvider.Activate(pendingKid); err != nil {
		die("activating pending key", err)
	}
	fmt.Println("\nvisible key ids after activation:", keyProvider.ListKeyIds())
	fmt.Println("new active key:")
	printJSON(keyProvider.JWK())

	set := jwk.NewSet()
	for _, kid := range keyProvider.ListKeyIds() {
		_ = set.AddKey(keyProvider.JWK(kid))
	}
	fmt.Println("\npublic JWKS:")
	printJSON(set)

	if err := keyProvider.Supersede(initialSigningKid); err != nil {
		die("superseding old key", err)
	}

	profile := joseprofile.New(nil, "alice.example.com", keyProvider, joseprofile.Config{})
	jwt, err := profile.CreateJWT(joseprofile.JWTOptions{
		Audience:         "bob.example.com",
		AdditionalClaims: map[string]any{"example": "local-key-provider"},
	})
	if err != nil {
		die("creating JWT", err)
	}
	fmt.Println("\nsigned JWT:", jwt)

	fmt.Println("\ndecoded JWT header:")
	printJSON(decodeJWTPart(jwt, 0))
	fmt.Println("decoded JWT payload:")
	printJSON(decodeJWTPart(jwt, 1))
}

func activeKid(kp dnsid.KeyProvider) string {
	kid, ok := kp.JWK().KeyID()
	if !ok || kid == "" {
		die("reading active kid", fmt.Errorf("active key missing kid"))
	}
	return kid
}

func decodeJWTPart(token string, part int) map[string]any {
	parts := strings.Split(token, ".")
	if part < 0 || part >= len(parts) {
		die("decoding JWT", fmt.Errorf("token has %d parts, wanted part %d", len(parts), part))
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[part])
	if err != nil {
		die("decoding JWT", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		die("parsing JWT JSON", err)
	}
	return out
}

func printJSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		die("marshaling JSON", err)
	}
	fmt.Println(string(data))
}

func die(action string, err error) {
	fmt.Fprintf(os.Stderr, "%s failed: %v\n", action, err)
	os.Exit(1)
}
