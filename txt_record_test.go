package dnsid

import (
	"reflect"
	"strings"
	"testing"
)

func TestTXTRecord_ParsedEmptyTagsPreserved(t *testing.T) {
	for _, version := range []string{identityRecordDraft01, identityRecordDNSid1} {
		for _, optional := range []string{"fl=", "ka=", "cu=", "fl=;ka=;cu=;xx="} {
			t.Run(version+"/"+optional, func(t *testing.T) {
				raw := "v=" + version + ";gi=example.com;ek=https://example.com/entity-keys.json;ku=https://agent.test/jwks.json;lr=microledger:abc123;su=https://agent.test/status;" + optional + ";sg=AAAA"
				record, err := ParseTXTRecord(raw)
				if err != nil {
					t.Fatal(err)
				}
				if len(record.Flags) != 0 || record.KeyAge != "" || record.Capabilities != "" {
					t.Fatalf("empty optional fields changed: %#v", record)
				}
				wantTags := map[string]string{
					"v": version, "gi": "example.com", "ek": "https://example.com/entity-keys.json",
					"ku": "https://agent.test/jwks.json", "lr": "microledger:abc123",
					"su": "https://agent.test/status", "sg": "AAAA",
				}
				for _, pair := range strings.Split(optional, ";") {
					wantTags[strings.TrimSuffix(pair, "=")] = ""
				}
				if !reflect.DeepEqual(record.Tags(), wantTags) {
					t.Fatalf("Tags() = %#v, want %#v", record.Tags(), wantTags)
				}
				delete(wantTags, "sg")
				wantCanonical := serializeTagsAlphabetical(wantTags)
				if got := record.Canonical(); got != wantCanonical {
					t.Fatalf("Canonical() = %q, want %q", got, wantCanonical)
				}
				unsigned, err := ParseUnsignedCanonical(wantCanonical)
				if err != nil {
					t.Fatalf("ParseUnsignedCanonical: %v", err)
				}
				if unsigned.Canonical() != wantCanonical {
					t.Fatalf("unsigned canonical = %q, want %q", unsigned.Canonical(), wantCanonical)
				}
				for _, copy := range []*TXTRecord{record, record.WithSignature("BBBB"), cloneTXTRecord(record), unsigned.WithSignature("AAAA")} {
					wantTags["sg"] = copy.Signature
					if got, want := copy.Serialize(), serializeTags(wantTags); got != want {
						t.Fatalf("Serialize() = %q, want %q", got, want)
					}
					roundTrip, err := ParseTXTRecord(copy.Serialize())
					if err != nil {
						t.Fatalf("round-trip parse: %v", err)
					}
					if roundTrip.Canonical() != wantCanonical {
						t.Fatalf("round-trip canonical = %q, want %q", roundTrip.Canonical(), wantCanonical)
					}
				}
				delete(wantTags, "sg")
				delete(wantTags, "xx")
				if got, want := string(record.KnownTagsCanonical()), serializeTagsAlphabetical(wantTags); got != want {
					t.Fatalf("KnownTagsCanonical() = %q, want %q", got, want)
				}
			})
		}
	}
}

func TestTXTRecord_CreatedUnsetOptionalTagsOmitted(t *testing.T) {
	record := &TXTRecord{
		Version: identityRecordDraft01, GovernanceID: "example.com",
		EntityKeyURI: "https://example.com/ek", KeyURI: "https://agent.example.com/ku",
		LogRef: "test:agent", StatusURI: "https://agent.example.com/status", Signature: "AAAA",
	}
	for _, tag := range []string{"fl", "ka", "cu"} {
		if _, present := record.Tags()[tag]; present {
			t.Errorf("unset %s present in Tags()", tag)
		}
		for _, output := range []string{record.Canonical(), record.Serialize()} {
			if strings.Contains(output, tag+"=") {
				t.Errorf("unset %s present in %q", tag, output)
			}
		}
	}
}
