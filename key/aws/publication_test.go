package awskms

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"strings"
	"testing"
	"time"
)

type awsPublicationDNS struct{ record, name string }

func (d awsPublicationDNS) FetchTXT(_ context.Context, name string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	if name != d.name {
		return nil, dnsid.DNSSECStateUnsigned, errors.New("unexpected DNS name")
	}
	return []dnsid.TXTRecordRData{{Value: d.record, TTL: time.Minute}}, dnsid.DNSSECStateValid, nil
}

type awsPublicationHTTP map[string]json.RawMessage

func (f awsPublicationHTTP) FetchJSON(_ context.Context, url string, _ dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	b, ok := f[url]
	if !ok {
		return nil, nil, errors.New("unexpected publication URL: " + url)
	}
	return b, nil, nil
}

type awsPublicationLog struct{}

func (*awsPublicationLog) Canonical(dnsidlog.LogEvent) ([]byte, error) { return nil, nil }
func (*awsPublicationLog) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now(), nil
}
func (*awsPublicationLog) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{}, nil
}
func (*awsPublicationLog) VerifyOperationalContinuity(context.Context, string, string, string) error {
	return nil
}
func (*awsPublicationLog) VerifyGovernanceRelationship(context.Context, string, string) error {
	return nil
}
func (r *awsPublicationLog) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	return dnsidlog.LoggedStateEvidence{}, nil
}
func (*awsPublicationLog) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (*awsPublicationLog) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	return nil, nil
}

func awsPublication(t *testing.T, m *dnsid.IdentityManager) (config.Dependencies, *awsPublicationLog) {
	t.Helper()
	record, err := m.CreateTXTRecord()
	if err != nil {
		t.Fatal(err)
	}
	marshal := func(v any) json.RawMessage {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	reader := &awsPublicationLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register(strings.Split(record.LogRef, ":")[0], func(string) dnsidlog.LogReader { return reader }); err != nil {
		t.Fatal(err)
	}
	return config.Dependencies{DNSResolver: awsPublicationDNS{record.Serialize(), "_dnsid." + m.Domain()}, HTTPSFetcher: awsPublicationHTTP{record.KeyURI: marshal(m.GetKeySet().Raw()), record.EntityKeyURI: marshal(m.GetEntityKeySet().Raw()), record.StatusURI: json.RawMessage(`{"state":"ACTIVE","lastTransitionAt":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`)}, LogRegistry: registry}, reader
}

// setupPublication authors evidence from explicitly supplied fixture custody,
// never from the config-selected manager being tested. Only DNS/HTTP/log I/O is
// faked; owner signatures and the verifier remain real.
func setupAWSPublication(t *testing.T, cfg dnsid.Config, kp dnsid.KeyProvider) config.Dependencies {
	t.Helper()
	m, err := dnsid.NewIdentityManager(cfg, kp, dnsid.WithEntityKeyProvider(dnsid.GenerateES256KeyProvider()))
	if err != nil {
		t.Fatal(err)
	}
	deps, _ := awsPublication(t, m)
	verifier, err := dnsid.NewIdentityManager(cfg, kp, dnsid.WithDNSResolver(deps.DNSResolver), dnsid.WithHTTPSFetcher(deps.HTTPSFetcher), dnsid.WithLogRegistry(deps.LogRegistry))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyLocalPublication(context.Background()); err != nil {
		t.Fatalf("independent established publication invalid: %v", err)
	}
	return deps
}
