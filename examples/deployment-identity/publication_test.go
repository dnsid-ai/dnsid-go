package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

type examplePublicationDNS struct{ record, name string }

func (d examplePublicationDNS) FetchTXT(_ context.Context, name string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	if name != d.name {
		return nil, dnsid.DNSSECStateUnsigned, errors.New("unexpected DNS name")
	}
	return []dnsid.TXTRecordRData{{Value: d.record, TTL: time.Minute}}, dnsid.DNSSECStateValid, nil
}

type examplePublicationHTTP map[string]json.RawMessage

func (f examplePublicationHTTP) FetchJSON(_ context.Context, url string, _ dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	b, ok := f[url]
	if !ok {
		return nil, nil, errors.New("unexpected publication URL: " + url)
	}
	return b, nil, nil
}

type examplePublicationLog struct{}

func (*examplePublicationLog) Canonical(dnsidlog.LogEvent) ([]byte, error) { return nil, nil }
func (*examplePublicationLog) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now(), nil
}
func (*examplePublicationLog) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{}, nil
}
func (*examplePublicationLog) VerifyOperationalContinuity(context.Context, string, string, string) error {
	return nil
}
func (*examplePublicationLog) VerifyGovernanceRelationship(context.Context, string, string) error {
	return nil
}
func (r *examplePublicationLog) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	return dnsidlog.LoggedStateEvidence{}, nil
}
func (*examplePublicationLog) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (*examplePublicationLog) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	return nil, nil
}

func examplePublication(t *testing.T, m *dnsid.IdentityManager) (config.Dependencies, *examplePublicationLog) {
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
	reader := &examplePublicationLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register(strings.Split(record.LogRef, ":")[0], func(string) dnsidlog.LogReader { return reader }); err != nil {
		t.Fatal(err)
	}
	return config.Dependencies{DNSResolver: examplePublicationDNS{record.Serialize(), "_dnsid." + m.Domain()}, HTTPSFetcher: examplePublicationHTTP{record.KeyURI: marshal(m.GetKeySet().Raw()), record.EntityKeyURI: marshal(m.GetEntityKeySet().Raw()), record.StatusURI: json.RawMessage(`{"state":"ACTIVE","lastTransitionAt":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`)}, LogRegistry: registry}, reader
}

// setupPublication authors evidence from explicitly supplied fixture custody,
// never from the config-selected manager being tested. Only DNS/HTTP/log I/O is
// faked; owner signatures and the verifier remain real.
func setupExamplePublication(t *testing.T, cfg dnsid.Config, kp dnsid.KeyProvider) config.Dependencies {
	t.Helper()
	m, err := dnsid.NewIdentityManager(cfg, kp, dnsid.WithEntityKeyProvider(dnsid.GenerateES256KeyProvider()))
	if err != nil {
		t.Fatal(err)
	}
	deps, _ := examplePublication(t, m)
	verifier, err := dnsid.NewIdentityManager(cfg, kp, dnsid.WithDNSResolver(deps.DNSResolver), dnsid.WithHTTPSFetcher(deps.HTTPSFetcher), dnsid.WithLogRegistry(deps.LogRegistry))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyLocalPublication(context.Background()); err != nil {
		t.Fatalf("independent established publication invalid: %v", err)
	}
	return deps
}
