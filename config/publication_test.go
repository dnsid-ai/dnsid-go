package config

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"strings"
	"testing"
	"time"
)

type configPublicationDNS struct{ record, name string }

func (d configPublicationDNS) FetchTXT(_ context.Context, name string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	if name != d.name {
		return nil, dnsid.DNSSECStateUnsigned, errors.New("unexpected DNS name")
	}
	return []dnsid.TXTRecordRData{{Value: d.record, TTL: time.Minute}}, dnsid.DNSSECStateValid, nil
}

type configPublicationHTTP map[string]json.RawMessage

func (f configPublicationHTTP) FetchJSON(_ context.Context, url string, _ dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	b, ok := f[url]
	if !ok {
		return nil, nil, errors.New("unexpected publication URL: " + url)
	}
	return b, nil, nil
}

type configPublicationLog struct{}

func (*configPublicationLog) Canonical(dnsidlog.LogEvent) ([]byte, error) { return nil, nil }
func (*configPublicationLog) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now(), nil
}
func (*configPublicationLog) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{}, nil
}
func (*configPublicationLog) VerifyOperationalContinuity(context.Context, string, string, string) error {
	return nil
}
func (*configPublicationLog) VerifyGovernanceRelationship(context.Context, string, string) error {
	return nil
}
func (r *configPublicationLog) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	return dnsidlog.LoggedStateEvidence{}, nil
}
func (*configPublicationLog) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (*configPublicationLog) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	return nil, nil
}

func configPublication(t *testing.T, m *dnsid.IdentityManager) (Dependencies, *configPublicationLog) {
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
	reader := &configPublicationLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register(strings.Split(record.LogRef, ":")[0], func(string) dnsidlog.LogReader { return reader }); err != nil {
		t.Fatal(err)
	}
	return Dependencies{DNSResolver: configPublicationDNS{record.Serialize(), "_dnsid." + m.Domain()}, HTTPSFetcher: configPublicationHTTP{record.KeyURI: marshal(m.GetKeySet().Raw()), record.EntityKeyURI: marshal(m.GetEntityKeySet().Raw()), record.StatusURI: json.RawMessage(`{"state":"ACTIVE","lastTransitionAt":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`)}, LogRegistry: registry}, reader
}

// setupPublication authors evidence from explicitly supplied fixture custody,
// never from the config-selected manager being tested. Only DNS/HTTP/log I/O is
// faked; owner signatures and the verifier remain real.
func setupPublication(t *testing.T, cfg dnsid.Config, kp dnsid.KeyProvider) Dependencies {
	t.Helper()
	m, err := dnsid.NewIdentityManager(cfg, kp, dnsid.WithEntityKeyProvider(dnsid.GenerateES256KeyProvider()))
	if err != nil {
		t.Fatal(err)
	}
	deps, _ := configPublication(t, m)
	verifier, err := dnsid.NewIdentityManager(cfg, kp, dnsid.WithDNSResolver(deps.DNSResolver), dnsid.WithHTTPSFetcher(deps.HTTPSFetcher), dnsid.WithLogRegistry(deps.LogRegistry))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyLocalPublication(context.Background()); err != nil {
		t.Fatalf("independent established publication invalid: %v", err)
	}
	return deps
}

func envPublication(t *testing.T, env map[string]string, overlay dnsid.Config, kp dnsid.KeyProvider) Dependencies {
	t.Helper()
	loaded := mustLoadEnv(t, env)
	return setupPublication(t, Merge(loaded, Loaded{Dnsid: overlay}).Dnsid, kp)
}
func cliPublication(t *testing.T, dir string, overlay dnsid.Config, kp dnsid.KeyProvider) Dependencies {
	t.Helper()
	loaded, err := LoadCliDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	return setupPublication(t, Merge(loaded, Loaded{Dnsid: overlay}).Dnsid, kp)
}
