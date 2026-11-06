package foundry

import (
	"context"
	"fmt"
	"time"

	"github.com/dnsid-ai/dnsid-go/config"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

// Defer policy-URL fetching until evidence is requested, so completed-operation
// restart can construct the normal manager and restore signing without a fetch.
type lazyLogTrust struct {
	loaded   config.Loaded
	gate     chan struct{}
	resolved *dnsidlog.LogRegistry
}

func newLazyLogRegistry(loaded config.Loaded) (*dnsidlog.LogRegistry, *lazyLogTrust, error) {
	trust := &lazyLogTrust{loaded: loaded, gate: make(chan struct{}, 1)}
	registry := dnsidlog.NewLogRegistry()
	err := registry.Register("c2sp-tlog", func(lr string) dnsidlog.LogReader { return &lazyLogReader{trust: trust, reference: lr} })
	return registry, trust, err
}

func (t *lazyLogTrust) get(ctx context.Context) (*dnsidlog.LogRegistry, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case t.gate <- struct{}{}:
	}
	defer func() { <-t.gate }()
	if t.resolved != nil {
		return t.resolved, nil
	}
	registry, err := config.LogRegistryFromTrust(ctx, t.loaded.LogTrust, t.loaded.Dnsid.Transport)
	if err != nil {
		return nil, err
	}
	t.resolved = registry
	return registry, nil
}

type lazyLogReader struct {
	trust     *lazyLogTrust
	reference string
}

func (r *lazyLogReader) get(ctx context.Context) (dnsidlog.LogReader, error) {
	registry, err := r.trust.get(ctx)
	if err != nil {
		return nil, err
	}
	return registry.NewReader(r.reference)
}
func (r *lazyLogReader) Canonical(event dnsidlog.LogEvent) ([]byte, error) {
	client, err := c2sptlog.New(r.reference)
	if err != nil {
		return nil, err
	}
	return client.Canonical(event)
}
func (r *lazyLogReader) PreloadHistory(ctx context.Context, domain string) (dnsidlog.LogReader, error) {
	reader, err := r.get(ctx)
	if err != nil {
		return nil, err
	}
	if preload, ok := reader.(interface {
		PreloadHistory(context.Context, string) (dnsidlog.LogReader, error)
	}); ok {
		return preload.PreloadHistory(ctx, domain)
	}
	return reader, nil
}
func (r *lazyLogReader) KeyTimestamp(ctx context.Context, domain, thumb string) (time.Time, error) {
	reader, err := r.get(ctx)
	if err != nil {
		return time.Time{}, err
	}
	return reader.KeyTimestamp(ctx, domain, thumb)
}
func (r *lazyLogReader) VerifyBilateralBinding(ctx context.Context, input dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	reader, err := r.get(ctx)
	if err != nil {
		return dnsidlog.BilateralBinding{}, err
	}
	return reader.VerifyBilateralBinding(ctx, input)
}
func (r *lazyLogReader) VerifyOperationalContinuity(ctx context.Context, domain, initial, current string) error {
	reader, err := r.get(ctx)
	if err != nil {
		return err
	}
	return reader.VerifyOperationalContinuity(ctx, domain, initial, current)
}
func (r *lazyLogReader) VerifyNonRevocation(ctx context.Context, domain string, at time.Time) (dnsidlog.LoggedStateEvidence, error) {
	reader, err := r.get(ctx)
	if err != nil {
		return dnsidlog.LoggedStateEvidence{}, err
	}
	return reader.VerifyNonRevocation(ctx, domain, at)
}
func (r *lazyLogReader) ReadEvent(ctx context.Context, ref dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	reader, err := r.get(ctx)
	if err != nil {
		return dnsidlog.LogEvent{}, err
	}
	return reader.ReadEvent(ctx, ref)
}
func (r *lazyLogReader) RebuildHistory(ctx context.Context, domain string) ([]dnsidlog.LogEvent, error) {
	reader, err := r.get(ctx)
	if err != nil {
		return nil, err
	}
	return reader.RebuildHistory(ctx, domain)
}
func (r *lazyLogReader) VerifyGovernanceRelationship(ctx context.Context, domain, governance string) error {
	reader, err := r.get(ctx)
	if err != nil {
		return err
	}
	if verifier, ok := reader.(interface {
		VerifyGovernanceRelationship(context.Context, string, string) error
	}); ok {
		return verifier.VerifyGovernanceRelationship(ctx, domain, governance)
	}
	return fmt.Errorf("foundry: log binding does not verify delegated governance")
}
