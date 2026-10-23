package c2sptlog

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"golang.org/x/mod/sumdb/note"
)

func TestClientPreloadHistory_BundleExpiryAndScope(t *testing.T) {
	for _, mode := range []string{"fetched", "offline"} {
		t.Run(mode, func(t *testing.T) {
			vector := loadStreamBundleVector(t)
			verifier, err := note.NewVerifier(vector.Trust.BundleVerifierKey)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(vector.Trust.Now, 0)
			clock := func() time.Time { return now }
			trust := StreamBundleTrust{
				PolicyDocument: []byte(vector.Policy), BundleVerifier: verifier, Now: clock,
				MaxBundleLifetime: time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
				MaxCheckpointAge:  10 * time.Minute,
			}
			bundle, err := VerifyStreamBundle(context.Background(), []byte(vector.Bundle), trust)
			if err != nil {
				t.Fatal(err)
			}
			now = bundle.Expires.Add(-time.Second)
			var source Source = bundle.Source
			fetches := 0
			var fetchCtx context.Context
			if mode == "fetched" {
				source = &fetchedStreamBundleSource{
					requireBundle: true, trust: trust,
					fetcher: &testBoundedFetcher{fetch: func(ctx context.Context, _ string, _ int64) ([]byte, error) {
						fetches++
						fetchCtx = ctx
						return []byte(vector.Bundle), nil
					}},
				}
			}
			policy, err := ParsePolicy(trust.PolicyDocument)
			if err != nil {
				t.Fatal(err)
			}
			policy.Now, policy.MaxCheckpointAge = clock, trust.MaxCheckpointAge
			client, err := New(bundle.Reference.String(), WithSource(source), WithPolicy(policy))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			prepared, err := client.PreloadHistory(ctx, bundle.FQDN)
			if err != nil {
				t.Fatal(err)
			}
			reader := prepared.(*Client)
			if reader.preloaded == nil || reader.preloaded.ctx != ctx || ctx.Err() != nil || client.preloaded != nil {
				t.Fatal("preload must retain its parent scope without mutating the original reader")
			}
			if mode == "fetched" && !errors.Is(fetchCtx.Err(), context.Canceled) {
				t.Fatal("fetch context was not released")
			}
			if events, err := prepared.RebuildHistory(ctx, bundle.FQDN); err != nil || len(events) != vector.Expected.EventCount {
				t.Fatalf("unexpired history: events=%d err=%v", len(events), err)
			}
			if mode == "fetched" && fetches != 1 {
				t.Fatalf("preloaded history refetched %d times", fetches)
			}
			// Expire during proof verification, then repeat with already-expired evidence.
			reader.policy.Now = func() time.Time { now = bundle.Expires; return now }
			for range 2 {
				events, err := prepared.RebuildHistory(ctx, bundle.FQDN)
				if err == nil || !strings.Contains(err.Error(), "expired") || len(events) != 0 {
					t.Fatalf("expired preload: events=%d err=%v", len(events), err)
				}
			}
			cancel()
			if mode == "fetched" {
				if _, err := prepared.RebuildHistory(context.Background(), bundle.FQDN); err == nil || fetches != 2 {
					t.Fatalf("canceled scope must reacquire evidence: fetches=%d err=%v", fetches, err)
				}
			}
		})
	}
}

func TestClientPreloadHistory_FetchDeadline(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "caller deadline"}[explicit], func(t *testing.T) {
			ctx := context.Background()
			if explicit {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Minute)
				defer cancel()
			}
			started := time.Now()
			cause := errors.New("fetch stopped")
			var fetchCtx context.Context
			source := &fetchedStreamBundleSource{requireBundle: true, fetcher: &testBoundedFetcher{
				fetch: func(child context.Context, _ string, _ int64) ([]byte, error) {
					fetchCtx = child
					deadline, ok := child.Deadline()
					if !ok {
						t.Fatal("fetch has no deadline")
					}
					if want, ok := ctx.Deadline(); ok {
						if !deadline.Equal(want) {
							t.Fatalf("deadline = %v, want caller deadline %v", deadline, want)
						}
					} else if deadline.Before(started.Add(dnsid.DefaultVerificationTimeout)) || deadline.After(time.Now().Add(dnsid.DefaultVerificationTimeout)) {
						t.Fatalf("deadline %v does not use the SDK default", deadline)
					}
					return nil, cause
				},
			}}
			client, err := New("c2sp-tlog:public:https://log.example#EREREREREREREREREREREQ", WithSource(source))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.PreloadHistory(ctx, "agent.example.com"); !errors.Is(err, cause) {
				t.Fatalf("error = %v, want fetch cause", err)
			}
			if ctx.Err() != nil || !errors.Is(fetchCtx.Err(), context.Canceled) {
				t.Fatal("fetch cancellation must not cancel the caller")
			}
		})
	}
}

func TestClientPreloadHistory_CustomSourcesNotReused(t *testing.T) {
	client, err := New("c2sp-tlog:public:https://log.example#EREREREREREREREREREREQ", WithSource(basicSource{}))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := client.PreloadHistory(context.Background(), "agent.example.com")
	if err != nil || prepared != client || client.preloaded != nil {
		t.Fatalf("custom source without freshness bounds must keep the original reader: %v", err)
	}
}
