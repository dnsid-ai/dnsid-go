//go:build dnsid_foundry

package foundry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOperationContext_DefaultsAndCallerDeadline(t *testing.T) {
	for _, timeout := range []time.Duration{createTimeout, activeTimeout} {
		start := time.Now()
		ctx, cancel := operationContext(context.Background(), timeout)
		deadline, ok := ctx.Deadline()
		cancel()
		if !ok || deadline.Before(start.Add(timeout)) || deadline.After(start.Add(timeout+time.Second)) {
			t.Fatalf("default=%s deadline=%v", timeout, deadline)
		}
	}
	if createTimeout != 30*time.Second || activeTimeout != 10*time.Minute {
		t.Fatal("incorrect workflow defaults")
	}
	parent, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	want, _ := parent.Deadline()
	for _, timeout := range []time.Duration{createTimeout, activeTimeout} {
		ctx, stop := operationContext(parent, timeout)
		got, _ := ctx.Deadline()
		stop()
		if !got.Equal(want) {
			t.Fatal("caller deadline replaced")
		}
	}
}

func TestPollBackoff_OneSecondDoublingToFifteen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var backoff pollBackoff
	for _, seconds := range []int{1, 2, 4, 8, 15, 15, 15} {
		if err := backoff.wait(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if backoff.interval != time.Duration(seconds)*time.Second {
			t.Fatalf("interval=%s want=%ds", backoff.interval, seconds)
		}
	}
}
