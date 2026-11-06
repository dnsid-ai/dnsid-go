package foundry

import (
	"context"
	"time"
)

const (
	createTimeout = 30 * time.Second
	activeTimeout = 10 * time.Minute
)

func operationContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, present := ctx.Deadline(); present {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

type pollBackoff struct{ interval time.Duration }

func (b *pollBackoff) wait(ctx context.Context) error {
	if b.interval == 0 {
		b.interval = time.Second
	} else {
		b.interval = min(2*b.interval, 15*time.Second)
	}
	return wait(ctx, b.interval)
}
