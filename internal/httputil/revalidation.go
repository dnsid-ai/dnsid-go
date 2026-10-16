package httputil

import "context"

type revalidationKey struct{}

// WithRevalidation propagates forced HTTP revalidation through identity and log reads.
func WithRevalidation(ctx context.Context) context.Context {
	return context.WithValue(ctx, revalidationKey{}, true)
}

// Revalidation reports whether this acquisition must revalidate HTTP caches.
func Revalidation(ctx context.Context) bool {
	revalidate, _ := ctx.Value(revalidationKey{}).(bool)
	return revalidate
}
