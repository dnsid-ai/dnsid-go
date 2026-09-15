package dnsid

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestWithIdentityCacheInjectsManagerCache(t *testing.T) {
	cache := NewIdentityCache(time.Hour)
	m, err := NewIdentityManager(Config{}, nil, WithIdentityCache(cache))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	if m.cache != cache {
		t.Fatal("IdentityManager did not retain the injected cache")
	}
}

func TestWithIdentityCacheRejectsNil(t *testing.T) {
	_, err := NewIdentityManager(Config{}, nil, WithIdentityCache(nil))
	var argumentErr *ArgumentError
	if !errors.As(err, &argumentErr) {
		t.Fatalf("NewIdentityManager error = %v, want ArgumentError", err)
	}
}

func TestIdentityCache_ExpiredEviction(t *testing.T) {
	c := NewIdentityCache(0)
	c.Put(&VerifiedDomain{domain: "example.com", expiry: time.Now().Add(-time.Minute)})

	if got := c.Get("example.com"); got != nil {
		t.Fatalf("expected nil for expired entry, got %v", got)
	}

	// Get must have evicted the expired entry under the write lock.
	c.mu.RLock()
	_, ok := c.entries[identityCacheKey{domain: "example.com"}]
	c.mu.RUnlock()
	if ok {
		t.Fatal("expected expired entry to be evicted")
	}
}

func TestIdentityCache_PreservesOperationalKey(t *testing.T) {
	key := GenerateES256KeyProvider().JWK()
	c := NewIdentityCache(time.Minute)
	c.Put(&VerifiedDomain{domain: "example.com", dnsTTL: time.Minute, kuKey: key, expiry: time.Now().Add(time.Minute)})

	got := c.Get("example.com")
	if got == nil || got.kuKey == nil {
		t.Fatal("cached operational key is missing")
	}
	wantThumb, _ := (&JWK{key: key}).Thumbprint()
	gotThumb, _ := (&JWK{key: got.kuKey}).Thumbprint()
	if gotThumb != wantThumb {
		t.Fatalf("cached operational key thumbprint = %q, want %q", gotThumb, wantThumb)
	}
}

func TestIdentityCache_ConcurrentGetPut(t *testing.T) {
	c := NewIdentityCache(time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			c.Put(&VerifiedDomain{domain: "example.com", dnsTTL: time.Minute, expiry: time.Now().Add(time.Minute)})
		}()
		go func() {
			defer wg.Done()
			c.Get("example.com")
		}()
	}
	wg.Wait()
}

// TestIdentityCache_UnlockRelockGap exercises the gap between dropping the read
// lock and acquiring the write lock in Get: a reader that observes an expired
// entry must return the fresh value if it is refreshed during the gap, not nil.
// The gapHook deterministically refreshes the entry inside the gap, so this
// fails if the re-check branch reverts to returning nil for a fresh entry.
func TestIdentityCache_UnlockRelockGap(t *testing.T) {
	const domain = "example.com"
	c := NewIdentityCache(0)
	// Seed an already-expired entry so Get enters the unlock/relock gap.
	c.entries[identityCacheKey{domain: domain}] = &VerifiedDomain{domain: domain, expiry: time.Now().Add(-time.Minute)}

	var once sync.Once
	c.gapHook = func() {
		// Refresh the entry exactly once, simulating a concurrent Put that
		// lands during the gap.
		once.Do(func() {
			c.Put(&VerifiedDomain{domain: domain, dnsTTL: time.Hour, expiry: time.Now().Add(time.Hour)})
		})
	}

	got := c.Get(domain)
	if got == nil {
		t.Fatal("Get returned nil for an entry refreshed during the unlock/relock gap")
	}
	if got.CachedState() != "cached" {
		t.Fatalf("expected cachedState %q, got %q", "cached", got.CachedState())
	}
}
