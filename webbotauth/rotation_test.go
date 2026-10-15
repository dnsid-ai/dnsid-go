package webbotauth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/httpsig"
)

func newWBAVerifier(t *testing.T, resolver dnsid.IdentityResolver, cfg Config) *Profile {
	t.Helper()
	p, err := NewVerifier(resolver, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWBA_DirectoryBackdating(t *testing.T) {
	for _, ttl := range []int64{300, 5, 1} {
		f := newWBAFixture(t, false, false)
		now := time.Now().Truncate(time.Second)
		f.signer.now = func() time.Time { return now }
		f.signer.cfg.DirectorySignatureTTL = time.Duration(ttl) * time.Second
		req, _ := http.NewRequest(http.MethodGet, "https://"+f.opts.SignerDomain+DirectoryPath, nil)
		res, err := f.signer.ServeHttpMessageSignaturesDirectory(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		wantCache := "max-age=" + strconv.FormatInt(ttl-min(5, ttl-1), 10) + ", must-revalidate"
		if res.Header.Get("Cache-Control") != wantCache || res.Header.Get("Content-Encoding") != "" {
			t.Fatalf("directory headers: %v", res.Header)
		}
		inputs, err := httpsig.ParseSignatureInput(res.Header.Get("Signature-Input"))
		if err != nil {
			t.Fatal(err)
		}
		params := inputs["sig1"]
		if params.Created != now.Unix()-min(5, ttl-1) || params.Expires-params.Created != ttl {
			t.Fatalf("ttl=%d: %+v", ttl, params)
		}
		if ttl == 300 {
			f.checker.now = func() time.Time { return now.Add(-5 * time.Second) }
			if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err != nil {
				t.Fatal(err)
			}
		}
	}
}

type refreshingWBAResolver struct {
	dnsid.IdentityResolver
	refresh func(context.Context, string, dnsid.VerifyDomainOpts) (*dnsid.VerifiedDomain, error)
}

func (r refreshingWBAResolver) RefreshDomain(ctx context.Context, domain string, peer dnsid.VerifyDomainOpts) (*dnsid.VerifiedDomain, error) {
	return r.refresh(ctx, domain, peer)
}

func TestWBA_KeyMismatchRefresh(t *testing.T) {
	for _, mode := range []string{"success", "unchanged", "unavailable", "denied", "revoked", "bad-request", "bad-directory", "identity-failure", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f := newWBAFixture(t, false, false)
			old := newWBAFixture(t, false, false)
			calls := 0
			f.checker.resolver = refreshingWBAResolver{IdentityResolver: old.manager,
				refresh: func(ctx context.Context, domain string, peer dnsid.VerifyDomainOpts) (*dnsid.VerifiedDomain, error) {
					calls++
					switch mode {
					case "unchanged":
						return old.manager.RefreshDomain(ctx, domain, peer)
					case "unavailable":
						return nil, context.DeadlineExceeded
					case "denied":
						return nil, dnsid.NewVerificationError(dnsid.VerificationCodeCounterpartyNotAccepted, false, "denied", nil)
					case "revoked":
						return nil, dnsid.NewVerificationError(dnsid.VerificationCodeStatusNotActive, false, "revoked", nil)
					case "expired":
						f.checker.now = func() time.Time { return time.Now().Add(time.Hour) }
					}
					return f.manager.RefreshDomain(ctx, domain, peer)
				}}
			if mode == "bad-request" {
				f.request.Header.Set("Signature", "sig1=:AAAA:")
			}
			if mode == "bad-directory" {
				f.checker.client.Transport = wbaRoundTrip(func(req *http.Request) (*http.Response, error) {
					res, err := f.signer.ServeHttpMessageSignaturesDirectory(req)
					res.Header.Set("Signature", "sig1=:AAAA:")
					return res, err
				})
			}
			if mode == "identity-failure" {
				old.dns.record = nil
			}
			_, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts)
			if (err == nil) != (mode == "success") {
				t.Fatalf("verification: %v", err)
			}
			want := 1
			if mode == "bad-request" || mode == "bad-directory" || mode == "identity-failure" {
				want = 0
			}
			if calls != want {
				t.Fatalf("refresh calls=%d, want %d", calls, want)
			}
			if mode == "unchanged" || mode == "unavailable" {
				f.signer.cfg = Config{SignatureAgentType: "jwks_uri", DirectoryURL: "https://" + f.opts.SignerDomain + "/another?key=changed"}
				f.signer.keys = dnsid.GenerateEd25519KeyProvider()
				f.request, err = f.signer.CreateWebBotAuthSignedRequest(f.request, SigningOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err == nil || calls != 1 {
					t.Fatalf("failed refresh cooldown bypassed by key/URL change: calls=%d, err=%v", calls, err)
				}
			}
		})
	}
}

func TestWBA_RefreshCooldown(t *testing.T) {
	p := New("", nil, Config{})
	now := time.Now()
	p.now = func() time.Time { return now }
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if p.allowKeyRefresh("bot.example") {
				admitted.Add(1)
			}
		})
	}
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatalf("admitted %d concurrent refreshes", admitted.Load())
	}
	now = now.Add(5 * time.Second)
	if !p.allowKeyRefresh("bot.example") {
		t.Fatal("cooldown did not expire")
	}
	for len(p.retryAt) < 1024 {
		p.retryAt[time.Unix(int64(len(p.retryAt)), 0).String()] = now.Add(time.Hour)
	}
	if p.allowKeyRefresh("other.example") || p.allowKeyRefresh("bot.example") {
		t.Fatal("full state or active cooldown was bypassed")
	}
}

func TestWBA_RequiresRefreshingResolver(t *testing.T) {
	for _, resolver := range []dnsid.IdentityResolver{nil, verifyOnlyWBAResolver{}} {
		_, err := NewVerifier(resolver, Config{})
		var argumentErr *dnsid.ArgumentError
		if !errors.As(err, &argumentErr) {
			t.Fatalf("expected construction error, got %v", err)
		}
	}
}

func TestWBA_DiscoveryCannotIdentifyKU(t *testing.T) {
	for _, suffix := range []string{"", "?cache=x#fragment"} {
		f := newWBAFixture(t, false, false)
		// Normalize host/default port, dot segments, and unreserved escapes too.
		uri := "https://BOT.EXAMPLE.COM:443/other/../%6bu" + suffix
		f.signer.cfg = Config{DirectoryURL: uri, SignatureAgentType: "jwks_uri"}
		f.signer.kuURL = f.dns.record.KeyURI
		if _, err := f.signer.CreateWebBotAuthSignedRequest(f.request, SigningOptions{}); err == nil {
			t.Fatal("signer accepted local ku discovery")
		}
		f.request.Header.Set("Signature-Agent", `sig1="`+uri+`";type=jwks_uri`)
		inputs, _ := httpsig.ParseSignatureInput(f.request.Header.Get("Signature-Input"))
		params := inputs["sig1"]
		if err := httpsig.SignHTTPMessage(f.request, params, f.signer.keys); err != nil {
			t.Fatal(err)
		}
		if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err == nil || !strings.Contains(err.Error(), "authenticated ku") {
			t.Fatalf("verifier accepted ku discovery: %v", err)
		}
	}
}

func TestWBA_FreshDirectoryKeyMissIsNotRetried(t *testing.T) {
	f := newWBAFixture(t, false, false)
	other := newWBAFixture(t, false, false)
	calls := 0
	f.checker.client.Transport = wbaRoundTrip(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Header.Get("Cache-Control") != "no-cache" || req.Header.Get("If-None-Match") != "" {
			t.Error("discovery did not require unconditional revalidation")
		}
		return other.signer.ServeHttpMessageSignaturesDirectory(req)
	})
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err == nil || calls != 1 {
		t.Fatalf("fresh key miss: calls=%d, error=%v", calls, err)
	}
}

func TestWBA_DirectoryHTTPFreshness(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		control, age string
		date         time.Time
		valid        bool
	}{
		{"max-age=295, must-revalidate", "295", now, false},
		{"max-age=295, must-revalidate", "294", now, true},
		{"max-age=295, must-revalidate", "", now.Add(-295 * time.Second), false},
		{"max-age=295, must-revalidate", "", time.Time{}, true},
		{"max-age=0", "0", now, true},
		{"max-age=0", "1", now, false},
		{"no-store", "", time.Time{}, true},
		{"no-cache", "", time.Time{}, true},
	} {
		header := http.Header{"Cache-Control": {tc.control}}
		if tc.age != "" {
			header.Set("Age", tc.age)
		}
		if !tc.date.IsZero() {
			header.Set("Date", tc.date.Format(http.TimeFormat))
		}
		_, err := directoryFreshness(header, now, now)
		if (err == nil) != tc.valid {
			t.Fatalf("control=%s age=%s: %v", tc.control, tc.age, err)
		}
	}
}

type verifyOnlyWBAResolver struct{}

func (verifyOnlyWBAResolver) VerifyDomain(context.Context, string) (*dnsid.VerifiedDomain, error) {
	panic("must not resolve during construction")
}
