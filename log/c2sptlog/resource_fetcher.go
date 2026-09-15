package c2sptlog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/dnsid-ai/dnsid-go/internal/netguard"
)

// ResourceFetchGuarantees declares the security properties provided by a
// BoundedResourceFetcher. The verification convenience factory requires every
// property for policy and public-log reads.
type ResourceFetchGuarantees struct {
	HTTPSOnly                     bool
	RejectsRedirects              bool
	ValidatesAllResolvedAddresses bool
	ConnectsToValidatedAddress    bool
	BoundsResponseDuringRead      bool
}

// SupportsPublicReads reports whether all transport guarantees required for a
// public c2sp-tlog policy and standard-resource scan are present.
func (g ResourceFetchGuarantees) SupportsPublicReads() bool {
	return g.HTTPSOnly && g.RejectsRedirects && g.ValidatesAllResolvedAddresses &&
		g.ConnectsToValidatedAddress && g.BoundsResponseDuringRead
}

// BoundedResourceFetcher fetches one resource while enforcing maxBytes during
// the read. Implementations must honor ctx cancellation and accurately report
// their transport properties through SecurityGuarantees. A supplied fetcher is
// trusted caller infrastructure; the SDK still checks the returned length.
type BoundedResourceFetcher interface {
	FetchBounded(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error)
	SecurityGuarantees() ResourceFetchGuarantees
}

// ResourceFetchErrorKind classifies failures from standard C2SP resource
// retrieval.
type ResourceFetchErrorKind string

const (
	// ResourceFetchMalformedURL indicates that the resource URL is invalid.
	ResourceFetchMalformedURL ResourceFetchErrorKind = "malformed_url"
	// ResourceFetchUnsafeDestination indicates that destination safety checks failed.
	ResourceFetchUnsafeDestination ResourceFetchErrorKind = "unsafe_destination"
	// ResourceFetchRedirect indicates that the resource returned a redirect.
	ResourceFetchRedirect ResourceFetchErrorKind = "redirect"
	// ResourceFetchResponseLimit indicates that the resource exceeded its byte limit.
	ResourceFetchResponseLimit ResourceFetchErrorKind = "response_limit"
	// ResourceFetchHTTPStatus indicates that the resource returned a non-success status.
	ResourceFetchHTTPStatus ResourceFetchErrorKind = "http_status"
	// ResourceFetchUnavailable indicates a network or transport failure.
	ResourceFetchUnavailable ResourceFetchErrorKind = "unavailable"
)

// ResourceFetchError is returned when a policy or standard C2SP resource
// cannot be fetched safely. Unsafe destinations, redirects, malformed URLs,
// and response-limit failures are permanent; network availability failures
// and retryable HTTP statuses are transient.
type ResourceFetchError struct {
	Kind             ResourceFetchErrorKind
	URL              string
	MaximumBytes     int64
	HTTPStatus       int
	TransientFailure bool
	Cause            error
}

func (e *ResourceFetchError) Error() string {
	if e == nil {
		return "<nil>"
	}
	var detail string
	switch e.Kind {
	case ResourceFetchMalformedURL:
		detail = "resource URL is invalid"
	case ResourceFetchUnsafeDestination:
		detail = "resource destination is unsafe"
	case ResourceFetchRedirect:
		detail = "resource redirect is rejected"
	case ResourceFetchResponseLimit:
		detail = fmt.Sprintf("resource exceeds configured byte maximum %d", e.MaximumBytes)
	case ResourceFetchHTTPStatus:
		detail = fmt.Sprintf("resource returned HTTP %d", e.HTTPStatus)
	default:
		detail = "resource is unavailable"
	}
	if e.URL != "" {
		detail += " at " + e.URL
	}
	if e.Cause != nil {
		detail += ": " + e.Cause.Error()
	}
	return "dnsid: c2sp-tlog " + detail
}

func (e *ResourceFetchError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Transient reports whether retrying an unchanged fetch may succeed.
func (e *ResourceFetchError) Transient() bool {
	return e != nil && e.TransientFailure
}

type httpBoundedResourceFetcher struct {
	client     *http.Client
	httpsOnly  bool
	guarantees ResourceFetchGuarantees
}

func (f *httpBoundedResourceFetcher) SecurityGuarantees() ResourceFetchGuarantees {
	if f == nil {
		return ResourceFetchGuarantees{}
	}
	return f.guarantees
}

func (f *httpBoundedResourceFetcher) FetchBounded(ctx context.Context, rawURL string, maximum int64) ([]byte, error) {
	if maximum < 1 {
		return nil, &ResourceFetchError{Kind: ResourceFetchResponseLimit, URL: rawURL, MaximumBytes: maximum}
	}
	parsed, err := parseResourceURL(rawURL, f != nil && f.httpsOnly)
	if err != nil {
		return nil, &ResourceFetchError{Kind: ResourceFetchMalformedURL, URL: rawURL, Cause: err}
	}
	if ctx == nil {
		return nil, &ResourceFetchError{Kind: ResourceFetchMalformedURL, URL: rawURL, Cause: errors.New("nil context")}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, &ResourceFetchError{Kind: ResourceFetchMalformedURL, URL: rawURL, Cause: err}
	}
	client := f.client
	if client == nil {
		client = &http.Client{CheckRedirect: rejectResourceRedirect}
	}
	resp, err := client.Do(req)
	if err != nil {
		var unsafe *netguard.UnsafeDestinationError
		if errors.As(err, &unsafe) {
			return nil, &ResourceFetchError{Kind: ResourceFetchUnsafeDestination, URL: rawURL, Cause: err}
		}
		return nil, &ResourceFetchError{Kind: ResourceFetchUnavailable, URL: rawURL, TransientFailure: true, Cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		return nil, &ResourceFetchError{Kind: ResourceFetchRedirect, URL: rawURL, HTTPStatus: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		transient := resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode >= http.StatusInternalServerError && resp.StatusCode <= 599
		return nil, &ResourceFetchError{Kind: ResourceFetchHTTPStatus, URL: rawURL, HTTPStatus: resp.StatusCode, TransientFailure: transient}
	}
	data, exceeded, err := readBoundedBody(resp.Body, maximum)
	if err != nil {
		return nil, &ResourceFetchError{Kind: ResourceFetchUnavailable, URL: rawURL, TransientFailure: true, Cause: err}
	}
	if exceeded {
		return nil, &ResourceFetchError{Kind: ResourceFetchResponseLimit, URL: rawURL, MaximumBytes: maximum}
	}
	return data, nil
}

func readBoundedBody(body io.Reader, maximum int64) ([]byte, bool, error) {
	limited := &io.LimitedReader{R: body, N: maximum}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if limited.N > 0 {
		return data, false, nil
	}
	var extra [1]byte
	n, err := io.ReadFull(body, extra[:])
	if n > 0 {
		return nil, true, nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	return data, false, nil
}

func parseResourceURL(rawURL string, httpsOnly bool) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed == nil || !parsed.IsAbs() || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		if err == nil {
			err = errors.New("absolute URL with a host is required")
		}
		return nil, err
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" {
		return nil, errors.New("URL credentials and fragments are not allowed")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return nil, errors.New("URL port must not be empty")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return nil, errors.New("URL port must be between 1 and 65535")
		}
	}
	if httpsOnly && parsed.Scheme != "https" {
		return nil, errors.New("HTTPS is required")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, errors.New("HTTP or HTTPS URL is required")
	}
	return parsed, nil
}

func rejectResourceRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func fetchBounded(fetcher BoundedResourceFetcher, ctx context.Context, rawURL string, maximum int64) ([]byte, error) {
	if fetcher == nil {
		return nil, &ResourceFetchError{Kind: ResourceFetchUnavailable, URL: rawURL, Cause: errors.New("resource fetcher is required")}
	}
	data, err := fetcher.FetchBounded(ctx, rawURL, maximum)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, &ResourceFetchError{Kind: ResourceFetchResponseLimit, URL: rawURL, MaximumBytes: maximum}
	}
	return data, nil
}
