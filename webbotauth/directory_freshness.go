package webbotauth

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/httpcc"
)

// No directory is retained locally; age metadata still limits upstream evidence.
func directoryFreshness(header http.Header, started, received time.Time) (time.Time, error) {
	control, err := httpcc.ParseResponse(strings.Join(header.Values("Cache-Control"), ", "))
	if err != nil {
		return time.Time{}, wbaError("invalid directory cache control")
	}
	age := time.Duration(0)
	upstreamAge := uint64(0)
	if raw := header.Get("Age"); raw != "" {
		seconds, err := strconv.ParseUint(raw, 10, 31)
		if err != nil {
			return time.Time{}, wbaError("invalid directory age")
		}
		upstreamAge = seconds
		age = time.Duration(seconds) * time.Second
	}
	age += received.Sub(started)
	if date, err := http.ParseTime(header.Get("Date")); err == nil {
		age = max(age, received.Sub(date))
	}
	seconds, bounded := control.MaxAge()
	if !bounded {
		return time.Time{}, nil
	}
	// A revalidated zero-freshness response can serve only this acquisition.
	if seconds == 0 && upstreamAge == 0 {
		return time.Time{}, nil
	}
	deadline := received.Add(time.Duration(min(seconds, 1<<31)) * time.Second).Add(-age)
	if !received.Before(deadline) {
		return time.Time{}, wbaError("HTTP-stale directory")
	}
	return deadline, nil
}
