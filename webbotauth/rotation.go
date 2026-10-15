package webbotauth

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dnsid-ai/dnsid-go"
)

// normalizedIdentifier applies RFC 3986 syntax normalization without query/fragment.
func normalizedIdentifier(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.TrimSuffix(strings.ToLower(u.Host), ":443")
	u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = "", "", "", false
	path := u.EscapedPath()
	for i := 0; i+2 < len(path); i++ {
		if path[i] != '%' {
			continue
		}
		v, _ := strconv.ParseUint(path[i+1:i+3], 16, 8)
		c := byte(v)
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", rune(c)) {
			path = path[:i] + string(c) + path[i+3:]
		} else {
			path = path[:i+1] + strings.ToUpper(path[i+1:i+3]) + path[i+3:]
			i += 2
		}
	}
	if path == "" {
		path = "/"
	}
	u.Path, _ = url.PathUnescape(path)
	u.RawPath = path
	return u.ResolveReference(&url.URL{Path: u.Path, RawPath: u.RawPath}).String()
}

func currentKeyMatches(vd *dnsid.VerifiedDomain, domain, endpoint, keyID string) (bool, error) {
	if vd == nil || vd.Domain() != domain || vd.KeySet() == nil || vd.Record() == nil {
		return false, wbaError("missing DNSid identity")
	}
	if normalizedIdentifier(endpoint) == normalizedIdentifier(vd.Record().KeyURI) {
		return false, wbaError("discovery identifies authenticated ku")
	}
	current, err := vd.KeySet().CurrentOperationalSigningKey(vd.Record().Version)
	if err != nil {
		return false, err
	}
	thumb, err := current.Thumbprint()
	return err == nil && thumb == keyID && current.Alg() == dnsid.JoseAlgEdDSA, err
}

func (p *Profile) allowKeyRefresh(domain string) bool {
	p.retryMu.Lock()
	defer p.retryMu.Unlock()
	now := p.currentTime()
	if now.Before(p.retryAt[domain]) {
		return false
	}
	for key, until := range p.retryAt {
		if !now.Before(until) {
			delete(p.retryAt, key)
		}
	}
	if len(p.retryAt) >= 1024 {
		return false
	}
	if p.retryAt == nil {
		p.retryAt = make(map[string]time.Time)
	}
	p.retryAt[domain] = now.Add(5 * time.Second)
	return true
}
