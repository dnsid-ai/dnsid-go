package dnsid

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestVerifiedDomain_CheckFreshness(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name   string
		change func(*VerifiedDomain)
		code   VerificationCode
	}{
		{"zero-ttl-acquired", func(*VerifiedDomain) {}, ""},
		{"zero-ttl-reused", func(v *VerifiedDomain) { v.verifiedAt = now.Add(-time.Hour) }, VerificationCodeDNSResolution},
		{"zero-ttl-cached", func(v *VerifiedDomain) { v.cachedState = "cached" }, VerificationCodeDNSResolution},
		{"positive-ttl", func(v *VerifiedDomain) {
			v.dnsTTL = time.Minute
			v.dnsExpiresAt = now.Add(time.Minute)
			v.cachedState = "cached"
		}, ""},
		{"expired-dns", func(v *VerifiedDomain) { v.dnsTTL = time.Minute; v.dnsExpiresAt = now.Add(-time.Second) }, VerificationCodeDNSResolution},
		{"runtime-tls", func(v *VerifiedDomain) {
			v.jwksTLSCertificate = &tls.Certificate{Leaf: &x509.Certificate{NotAfter: now.Add(-time.Second)}}
		}, VerificationCodeTLSError},
		{"record-tls", func(v *VerifiedDomain) {
			v.ekTLSCertificate = &tls.Certificate{Leaf: &x509.Certificate{NotAfter: now.Add(-time.Second)}}
		}, VerificationCodeTLSError},
		{"future-tls", func(v *VerifiedDomain) {
			v.jwksTLSCertificate = &tls.Certificate{Leaf: &x509.Certificate{NotBefore: now.Add(time.Hour), NotAfter: now.Add(2 * time.Hour)}}
		}, VerificationCodeTLSError},
		{"key-age", func(v *VerifiedDomain) { v.record.KeyAge = "24h"; v.keyBoundAt = now.Add(-25 * time.Hour) }, VerificationCodeKeyAgeExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &VerifiedDomain{record: &TXTRecord{}, verifiedAt: now, cachedState: "fresh"}
			tc.change(v)
			err := v.CheckFreshness(now.Add(-time.Second))
			if tc.code == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var ve *VerificationError
			if !errors.As(err, &ve) || ve.Code() != tc.code {
				t.Fatalf("want %s, got %v", tc.code, err)
			}
		})
	}
}
