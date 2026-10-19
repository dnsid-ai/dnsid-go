package dnsid

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsOutcomeResolver struct {
	records []TXTRecordRData
	state   DNSSECState
	err     error
}

func (r *dnsOutcomeResolver) FetchTXT(context.Context, string) ([]TXTRecordRData, DNSSECState, error) {
	return r.records, r.state, r.err
}

// Bound the lookup independently of the verification caller's cancellation.
type timeoutDNSResolver struct{ DNSResolver }

func (r timeoutDNSResolver) FetchTXT(ctx context.Context, name string) ([]TXTRecordRData, DNSSECState, error) {
	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	return r.DNSResolver.FetchTXT(ctx, name)
}

func requireDNSOutcome(t *testing.T, manager *IdentityManager, code VerificationCode, transient bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	vd, err := manager.VerifyDomain(ctx, "agent.example.com")
	var ve *VerificationError
	if vd != nil || !errors.As(err, &ve) || ve.Code() != code || ve.Transient() != transient {
		t.Fatalf("VerifyDomain = (%v, %v), want %s (transient=%v)", vd, err, code, transient)
	}
	if manager.cachedDomain("agent.example.com") != nil {
		t.Fatal("failed verification populated the identity cache")
	}
}

func TestVerifyDomain_InjectedDNSOutcomes(t *testing.T) {
	for _, mode := range []DNSSECMode{DNSSECModeAuto, DNSSECModeValidated, DNSSECModeRequired} {
		for _, state := range []DNSSECState{"", DNSSECStateUnknown, DNSSECStateUnsigned, DNSSECStateValid, DNSSECStateFailed, "BOGUS"} {
			for _, tc := range []struct {
				name      string
				records   []TXTRecordRData
				err       error
				code      VerificationCode
				transient bool
			}{
				{name: "nodata", code: VerificationCodeRecordNotFound},
				{name: "nxdomain", err: &net.DNSError{IsNotFound: true}, code: VerificationCodeRecordNotFound},
				{name: "wrapped nodata", err: fmt.Errorf("resolver: %w", &net.DNSError{IsNotFound: true}), code: VerificationCodeRecordNotFound},
				{name: "multiple", records: []TXTRecordRData{{Value: "bad"}, {Value: "bad"}}, code: VerificationCodeRecordInvalid},
				{name: "malformed", records: []TXTRecordRData{{Value: "bad"}}, code: VerificationCodeRecordInvalid},
				{name: "invalid semantics", records: []TXTRecordRData{{Value: "v=dnsid-draft-01;gi=example.com;ek=https://example.com/ek;ku=http://agent.example.com/ku;lr=test:agent;su=https://agent.example.com/status;sg=AAAA"}}, code: VerificationCodeRecordInvalid},
				{name: "timeout", err: &net.DNSError{IsTimeout: true}, code: VerificationCodeDNSResolution, transient: true},
				{name: "timeout with not-found flag", err: &net.DNSError{IsTimeout: true, IsNotFound: true}, code: VerificationCodeDNSResolution, transient: true},
				{name: "temporary with not-found flag", err: &net.DNSError{IsTemporary: true, IsNotFound: true}, code: VerificationCodeDNSResolution, transient: true},
				{name: "network", err: errors.New("connection refused"), code: VerificationCodeDNSResolution, transient: true},
				{name: "servfail", err: &net.DNSError{Err: "server misbehaving", IsTemporary: true}, code: VerificationCodeDNSResolution, transient: true},
				{name: "untyped not-found message", err: errors.New("no such host"), code: VerificationCodeDNSResolution, transient: true},
			} {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, state, tc.name), func(t *testing.T) {
					resolver := &dnsOutcomeResolver{records: tc.records, state: state, err: tc.err}
					manager, err := NewIdentityManager(Config{Verification: VerificationConfig{DNSSECMode: mode}}, nil, WithDNSResolver(resolver))
					if err != nil {
						t.Fatal(err)
					}
					code, transient := tc.code, tc.transient
					if state == DNSSECStateFailed || (!transient && (state == "BOGUS" ||
						(mode == DNSSECModeValidated && (state == "" || state == DNSSECStateUnknown)) ||
						(mode == DNSSECModeRequired && state != DNSSECStateValid))) {
						code, transient = VerificationCodeDNSSECFailed, false
					}
					requireDNSOutcome(t, manager, code, transient)
				})
			}
		}
	}
}

func TestDNSResolvers_WireOutcomes(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		for _, tc := range []struct {
			name   string
			rcode  dnsmessage.RCode
			values []string
			code   VerificationCode
		}{
			{name: "nxdomain", rcode: dnsmessage.RCodeNameError, code: VerificationCodeRecordNotFound},
			{name: "nodata", code: VerificationCodeRecordNotFound},
			{name: "multiple", values: []string{"bad", "bad"}, code: VerificationCodeRecordInvalid},
			{name: "malformed", values: []string{"bad"}, code: VerificationCodeRecordInvalid},
			{name: "servfail", rcode: dnsmessage.RCodeServerFailure, code: VerificationCodeDNSResolution},
			{name: "timeout", code: VerificationCodeDNSResolution},
		} {
			t.Run(fmt.Sprintf("tcp=%v/%s", tcp, tc.name), func(t *testing.T) {
				server := startDNSOutcomeServer(t, tcp, tc.rcode, tc.values, tc.name == "timeout")
				for _, configured := range []bool{false, true} {
					t.Run(fmt.Sprintf("configured=%v", configured), func(t *testing.T) {
						var resolver DNSResolver = netDNSResolver{r: &net.Resolver{Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
							return (&net.Dialer{}).DialContext(ctx, network, server)
						}}}
						if configured {
							resolver = customDNSServerResolver{server: server}
						}
						if tc.name == "timeout" {
							resolver = timeoutDNSResolver{resolver}
						}
						if tc.code == VerificationCodeRecordNotFound {
							ctx, cancel := context.WithTimeout(context.Background(), time.Second)
							defer cancel()
							records, state, err := resolver.FetchTXT(ctx, "_dnsid.agent.example.com")
							if len(records) != 0 || state != DNSSECStateUnknown || err != nil {
								t.Fatalf("FetchTXT = (%v, %s, %v), want empty/UNKNOWN/nil", records, state, err)
							}
						}
						manager, err := NewVerifier(WithDNSResolver(resolver))
						if err != nil {
							t.Fatal(err)
						}
						requireDNSOutcome(t, manager, tc.code, tc.code == VerificationCodeDNSResolution)
						if tc.code == VerificationCodeRecordNotFound {
							for _, mode := range []DNSSECMode{DNSSECModeValidated, DNSSECModeRequired} {
								manager.verification.DNSSECMode = mode
								requireDNSOutcome(t, manager, VerificationCodeDNSSECFailed, false)
							}
						}
					})
				}
			})
		}
	}
}

// startDNSOutcomeServer serves deterministic replies over UDP or a UDP-to-TCP retry.
func startDNSOutcomeServer(t *testing.T, tcpRetry bool, rcode dnsmessage.RCode, values []string, drop bool) string {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	answer := func(query []byte, truncated bool) []byte {
		var msg dnsmessage.Message
		if err := msg.Unpack(query); err != nil {
			t.Error(err)
			return nil
		}
		msg.Header = dnsmessage.Header{ID: msg.ID, Response: true, RecursionAvailable: true, Truncated: truncated}
		if !truncated {
			msg.RCode = rcode
			for _, value := range values {
				msg.Answers = append(msg.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{Name: msg.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.TXTResource{TXT: []string{value}},
				})
			}
		}
		out, err := msg.Pack()
		if err != nil {
			t.Error(err)
		}
		return out
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if !drop || tcpRetry {
				udp.WriteTo(answer(buf[:n], tcpRetry), addr)
			}
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				var length [2]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(length[:]))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				if drop {
					io.Copy(io.Discard, conn)
					return
				}
				out := answer(query, false)
				binary.BigEndian.PutUint16(length[:], uint16(len(out)))
				conn.Write(append(length[:], out...))
			}()
		}
	}()
	return udp.LocalAddr().String()
}

func TestDNSResolvers_NetworkFailure(t *testing.T) {
	for _, resolver := range []DNSResolver{
		netDNSResolver{r: &net.Resolver{Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("network unavailable")
		}}},
		customDNSServerResolver{server: "127.0.0.1:0"},
	} {
		manager, err := NewVerifier(WithDNSResolver(resolver))
		if err != nil {
			t.Fatal(err)
		}
		requireDNSOutcome(t, manager, VerificationCodeDNSResolution, true)
	}
}

func TestVerifyDomain_RecordNotFoundAllowsLaterPublication(t *testing.T) {
	const domain = "agent.example.com"
	for _, notFound := range []error{nil, fmt.Errorf("resolver: %w", &net.DNSError{IsNotFound: true})} {
		t.Run(fmt.Sprint(notFound), func(t *testing.T) {
			fixture := newCoalescingFixture(t, []string{domain}, nil)
			resolver := &dnsOutcomeResolver{state: DNSSECStateUnsigned, err: notFound}
			fixture.manager.dns = resolver
			for range 2 {
				requireDNSOutcome(t, fixture.manager, VerificationCodeRecordNotFound, false)
			}
			resolver.records, resolver.err = fixture.dns.records["_dnsid."+domain], nil
			vd, err := fixture.manager.VerifyDomain(context.Background(), domain)
			if err != nil || vd == nil || vd.CachedState() != "fresh" {
				t.Fatalf("verification after publication = (%v, %v), want fresh identity", vd, err)
			}
			if fixture.manager.cachedDomain(domain) == nil {
				t.Fatal("successful verification did not populate the cache")
			}
		})
	}
}
