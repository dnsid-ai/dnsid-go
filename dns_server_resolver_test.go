package dnsid

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestNetDNSResolverUsesWireTTL(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ttl      uint32
		aliasTTL uint32
		want     time.Duration
	}{
		{"ordinary", 17, 0, 17 * time.Second},
		{"alias", 90, 4, 4 * time.Second},
		{"zero", 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			go func() {
				buf := make([]byte, 4096)
				for {
					n, addr, err := server.ReadFrom(buf)
					if err != nil {
						return
					}
					var p dnsmessage.Parser
					h, err := p.Start(buf[:n])
					if err != nil {
						return
					}
					q, err := p.Question()
					if err != nil {
						return
					}
					msg := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true}, Questions: []dnsmessage.Question{q}}
					if tc.aliasTTL > 0 {
						msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: tc.aliasTTL}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("target.example.com.")}})
					}
					msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: tc.ttl}, Body: &dnsmessage.TXTResource{TXT: []string{"first", "second"}}})
					answer, err := msg.Pack()
					if err == nil {
						server.WriteTo(answer, addr)
					}
				}
			}()
			resolver := netDNSResolver{r: &net.Resolver{Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.LocalAddr().String())
			}}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			records, _, err := resolver.FetchTXT(ctx, "_dnsid.example.com.")
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 || records[0].Value != "firstsecond" || records[0].TTL != tc.want {
				t.Fatalf("records = %+v, want firstsecond with TTL %s", records, tc.want)
			}
		})
	}
}

// TestDialDNSServerHonoursNetwork guards the TCP retry the Go resolver makes
// when a UDP answer is truncated: the dial must use the network it was asked
// for, not always UDP.
func TestDialDNSServerHonoursNetwork(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
			accepted <- struct{}{}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialDNSServer(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	conn.Close()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the TCP listener never saw the connection: the dial did not use tcp")
	}
	if _, err := dialDNSServer(ctx, "udp", "127.0.0.1:53"); err != nil {
		t.Fatalf("udp dial: %v", err)
	}
}

// TestCustomDNSServerResolverRetriesTruncatedAnswerOverTCP is the behaviour
// the dial fix exists for. A fake server on one port answers every UDP query
// with TC set and no records, the way Route 53 answers a non-EDNS0 TXT query
// for a DNSid record, and serves the full record over TCP. Config.Transport.DNSServer's
// resolver must come back with the TXT record, which means its TCP retry
// really went over TCP.
func TestCustomDNSServerResolverRetriesTruncatedAnswerOverTCP(t *testing.T) {
	const name = "_dnsid.agent.example.com."
	const txt = "v=DNSid1;ek=https://agent.example.com/.well-known/dnsid.json"

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		t.Fatalf("tcp listen on the udp port: %v", err)
	}
	defer tcp.Close()

	answer := func(query []byte, truncated bool) []byte {
		var p dnsmessage.Parser
		h, err := p.Start(query)
		if err != nil {
			t.Errorf("parse query: %v", err)
			return nil
		}
		q, err := p.Question()
		if err != nil {
			t.Errorf("parse question: %v", err)
			return nil
		}
		msg := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: h.ID, Response: true, Truncated: truncated, RecursionAvailable: true},
			Questions: []dnsmessage.Question{q},
		}
		if !truncated {
			msg.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.TXTResource{TXT: []string{txt}},
			}}
		}
		out, err := msg.Pack()
		if err != nil {
			t.Errorf("pack answer: %v", err)
		}
		return out
	}

	udpQueries := make(chan struct{}, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			udpQueries <- struct{}{}
			if out := answer(buf[:n], true); out != nil {
				udp.WriteTo(out, addr)
			}
		}
	}()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var length [2]byte
				if _, err := io.ReadFull(c, length[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(length[:]))
				if _, err := io.ReadFull(c, query); err != nil {
					return
				}
				out := answer(query, false)
				if out == nil {
					return
				}
				binary.BigEndian.PutUint16(length[:], uint16(len(out)))
				c.Write(append(length[:], out...))
			}()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	records, _, err := customDNSServerResolver{server: udp.LocalAddr().String()}.FetchTXT(ctx, name)
	if err != nil {
		t.Fatalf("FetchTXT: %v", err)
	}
	select {
	case <-udpQueries:
	default:
		t.Fatal("the resolver never asked over UDP; the test did not exercise the truncation retry")
	}
	if len(records) != 1 || records[0].Value != txt || records[0].TTL != time.Minute {
		t.Fatalf("records = %+v, want the record and its TTL served over TCP", records)
	}
}
