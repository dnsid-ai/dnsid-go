package dnsid

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// net.Resolver does not expose DNS TTLs, but its Dial hook lets us observe
// the exact replies it uses, including UDP replies retried over TCP.
type txtTTLCapture struct {
	mu   sync.Mutex
	ttls map[string]time.Duration
}

func (c *txtTTLCapture) dial(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(network, "udp") {
			if packet, ok := conn.(net.PacketConn); ok {
				return &ttlPacketConn{Conn: conn, packet: packet, capture: c}, nil
			}
			return &ttlDatagramConn{Conn: conn, capture: c}, nil
		}
		return &ttlStreamConn{Conn: conn, capture: c}, nil
	}
}

func (c *txtTTLCapture) observe(data []byte) {
	var msg dnsmessage.Message
	if err := msg.Unpack(data); err != nil || !msg.Response || msg.Truncated || msg.RCode != dnsmessage.RCodeSuccess || len(msg.Questions) != 1 || msg.Questions[0].Type != dnsmessage.TypeTXT {
		return
	}
	// Aliases cannot be trusted longer than the CNAME that led to the TXT.
	var aliasTTL uint32 = ^uint32(0)
	for _, answer := range msg.Answers {
		if answer.Header.Type == dnsmessage.TypeCNAME && answer.Header.TTL < aliasTTL {
			aliasTTL = answer.Header.TTL
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, answer := range msg.Answers {
		if answer.Header.Type != dnsmessage.TypeTXT || answer.Header.Class != dnsmessage.ClassINET {
			continue
		}
		txt, ok := answer.Body.(*dnsmessage.TXTResource)
		if !ok {
			continue
		}
		ttl := min(answer.Header.TTL, aliasTTL)
		value := strings.Join(txt.TXT, "")
		duration := time.Duration(ttl) * time.Second
		if old, exists := c.ttls[value]; !exists || duration < old {
			c.ttls[value] = duration
		}
	}
}

type ttlDatagramConn struct {
	net.Conn
	capture *txtTTLCapture
}

func (c *ttlDatagramConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.capture.observe(b[:n])
	}
	return n, err
}

type ttlPacketConn struct {
	net.Conn
	packet  net.PacketConn
	capture *txtTTLCapture
}

func (c *ttlPacketConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.capture.observe(b[:n])
	}
	return n, err
}

func (c *ttlPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.packet.ReadFrom(b)
	if n > 0 {
		c.capture.observe(b[:n])
	}
	return n, addr, err
}

func (c *ttlPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.packet.WriteTo(b, addr)
}

type ttlStreamConn struct {
	net.Conn
	capture *txtTTLCapture
	pending []byte
	mu      sync.Mutex
}

func (c *ttlStreamConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.Conn.Read(b)
	c.pending = append(c.pending, b[:n]...)
	for len(c.pending) >= 2 {
		length := int(binary.BigEndian.Uint16(c.pending))
		if len(c.pending) < length+2 {
			break
		}
		c.capture.observe(c.pending[2 : length+2])
		c.pending = c.pending[length+2:]
	}
	return n, err
}
