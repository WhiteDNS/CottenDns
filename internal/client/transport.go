// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================
// transport.go — resolver query transport abstraction. The synchronous query
// paths (MTU probing, session init, health rechecks) talk to a resolver through
// a queryExchanger so they work identically over UDP or DNS-over-TCP/53. The
// active transport is chosen client-wide: RESOLVER_TRANSPORT = udp | tcp | auto,
// where "auto" tries UDP first and falls back to TCP when a full UDP MTU scan
// finds zero usable resolvers (see RunInitialMTUTests). The high-throughput data
// plane has its own persistent TCP path (tcp_data.go).
// ==============================================================================

package client

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

const tcpQueryDialTimeout = 4 * time.Second

// queryExchanger is a synchronous DNS request/response transport to one resolver.
type queryExchanger interface {
	exchange(packet []byte, timeout time.Duration) ([]byte, error)
	Close() error
}

// newQueryTransport opens a synchronous query transport to resolverLabel using
// the client's active transport (UDP, or TCP when useTCP is set).
func (c *Client) newQueryTransport(resolverLabel string) (queryExchanger, error) {
	if c.useTCP.Load() {
		return newTCPQueryTransport(resolverLabel, tcpQueryDialTimeout)
	}
	conn, err := dialUDPResolver(resolverLabel)
	if err != nil {
		return nil, err
	}
	return &udpQueryTransport{client: c, conn: conn}, nil
}

// tcpQueryTransport wraps a single persistent TCP connection to a resolver and
// exchanges RFC 1035 §4.2.2 length-prefixed DNS messages. The connection is
// reused across the many queries a probe sends, so there is no per-query
// handshake cost.
type tcpQueryTransport struct {
	conn net.Conn
}

func newTCPQueryTransport(resolverLabel string, dialTimeout time.Duration) (*tcpQueryTransport, error) {
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.Dial("tcp", resolverLabel)
	if err != nil {
		return nil, err
	}
	return &tcpQueryTransport{conn: conn}, nil
}

func (t *tcpQueryTransport) exchange(packet []byte, timeout time.Duration) ([]byte, error) {
	if t == nil || t.conn == nil {
		return nil, net.ErrClosed
	}
	if len(packet) < 2 {
		return nil, errors.New("malformed dns query")
	}
	expectedID := binary.BigEndian.Uint16(packet[:2])

	deadline := time.Now().Add(timeout)
	_ = t.conn.SetDeadline(deadline)

	if err := writeTCPDNSFramed(t.conn, packet); err != nil {
		return nil, err
	}

	// TCP is ordered, but tolerate a stray non-matching message defensively.
	for attempts := 0; attempts < 8; attempts++ {
		resp, err := readTCPDNSFramed(t.conn)
		if err != nil {
			return nil, err
		}
		if len(resp) >= 2 && binary.BigEndian.Uint16(resp[:2]) == expectedID {
			return resp, nil
		}
	}
	return nil, errors.New("too many mismatched dns responses over tcp")
}

func (t *tcpQueryTransport) Close() error {
	if t == nil || t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

// writeTCPDNSFramed writes a 2-byte length prefix followed by the DNS message.
func writeTCPDNSFramed(conn net.Conn, msg []byte) error {
	if len(msg) > 0xFFFF {
		return errors.New("dns message too large for tcp framing")
	}
	framed := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(msg)))
	copy(framed[2:], msg)
	_, err := conn.Write(framed)
	return err
}

// readTCPDNSFramed reads one length-prefixed DNS message.
func readTCPDNSFramed(conn net.Conn) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n < 2 {
		return nil, errors.New("short tcp dns message")
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
