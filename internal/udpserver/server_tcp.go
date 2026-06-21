// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================
// server_tcp.go — DNS-over-TCP listener on the same host:port as the UDP
// listener. Many restrictive networks filter or truncate UDP/53 but still allow
// TCP/53; serving both lets clients fall back to TCP without any change to the
// tunnel framing. Each TCP message is a standard RFC 1035 §4.2.2 length-prefixed
// DNS message (2-byte big-endian length, then the message). Responses use the
// same framing. The handler is the exact same transport-agnostic
// safeHandlePacket used by the UDP path, so all tunnel logic is shared.
// ==============================================================================

package udpserver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tcpReadIdleTimeout  = 30 * time.Second
	tcpWriteTimeout     = 15 * time.Second
	tcpMaxMessageLength = 65535
)

// serveTCP runs the DNS-over-TCP listener until ctx is cancelled. It mirrors the
// UDP listener but is connection-oriented: each accepted connection is serviced
// by its own goroutine that reads length-prefixed queries and writes
// length-prefixed responses. Returns when the listener is closed.
func (s *Server) serveTCP(ctx context.Context, host string, port int) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(host, itoaPort(port)))
	if err != nil {
		return err
	}

	maxConns := s.cfg.TCPMaxConns
	if maxConns <= 0 {
		maxConns = 2048
	}

	s.log.Infof(
		"\U0001F4E1 <green>TCP Listener Ready, Addr: <cyan>%s</cyan>, MaxConns: <cyan>%d</cyan></green>",
		ln.Addr().String(),
		maxConns,
	)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var (
		conns  sync.WaitGroup
		active atomic.Int64
	)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}

		// Shed load instead of unbounded growth under a connection flood.
		if active.Load() >= int64(maxConns) {
			_ = conn.Close()
			continue
		}
		active.Add(1)
		conns.Add(1)
		go func(c net.Conn) {
			defer conns.Done()
			defer active.Add(-1)
			s.handleTCPConn(ctx, c)
		}(conn)
	}

	conns.Wait()
	return nil
}

// handleTCPConn services one TCP connection using the server's packet handler.
func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	serveTCPDNSMessages(ctx, conn, s.safeHandlePacket)
}

// serveTCPDNSMessages reads a sequence of RFC 1035 §4.2.2 length-prefixed DNS
// messages from conn, runs each through handler, and writes the length-prefixed
// response. It tolerates pipelined queries and returns on idle, error, or
// context cancellation. Split out from handleTCPConn so the framing can be
// unit-tested with any net.Conn and handler.
func serveTCPDNSMessages(ctx context.Context, conn net.Conn, handler func([]byte) []byte) {
	lenBuf := make([]byte, 2)
	for {
		if ctx != nil && ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(tcpReadIdleTimeout))

		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return // EOF, idle timeout, or peer closed.
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf))
		if msgLen == 0 || msgLen > tcpMaxMessageLength {
			return
		}

		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}

		response := handler(msg)
		if len(response) == 0 {
			// No tunnel response for this query; keep the connection open for
			// the next pipelined message rather than dropping it.
			continue
		}
		if len(response) > tcpMaxMessageLength {
			response = response[:tcpMaxMessageLength]
		}

		out := make([]byte, 2+len(response))
		binary.BigEndian.PutUint16(out[:2], uint16(len(response)))
		copy(out[2:], response)

		_ = conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

func itoaPort(port int) string {
	// Small, allocation-light int-to-string for a port number.
	if port <= 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for port > 0 {
		i--
		b[i] = byte('0' + port%10)
		port /= 10
	}
	return string(b[i:])
}
