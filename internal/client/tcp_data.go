// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================
// tcp_data.go — high-throughput data-plane transport over DNS-over-TCP/53, used
// when the client runs in TCP mode (RESOLVER_TRANSPORT=tcp, or the auto fallback
// after a UDP scan finds zero resolvers). It keeps one persistent TCP connection
// per resolver, writes length-prefixed queries, and runs a read loop per
// connection that pushes responses into the SAME rxChannel the UDP reader feeds —
// so handleInboundPacket processes TCP and UDP responses identically. Broken
// connections are re-dialed lazily on the next send.
// ==============================================================================

package client

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

const (
	tcpDataDialTimeout  = 4 * time.Second
	tcpDataWriteTimeout = 10 * time.Second
)

type tcpDataManager struct {
	client *Client
	ctx    context.Context

	mu    sync.Mutex
	conns map[string]*tcpDataConn // keyed by resolver address string
	dead  bool
}

type tcpDataConn struct {
	manager      *tcpDataManager
	key          string // resolver address string (map key)
	resolverAddr *net.UDPAddr
	localAddr    string

	writeMu sync.Mutex
	conn    net.Conn
}

func newTCPDataManager(c *Client) *tcpDataManager {
	return &tcpDataManager{client: c, conns: make(map[string]*tcpDataConn)}
}

func (m *tcpDataManager) Start(ctx context.Context) {
	m.mu.Lock()
	m.ctx = ctx
	m.dead = false
	m.mu.Unlock()
}

// Stop closes every connection and prevents new ones.
func (m *tcpDataManager) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.dead = true
	conns := m.conns
	m.conns = make(map[string]*tcpDataConn)
	m.mu.Unlock()
	for _, dc := range conns {
		dc.close()
	}
}

// Send transmits one already-built DNS query to the resolver over its persistent
// TCP connection, dialing lazily and re-dialing on failure. On success it mirrors
// the UDP writer's bookkeeping (resolver send tracking + tx byte counter).
func (m *tcpDataManager) Send(serverKey string, addr *net.UDPAddr, packet []byte, now time.Time) {
	if m == nil || addr == nil || len(packet) == 0 {
		return
	}
	dc, err := m.connFor(addr)
	if err != nil || dc == nil {
		return
	}

	dc.writeMu.Lock()
	_ = dc.conn.SetWriteDeadline(time.Now().Add(tcpDataWriteTimeout))
	werr := writeTCPDNSFramed(dc.conn, packet)
	dc.writeMu.Unlock()

	if werr != nil {
		dc.close()
		m.remove(dc)
		return
	}

	m.client.trackResolverSend(packet, addr.String(), dc.localAddr, serverKey, now)
	m.client.txTotalBytes.Add(uint64(len(packet)))
}

// connFor returns the existing connection for a resolver or dials a new one and
// starts its read loop.
func (m *tcpDataManager) connFor(addr *net.UDPAddr) (*tcpDataConn, error) {
	key := addr.String()

	m.mu.Lock()
	if m.dead {
		m.mu.Unlock()
		return nil, net.ErrClosed
	}
	if dc, ok := m.conns[key]; ok {
		m.mu.Unlock()
		return dc, nil
	}
	m.mu.Unlock()

	// Dial outside the lock (network I/O); resolve UDP resolver addr to TCP.
	d := net.Dialer{Timeout: tcpDataDialTimeout}
	tcpAddr := net.JoinHostPort(addr.IP.String(), itoaInt(addr.Port))
	conn, err := d.Dial("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}

	dc := &tcpDataConn{
		manager:      m,
		key:          key,
		resolverAddr: addr,
		conn:         conn,
	}
	if la := conn.LocalAddr(); la != nil {
		dc.localAddr = la.String()
	}

	m.mu.Lock()
	if m.dead {
		m.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	// Lost a race with another sender — use the winner, drop ours.
	if existing, ok := m.conns[key]; ok {
		m.mu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	m.conns[key] = dc
	ctx := m.ctx
	m.mu.Unlock()

	go dc.readLoop(ctx)
	return dc, nil
}

func (m *tcpDataManager) remove(dc *tcpDataConn) {
	if dc == nil {
		return
	}
	m.mu.Lock()
	if cur, ok := m.conns[dc.key]; ok && cur == dc {
		delete(m.conns, dc.key)
	}
	m.mu.Unlock()
}

func (dc *tcpDataConn) close() {
	if dc == nil || dc.conn == nil {
		return
	}
	_ = dc.conn.Close()
}

// readLoop reads length-prefixed DNS responses and feeds them into the client's
// rxChannel using pooled buffers, exactly like the UDP reader, so the existing
// processor/handleInboundPacket path handles them unchanged.
func (dc *tcpDataConn) readLoop(ctx context.Context) {
	defer func() {
		dc.close()
		dc.manager.remove(dc)
	}()

	var lenBuf [2]byte
	for {
		if ctx != nil && ctx.Err() != nil {
			return
		}
		if _, err := io.ReadFull(dc.conn, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		if n < 12 || n > RuntimeUDPReadBufferSize {
			return
		}

		buf := dc.manager.client.getRuntimeUDPBuffer()
		if _, err := io.ReadFull(dc.conn, buf[:n]); err != nil {
			dc.manager.client.putRuntimeUDPBuffer(buf)
			return
		}

		// Only DNS responses (QR=1) are of interest, mirroring the UDP reader.
		if (buf[2] & 0x80) == 0 {
			dc.manager.client.putRuntimeUDPBuffer(buf)
			continue
		}

		c := dc.manager.client
		c.rxTotalBytes.Add(uint64(n))
		select {
		case c.rxChannel <- asyncReadPacket{data: buf[:n], addr: dc.resolverAddr, localAddr: dc.localAddr}:
		default:
			c.putRuntimeUDPBuffer(buf)
			c.onRXDrop(dc.resolverAddr)
		}
	}
}

// itoaInt is a small allocation-light int-to-string for a port number.
func itoaInt(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [11]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
