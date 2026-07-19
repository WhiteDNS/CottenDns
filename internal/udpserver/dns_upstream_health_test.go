package udpserver

import (
	"encoding/binary"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOrderedDNSUpstreamsDeprioritizesRepeatedFailures(t *testing.T) {
	s := &Server{
		dnsUpstreamServers: []string{"slow", "healthy"},
		dnsUpstreamHealth:  make(map[string]*dnsUpstreamHealthState),
	}
	s.recordDNSUpstreamResult("slow", time.Second, false)
	s.recordDNSUpstreamResult("slow", time.Second, false)
	s.recordDNSUpstreamResult("healthy", 20*time.Millisecond, true)

	ordered := s.orderedDNSUpstreams(time.Now())
	if len(ordered) != 2 || ordered[0] != "healthy" {
		t.Fatalf("expected healthy upstream first, got %v", ordered)
	}
}

func TestQueryOneUpstreamRetriesTruncatedUDPOverTCP(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	port := tcpListener.Addr().(*net.TCPAddr).Port
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	want := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}
	go func() {
		buffer := make([]byte, 512)
		n, addr, readErr := udpConn.ReadFromUDP(buffer)
		if readErr == nil {
			truncated := append([]byte(nil), buffer[:n]...)
			truncated[2] |= 0x02
			_, _ = udpConn.WriteToUDP(truncated, addr)
		}
	}()
	go func() {
		conn, acceptErr := tcpListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var size [2]byte
		if _, readErr := io.ReadFull(conn, size[:]); readErr != nil {
			return
		}
		request := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, readErr := io.ReadFull(conn, request); readErr != nil {
			return
		}
		frame := make([]byte, 2+len(want))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(want)))
		copy(frame[2:], want)
		_, _ = conn.Write(frame)
	}()

	s := &Server{dnsUpstreamBufferPool: sync.Pool{New: func() any { return make([]byte, 65535) }}}
	got, err := s.queryOneUpstream(tcpListener.Addr().String(), query, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) || s.dnsUpstreamTCPFallbacks.Load() != 1 {
		t.Fatalf("unexpected fallback response=%x fallbacks=%d", got, s.dnsUpstreamTCPFallbacks.Load())
	}
}

func TestMetricsHandlerExposesHealthAndCounters(t *testing.T) {
	s := &Server{sessions: &sessionStore{}}
	s.dnsUpstreamQueries.Store(7)

	health := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(health, httptest.NewRequest("GET", "/healthz", nil))
	if health.Code != 200 || health.Body.String() != "ok\n" {
		t.Fatalf("unexpected health response: %d %q", health.Code, health.Body.String())
	}

	metrics := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(metrics, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "cottendns_dns_upstream_queries_total 7") {
		t.Fatalf("missing upstream counter: %s", metrics.Body.String())
	}
}
