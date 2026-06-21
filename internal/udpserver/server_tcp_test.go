// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// writeTCPDNSMessage frames and writes one length-prefixed DNS message.
func writeTCPDNSMessage(conn net.Conn, msg []byte) error {
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msg)))
	copy(buf[2:], msg)
	_, err := conn.Write(buf)
	return err
}

// readTCPDNSMessage reads one length-prefixed DNS message.
func readTCPDNSMessage(conn net.Conn) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func TestServeTCPDNSMessages_FramingRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	// Handler echoes the query back with a one-byte tag, proving the framing
	// carries the exact message both ways and supports pipelining.
	handler := func(q []byte) []byte {
		return append(append([]byte{}, q...), 0xAA)
	}
	go func() {
		serveTCPDNSMessages(context.Background(), server, handler)
		server.Close()
	}()

	for i := 0; i < 3; i++ {
		query := []byte{byte(i), 0x01, 0x02, 0x03}
		if err := writeTCPDNSMessage(client, query); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		resp, err := readTCPDNSMessage(client)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if len(resp) != len(query)+1 || resp[len(resp)-1] != 0xAA {
			t.Fatalf("response %d malformed: %v", i, resp)
		}
		for j := range query {
			if resp[j] != query[j] {
				t.Fatalf("response %d payload mismatch at %d", i, j)
			}
		}
	}
}

func TestServeTCPDNSMessages_EmptyResponseKeepsConnOpen(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	calls := 0
	handler := func(q []byte) []byte {
		calls++
		if calls == 1 {
			return nil // no tunnel response -> connection must stay open
		}
		return []byte{0x99}
	}
	go func() {
		serveTCPDNSMessages(context.Background(), server, handler)
		server.Close()
	}()

	_ = writeTCPDNSMessage(client, []byte{0x01})
	_ = writeTCPDNSMessage(client, []byte{0x02})
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := readTCPDNSMessage(client)
	if err != nil {
		t.Fatalf("expected a response after an empty one: %v", err)
	}
	if len(resp) != 1 || resp[0] != 0x99 {
		t.Fatalf("unexpected response: %v", resp)
	}
}

func TestItoaPort(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want string
	}{{53, "53"}, {443, "443"}, {65535, "65535"}, {0, "0"}, {-1, "0"}} {
		if got := itoaPort(tc.in); got != tc.want {
			t.Errorf("itoaPort(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
