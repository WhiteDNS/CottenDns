// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================
// stream_fec_test.go — locks the live server-side FEC contract: data packets
// fed through Stream_server.feedFECData / flushFEC / popFECShard must be
// recoverable by a fec.Decoder + UnpackFECDataUnit on the client side, even
// when a fraction of the framed shards are dropped in flight. This guards the
// exact framing used by the dequeue path, independently of the codec's own
// tests.
// ==============================================================================

package udpserver

import (
	"fmt"
	"testing"

	"cottenpickdns-go/internal/fec"
	VpnProto "cottenpickdns-go/internal/vpnproto"
)

func TestStreamServerFECRoundTripWithLoss(t *testing.T) {
	// block=4 data + parity=4 recovery -> any 4 of 8 shards reconstruct a block,
	// i.e. each block survives up to 50% shard loss.
	const (
		blockSize = 4
		parity    = 4
		numUnits  = 10 // intentionally not a multiple of blockSize (tail flush)
		dropEvery = 2  // drop every 2nd shard -> 50% loss
	)

	s := &Stream_server{ID: 7, SessionID: 1}
	s.EnableFEC(blockSize, parity)

	type unit struct {
		seq     uint16
		payload []byte
	}
	want := make([]unit, numUnits)
	for i := range want {
		want[i] = unit{
			seq:     uint16(100 + i),
			payload: []byte(fmt.Sprintf("data-unit-%d-payload", i)),
		}
		s.feedFECData(want[i].seq, 0, want[i].payload)
	}
	// Flush the trailing partial block so the last units are emitted.
	s.flushFEC()

	// Drain every framed shard the stream produced, dropping half of them.
	var delivered [][]byte
	idx := 0
	for {
		frame, ok := s.popFECShard()
		if !ok {
			break
		}
		if idx%dropEvery != 0 {
			delivered = append(delivered, frame)
		}
		idx++
	}
	if idx == 0 {
		t.Fatal("stream produced no FEC shards")
	}

	// Client side: decode surviving shards and replay recovered units.
	dec := fec.NewDecoder()
	got := make(map[uint16][]byte)
	for _, frame := range delivered {
		units, err := dec.AddShard(frame)
		if err != nil {
			t.Fatalf("AddShard: %v", err)
		}
		for _, u := range units {
			seq, _, payload, ok := VpnProto.UnpackFECDataUnit(u)
			if !ok {
				t.Fatalf("UnpackFECDataUnit failed for recovered unit")
			}
			got[seq] = append([]byte(nil), payload...)
		}
	}

	for _, w := range want {
		p, ok := got[w.seq]
		if !ok {
			t.Fatalf("unit seq=%d not recovered after 50%% shard loss", w.seq)
		}
		if string(p) != string(w.payload) {
			t.Fatalf("unit seq=%d payload mismatch: got %q want %q", w.seq, p, w.payload)
		}
	}
}
