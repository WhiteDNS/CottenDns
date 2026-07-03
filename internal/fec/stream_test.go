// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package fec

import (
	"bytes"
	"fmt"
	"testing"
)

func TestEncoderEmitsBlockWhenFull(t *testing.T) {
	enc := NewEncoder(4, 12)
	var frames [][]byte
	for i := 0; i < 4; i++ {
		out, err := enc.AddPacket([]byte(fmt.Sprintf("pkt-%d", i)))
		if err != nil {
			t.Fatalf("AddPacket: %v", err)
		}
		if i < 3 && out != nil {
			t.Fatalf("block emitted early at packet %d", i)
		}
		if i == 3 {
			frames = out
		}
	}
	if len(frames) != 4+12 {
		t.Fatalf("expected 16 shard frames, got %d", len(frames))
	}
}

// End-to-end through the framing: encode a block, drop 75% of the shard packets,
// and the decoder must still recover every original data packet.
func TestStreamRoundTripSurvives75Loss(t *testing.T) {
	enc := NewEncoder(4, 12) // rate 1/4 -> survives 75%
	pkts := [][]byte{
		[]byte("hello-stream-0"),
		[]byte("data-1"),
		[]byte(bytes.Repeat([]byte("Z"), 40)),
		[]byte("p3"),
	}
	var frames [][]byte
	for _, p := range pkts {
		out, _ := enc.AddPacket(p)
		if out != nil {
			frames = out
		}
	}
	if frames == nil {
		t.Fatal("no block emitted")
	}

	// Keep only 4 of 16 frames (drop 75%); choose the last 4 (all parity-ish).
	dec := NewDecoder()
	var recovered [][]byte
	kept := 0
	for i := len(frames) - 1; i >= 0 && kept < 4; i-- {
		out, err := dec.AddShard(frames[i])
		if err != nil {
			t.Fatalf("AddShard: %v", err)
		}
		kept++
		if out != nil {
			recovered = out
		}
	}
	if recovered == nil {
		t.Fatal("block not recovered after receiving 25% of shards")
	}
	for i := range pkts {
		if !bytes.Equal(recovered[i], pkts[i]) {
			t.Fatalf("packet %d mismatch: got %q want %q", i, recovered[i], pkts[i])
		}
	}
}

func TestDecoderRecoversOncePerBlock(t *testing.T) {
	enc := NewEncoder(2, 2)
	var frames [][]byte
	for _, p := range [][]byte{[]byte("a"), []byte("bb")} {
		if out, _ := enc.AddPacket(p); out != nil {
			frames = out
		}
	}
	dec := NewDecoder()
	recoveries := 0
	for _, f := range frames { // feed all 4 shards
		if out, err := dec.AddShard(f); err == nil && out != nil {
			recoveries++
		}
	}
	if recoveries != 1 {
		t.Fatalf("expected exactly one recovery for the block, got %d", recoveries)
	}
}

func TestFlushEmitsShortBlock(t *testing.T) {
	enc := NewEncoder(8, 4)
	enc.AddPacket([]byte("only-one"))
	frames, err := enc.Flush()
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(frames) != 1+4 { // 1 data + 4 parity
		t.Fatalf("short block: expected 5 frames, got %d", len(frames))
	}
	dec := NewDecoder()
	var rec [][]byte
	if out, _ := dec.AddShard(frames[0]); out != nil { // single data shard suffices
		rec = out
	}
	if rec == nil || !bytes.Equal(rec[0], []byte("only-one")) {
		t.Fatalf("short block round-trip failed: %v", rec)
	}
}

func TestParseShardRejectsCorruptFrame(t *testing.T) {
	if _, err := NewDecoder().AddShard([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short shard packet")
	}
	good := FrameShard(1, 0, 2, 2, []byte("xyz"))
	good[7] = 0xFF // corrupt the declared shard size
	if _, err := NewDecoder().AddShard(good); err == nil {
		t.Fatal("expected error for inconsistent shard frame")
	}
}
