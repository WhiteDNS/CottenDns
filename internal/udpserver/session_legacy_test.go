// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"testing"
	"time"
)

func newLegacyTestStore() *sessionStore {
	return newSessionStore(8, 32, time.Minute, time.Minute, 100, 100, 0)
}

func legacyInitPayload(n int) []byte {
	p := make([]byte, sessionInitDataSize)
	p[0] = 1 // valid ResponseMode
	p[8] = byte(n >> 8)
	p[9] = byte(n)
	return p
}

// The parser tells the two header layouts apart by which half of the ID space a
// session lands in, so the allocator must keep them disjoint: a legacy client
// can never be handed an ID it cannot fit in one byte, and a native client must
// never be handed one that would decode as legacy.
func TestSessionIDSpaceSplitByWireFormat(t *testing.T) {
	store := newLegacyTestStore()

	for i := 0; i < 50; i++ {
		legacy, _, err := store.findOrCreate(legacyInitPayload(i), 0, 0, 8, true)
		if err != nil || legacy == nil {
			t.Fatalf("legacy session %d: err=%v record=%v", i, err, legacy)
		}
		if legacy.ID == 0 || legacy.ID > maxLegacySessionID {
			t.Fatalf("legacy session %d got ID %d, want 1..%d", i, legacy.ID, maxLegacySessionID)
		}
		if !legacy.LegacySessionID {
			t.Fatalf("legacy session %d not flagged legacy", i)
		}

		native, _, err := store.findOrCreate(legacyInitPayload(1000+i), 0, 0, 8, false)
		if err != nil || native == nil {
			t.Fatalf("native session %d: err=%v record=%v", i, err, native)
		}
		if native.ID <= maxLegacySessionID {
			t.Fatalf("native session %d got ID %d, want >%d", i, native.ID, maxLegacySessionID)
		}
		if native.LegacySessionID {
			t.Fatalf("native session %d wrongly flagged legacy", i)
		}
	}
}

// The reuse signature comes from the init payload, which is byte-identical in
// both wire formats. Reuse must not hand a client a session belonging to the
// other format, or it would receive a session ID it cannot express.
func TestSessionReuseDoesNotCrossWireFormats(t *testing.T) {
	store := newLegacyTestStore()

	legacy, _, err := store.findOrCreate(legacyInitPayload(7), 0, 0, 8, true)
	if err != nil || legacy == nil {
		t.Fatalf("legacy create: err=%v record=%v", err, legacy)
	}

	// Same payload, native client: must not reuse the legacy record.
	native, reused, err := store.findOrCreate(legacyInitPayload(7), 0, 0, 8, false)
	if err != nil || native == nil {
		t.Fatalf("native create: err=%v record=%v", err, native)
	}
	if reused {
		t.Fatal("native client reused a legacy session record")
	}
	if native.ID == legacy.ID {
		t.Fatalf("native and legacy sessions share ID %d", native.ID)
	}
	if native.LegacySessionID {
		t.Fatal("native session inherited the legacy wire format")
	}
}

// Legacy capacity is inherently capped at 255 by the one-byte field. Exhausting
// it must be refused cleanly rather than spilling into the native range.
func TestLegacySessionExhaustionDoesNotSpillIntoNativeRange(t *testing.T) {
	store := newLegacyTestStore()

	for i := 0; i < maxLegacySessionID; i++ {
		record, _, err := store.findOrCreate(legacyInitPayload(i), 0, 0, 8, true)
		if err != nil || record == nil {
			t.Fatalf("legacy session %d should fit: err=%v", i, err)
		}
		if record.ID > maxLegacySessionID {
			t.Fatalf("legacy session %d spilled to ID %d", i, record.ID)
		}
	}

	_, _, err := store.findOrCreate(legacyInitPayload(9999), 0, 0, 8, true)
	if err != ErrSessionTableFull {
		t.Fatalf("expected ErrSessionTableFull once legacy range is full, got %v", err)
	}

	// The native range must still be usable while legacy is exhausted.
	native, _, err := store.findOrCreate(legacyInitPayload(20000), 0, 0, 8, false)
	if err != nil || native == nil {
		t.Fatalf("native session should still allocate: err=%v", err)
	}
	if native.ID <= maxLegacySessionID {
		t.Fatalf("native session got legacy-range ID %d", native.ID)
	}
}
