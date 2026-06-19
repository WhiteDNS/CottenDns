// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"bytes"
	"testing"

	"cottenpickdns-go/internal/compression"
	Enums "cottenpickdns-go/internal/enums"
	"cottenpickdns-go/internal/security"
)

// A 32-char shared key works for every method: deriveKey hashes/pads it per
// method, so one key string interoperates across the whole set.
const autoDetectKey = "0123456789abcdef0123456789abcdef"

// Every method's encoded frame must be decoded by the auto-detect codec set,
// and the detected index must map back to the method that produced it.
func TestParseInflatedFromLabelsAnyDetectsEveryMethod(t *testing.T) {
	set, err := security.NewCodecSet(security.AllMethods, autoDetectKey)
	if err != nil {
		t.Fatalf("NewCodecSet: %v", err)
	}

	payload := []byte("auto-detect-me-please")

	for setIdx, method := range security.AllMethods {
		codec, err := security.NewCodec(method, autoDetectKey)
		if err != nil {
			t.Fatalf("NewCodec(%d): %v", method, err)
		}

		labels, err := BuildEncodedAuto(BuildOptions{
			PacketType: Enums.PACKET_PING,
			Payload:    payload,
		}, codec, compression.DefaultMinSize)
		if err != nil {
			t.Fatalf("BuildEncodedAuto(method %d): %v", method, err)
		}

		// Start the trial at a deliberately wrong index to force the search to
		// locate the correct method on its own.
		start := (setIdx + 2) % len(set)
		packet, detectedIdx, err := ParseInflatedFromLabelsAny(labels, set, start)
		if err != nil {
			t.Fatalf("method %d: ParseInflatedFromLabelsAny failed: %v", method, err)
		}
		if detectedIdx != setIdx {
			t.Fatalf("method %d: detected set index %d (method %d), want %d",
				method, detectedIdx, security.AllMethods[detectedIdx], setIdx)
		}
		if packet.PacketType != Enums.PACKET_PING {
			t.Fatalf("method %d: packet type = %d, want PING", method, packet.PacketType)
		}
		if !bytes.Equal(packet.Payload, payload) {
			t.Fatalf("method %d: payload mismatch: got %q", method, packet.Payload)
		}
	}
}

func TestParseInflatedFromLabelsAnyPreferredFirstStillWorks(t *testing.T) {
	set, err := security.NewCodecSet(security.AllMethods, autoDetectKey)
	if err != nil {
		t.Fatalf("NewCodecSet: %v", err)
	}
	codec, err := security.NewCodec(3, autoDetectKey) // AES-128-GCM
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	labels, err := BuildEncodedAuto(BuildOptions{
		PacketType: Enums.PACKET_PONG,
		Payload:    []byte("x"),
	}, codec, compression.DefaultMinSize)
	if err != nil {
		t.Fatalf("BuildEncodedAuto: %v", err)
	}

	_, idx, err := ParseInflatedFromLabelsAny(labels, set, 3)
	if err != nil || idx != 3 {
		t.Fatalf("preferred-first: idx=%d err=%v, want idx=3", idx, err)
	}
}

func TestParseInflatedFromLabelsAnyEmptySet(t *testing.T) {
	if _, _, err := ParseInflatedFromLabelsAny("abc", nil, 0); err == nil {
		t.Fatal("expected error for empty codec set")
	}
}
