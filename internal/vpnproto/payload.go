// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"errors"

	"cottenpickdns-go/internal/compression"
	"cottenpickdns-go/internal/security"
)

var ErrInvalidCompressedPayload = errors.New("invalid compressed vpn payload")

func PreparePayload(packetType uint8, payload []byte, requestedCompression uint8, minSize int) ([]byte, uint8) {
	requestedCompression = compression.NormalizeAvailableType(requestedCompression)
	if requestedCompression == compression.TypeOff {
		return payload, compression.TypeOff
	}

	if !hasCompressionExtension(packetType) {
		return payload, compression.TypeOff
	}
	if len(payload) == 0 {
		return payload, compression.TypeOff
	}
	return compression.CompressPayload(payload, requestedCompression, minSize)
}

func InflatePayload(packet Packet) (Packet, error) {
	if !packet.HasCompressionType || packet.CompressionType == compression.TypeOff {
		return packet, nil
	}

	payload, ok := compression.TryDecompressPayload(packet.Payload, packet.CompressionType)
	if !ok {
		return Packet{}, ErrInvalidCompressedPayload
	}
	packet.Payload = payload
	return packet, nil
}

func ParseInflatedFromLabels(labels string, codec *security.Codec) (Packet, error) {
	packet, err := ParseFromLabels(labels, codec)
	if err != nil {
		return Packet{}, err
	}

	return InflatePayload(packet)
}

// ParseInflatedFromLabelsAny decodes the upstream tunnel labels by trying each
// codec, beginning at startIdx and wrapping through the rest, and returns the
// first valid packet together with the index of the codec that succeeded. This
// supports server-side encryption-method auto-detection: the frame is fully
// encrypted, so the method is discovered by trial, with frame-structure
// validation in Parse as the success signal. Callers should pass the
// last-successful index as startIdx so the steady state costs one attempt.
//
// Authenticated (AES-GCM) methods fail cleanly on a wrong key/method; for
// unauthenticated methods (None/XOR/ChaCha20) the header validation in Parse is
// what rejects a wrong-method guess.
func ParseInflatedFromLabelsAny(labels string, codecs []*security.Codec, startIdx int) (Packet, int, error) {
	n := len(codecs)
	if n == 0 {
		return Packet{}, -1, ErrCodecUnavailable
	}
	if startIdx < 0 || startIdx >= n {
		startIdx = 0
	}

	var lastErr error
	for offset := 0; offset < n; offset++ {
		idx := (startIdx + offset) % n
		if codecs[idx] == nil {
			continue
		}
		packet, err := ParseInflatedFromLabels(labels, codecs[idx])
		if err == nil {
			return packet, idx, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ErrCodecUnavailable
	}
	return Packet{}, -1, lastErr
}

func ParseInflated(data []byte) (Packet, error) {
	packet, err := Parse(data)
	if err != nil {
		return Packet{}, err
	}

	return InflatePayload(packet)
}

func BuildRawAuto(opts BuildOptions, minSize int) ([]byte, error) {
	payload, compressionType := PreparePayload(opts.PacketType, opts.Payload, opts.CompressionType, minSize)
	opts.Payload = payload
	opts.CompressionType = compressionType
	return BuildRaw(opts)
}

func BuildEncodedAuto(opts BuildOptions, codec *security.Codec, minSize int) (string, error) {
	raw, err := BuildRawAuto(opts, minSize)
	if err != nil {
		return "", err
	}
	if codec == nil {
		return "", ErrCodecUnavailable
	}
	return codec.EncryptAndEncode(raw)
}
