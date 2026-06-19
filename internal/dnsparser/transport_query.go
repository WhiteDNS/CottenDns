// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================
// query.go — construction of outbound DNS (tunnel) question packets and the
// helpers for encoding tunnel payload into the QNAME. Split out of transport.go.
// ==============================================================================

package dnsparser

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
	"sync"
	"sync/atomic"

	Enums "cottenpickdns-go/internal/enums"
)

func BuildTXTQuestionPacket(name string, qType uint16, ednsUDPSize uint16) ([]byte, error) {
	qname, err := encodeDNSNameStrict(name)
	if err != nil {
		return nil, err
	}

	requestID := nextDNSRequestID()

	arCount := uint16(0)
	optLen := 0
	if ednsUDPSize > 0 {
		arCount = 1
		optLen = 11
	}

	packet := make([]byte, dnsHeaderSize+len(qname)+4+optLen)
	binary.BigEndian.PutUint16(packet[0:2], requestID)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[10:12], arCount)

	offset := dnsHeaderSize
	offset += copy(packet[offset:], qname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qType)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	offset += 4

	if ednsUDPSize > 0 {
		packet[offset] = 0x00
		offset++
		binary.BigEndian.PutUint16(packet[offset:offset+2], Enums.DNS_RECORD_TYPE_OPT)
		offset += 2
		binary.BigEndian.PutUint16(packet[offset:offset+2], ednsUDPSize)
		offset += 2
		offset += 4
		binary.BigEndian.PutUint16(packet[offset:offset+2], 0)
	}

	return packet, nil
}

func BuildTunnelTXTQuestionPacket(domain string, encodedFrame []byte, qType uint16, ednsUDPSize uint16) ([]byte, error) {
	normalizedDomain, domainQname, err := PrepareTunnelDomainQname(domain)
	if err != nil {
		return nil, err
	}

	return BuildTunnelTXTQuestionPacketPrepared(normalizedDomain, domainQname, encodedFrame, qType, ednsUDPSize)
}

func BuildTunnelTXTQuestionPacketPrepared(normalizedDomain string, domainQname []byte, encodedFrame []byte, qType uint16, ednsUDPSize uint16) ([]byte, error) {
	if normalizedDomain == "" || len(domainQname) == 0 {
		return nil, ErrInvalidName
	}
	if len(encodedFrame) == 0 {
		return buildTXTQuestionPacketPrepared(domainQname, qType, ednsUDPSize), nil
	}
	if encodedQNameLen(len(encodedFrame), len(normalizedDomain)) > maxDNSNameLen {
		return nil, ErrInvalidName
	}

	labelCount := (len(encodedFrame) + maxDNSLabelLen - 1) / maxDNSLabelLen
	qnameLen := len(encodedFrame) + labelCount + len(domainQname)

	arCount := uint16(0)
	optLen := 0
	if ednsUDPSize > 0 {
		arCount = 1
		optLen = 11
	}

	packet := make([]byte, dnsHeaderSize+qnameLen+4+optLen)
	binary.BigEndian.PutUint16(packet[0:2], nextDNSRequestID())
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[10:12], arCount)

	offset := dnsHeaderSize
	for start := 0; start < len(encodedFrame); start += maxDNSLabelLen {
		end := start + maxDNSLabelLen
		if end > len(encodedFrame) {
			end = len(encodedFrame)
		}
		packet[offset] = byte(end - start)
		offset++
		offset += copy(packet[offset:], encodedFrame[start:end])
	}
	offset += copy(packet[offset:], domainQname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qType)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	offset += 4

	if ednsUDPSize > 0 {
		packet[offset] = 0x00
		offset++
		binary.BigEndian.PutUint16(packet[offset:offset+2], Enums.DNS_RECORD_TYPE_OPT)
		offset += 2
		binary.BigEndian.PutUint16(packet[offset:offset+2], ednsUDPSize)
		offset += 2
		offset += 4
		binary.BigEndian.PutUint16(packet[offset:offset+2], 0)
	}

	return packet, nil
}

func PrepareTunnelDomainQname(domain string) (string, []byte, error) {
	normalizedDomain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if normalizedDomain == "" {
		return "", nil, ErrInvalidName
	}

	domainQname, err := encodeDNSNameStrict(normalizedDomain)
	if err != nil {
		return "", nil, err
	}
	return normalizedDomain, domainQname, nil
}

func buildTXTQuestionPacketPrepared(qname []byte, qType uint16, ednsUDPSize uint16) []byte {
	requestID := nextDNSRequestID()

	arCount := uint16(0)
	optLen := 0
	if ednsUDPSize > 0 {
		arCount = 1
		optLen = 11
	}

	packet := make([]byte, dnsHeaderSize+len(qname)+4+optLen)
	binary.BigEndian.PutUint16(packet[0:2], requestID)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[10:12], arCount)

	offset := dnsHeaderSize
	offset += copy(packet[offset:], qname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qType)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	offset += 4

	if ednsUDPSize > 0 {
		packet[offset] = 0x00
		offset++
		binary.BigEndian.PutUint16(packet[offset:offset+2], Enums.DNS_RECORD_TYPE_OPT)
		offset += 2
		binary.BigEndian.PutUint16(packet[offset:offset+2], ednsUDPSize)
		offset += 2
		offset += 4
		binary.BigEndian.PutUint16(packet[offset:offset+2], 0)
	}

	return packet
}

func CalculateMaxEncodedQNameChars(domain string) int {
	domainLen := len(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domainLen <= 0 {
		return maxDNSNameLen
	}

	low := 0
	high := maxDNSNameLen
	best := 0
	for low <= high {
		mid := (low + high) / 2
		if encodedQNameLen(mid, domainLen) <= maxDNSNameLen {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return best
}

func EncodeDataToLabels(data string) string {
	if len(data) <= maxDNSLabelLen {
		return data
	}

	var b strings.Builder
	b.Grow(len(data) + len(data)/maxDNSLabelLen)
	for start := 0; start < len(data); start += maxDNSLabelLen {
		if start > 0 {
			b.WriteByte('.')
		}
		end := start + maxDNSLabelLen
		if end > len(data) {
			end = len(data)
		}
		b.WriteString(data[start:end])
	}
	return b.String()
}

func BuildTunnelQuestionName(domain string, encodedFrame string) (string, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return "", ErrInvalidName
	}
	if encodedFrame == "" {
		return domain, nil
	}

	name := EncodeDataToLabels(encodedFrame) + "." + domain
	if len(name) > maxDNSNameLen {
		return "", ErrInvalidName
	}
	return name, nil
}

func encodedQNameLen(encodedChars int, domainLen int) int {
	if encodedChars <= 0 {
		return domainLen
	}
	labelSplits := (encodedChars - 1) / maxDNSLabelLen
	return encodedChars + labelSplits + 1 + domainLen
}

var dnsIDCounter atomic.Uint32
var dnsIDInit sync.Once

func nextDNSRequestID() uint16 {
	dnsIDInit.Do(func() {
		var seed [4]byte
		if _, err := rand.Read(seed[:]); err == nil {
			dnsIDCounter.Store(uint32(binary.BigEndian.Uint32(seed[:])))
		}
	})
	return uint16(dnsIDCounter.Add(1))
}
