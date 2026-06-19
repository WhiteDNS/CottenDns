// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the CottenpickDNS client.
// This file (tunnel_query.go) handles the construction of DNS tunnel queries.
// ==============================================================================
package client

import (
	DnsParser "cottenpickdns-go/internal/dnsparser"
	Enums "cottenpickdns-go/internal/enums"
	VpnProto "cottenpickdns-go/internal/vpnproto"
)

type preparedTunnelDomain struct {
	normalized string
	qname      []byte
}

// normalizeRuntimeQueryTypes is a defensive guard for the runtime query-type
// set: config finalization already guarantees a non-empty slice, but a Client
// constructed in a test without going through config validation might pass nil.
// In that case fall back to TXT-only (the historical behavior).
func normalizeRuntimeQueryTypes(codes []uint16) []uint16 {
	if len(codes) == 0 {
		return []uint16{Enums.DNS_RECORD_TYPE_TXT}
	}
	out := make([]uint16, len(codes))
	copy(out, codes)
	return out
}

// nextQueryType returns the DNS record type to use for the next tunnel query,
// rotating round-robin over the configured set (A1). The upstream server reads
// the tunnel payload from the QNAME labels regardless of qType, so rotation is
// purely a query-fingerprint measure and never affects decodability. A
// single-element set always returns that one type (e.g. the default TXT-only).
func (c *Client) nextQueryType() uint16 {
	if c == nil || len(c.queryTypes) == 0 {
		return Enums.DNS_RECORD_TYPE_TXT
	}
	if len(c.queryTypes) == 1 {
		return c.queryTypes[0]
	}
	idx := c.queryTypeCursor.Add(1) - 1
	return c.queryTypes[int(idx%uint32(len(c.queryTypes)))]
}

func buildTunnelTXTQuestionBytes(domain string, encoded []byte, qType uint16) ([]byte, error) {
	return DnsParser.BuildTunnelTXTQuestionPacket(domain, encoded, qType, EDnsSafeUDPSize)
}

func prepareTunnelDomain(domain string) (preparedTunnelDomain, error) {
	normalized, qname, err := DnsParser.PrepareTunnelDomainQname(domain)
	if err != nil {
		return preparedTunnelDomain{}, err
	}
	return preparedTunnelDomain{normalized: normalized, qname: qname}, nil
}

func buildTunnelTXTQuestionBytesPrepared(domain preparedTunnelDomain, encoded []byte, qType uint16) ([]byte, error) {
	return DnsParser.BuildTunnelTXTQuestionPacketPrepared(domain.normalized, domain.qname, encoded, qType, EDnsSafeUDPSize)
}

// buildTunnelTXTQueryRaw builds an encoded tunnel query using the provided options and codec.
func (c *Client) buildTunnelTXTQueryRaw(domain string, options VpnProto.BuildOptions) ([]byte, error) {
	raw, err := VpnProto.BuildRaw(options)
	if err != nil {
		return nil, err
	}
	encoded, err := c.codec.EncryptAndEncodeBytes(raw)
	if err != nil {
		return nil, err
	}
	return buildTunnelTXTQuestionBytes(domain, encoded, c.nextQueryType())
}

func (c *Client) buildEncodedAutoWithCompressionTrace(options VpnProto.BuildOptions) ([]byte, error) {
	raw, err := VpnProto.BuildRawAuto(options, c.cfg.CompressionMinSize)
	if err != nil {
		return nil, err
	}

	if c.codec == nil {
		return nil, VpnProto.ErrCodecUnavailable
	}
	return c.codec.EncryptAndEncodeBytes(raw)
}

// buildTunnelTXTQuery builds an encoded tunnel query with automatic option handling.
func (c *Client) buildTunnelTXTQuery(domain string, options VpnProto.BuildOptions) ([]byte, error) {
	encoded, err := c.buildEncodedAutoWithCompressionTrace(options)
	if err != nil {
		return nil, err
	}
	return buildTunnelTXTQuestionBytes(domain, encoded, c.nextQueryType())
}
