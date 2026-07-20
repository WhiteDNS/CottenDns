// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// server_policy.go — client-side application of the ceilings a server states in
// SESSION_ACCEPT.
//
// The server cannot make a client behave, but it can say what it will tolerate,
// and a cooperating client clamps itself. This matters on a shared public
// server, where one client configured with a huge ARQ window or a very
// aggressive ping interval otherwise takes a disproportionate share.
//
// Why an atomic rather than rewriting c.cfg: the config value is read from
// several goroutines (stream setup builds an ARQ per stream, the send path
// reads the compression threshold, the ping manager reads its interval).
// Mutating it when SESSION_ACCEPT lands -- which happens on the init collector
// goroutine while those readers are already running -- would be a data race.
// Instead the policy is published once through an atomic pointer and the
// governed values are clamped where they are read, so no existing reader
// changes its synchronization.
//
// A server that configures no ceilings sends no policy block, the pointer stays
// nil, and every accessor returns the configured value untouched.
// ==============================================================================

package client

import (
	"time"

	VpnProto "cottendns-go/internal/vpnproto"
)

// applyServerClientPolicy publishes any policy carried by a SESSION_ACCEPT
// payload. Absent or truncated blocks are simply "no ceilings stated"; they are
// not an error, because a policy-less server is the normal case.
func (c *Client) applyServerClientPolicy(payload []byte) {
	// The client always speaks the native two-byte session-ID format, so the
	// policy block sits after the native-width base payload.
	policy, ok := VpnProto.DecodeSessionAcceptPolicy(payload, false)
	if !ok {
		return
	}

	c.serverPolicy.Store(&policy)

	if c.log != nil {
		c.log.Debugf(
			"\U0001F4CB <blue>Server Client Policy Applied</blue> <magenta>|</magenta> <blue>ARQ Window Max</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Batch Max</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Ping Interval Min</blue>: <cyan>%.3fs</cyan>",
			policy.MaxARQWindowSize,
			policy.MaxPacketsPerBatch,
			policy.MinPingAggressiveInterval,
		)
	}
}

// serverPolicySnapshot returns the active policy, or nil when the server stated
// none.
func (c *Client) serverPolicySnapshot() *VpnProto.SessionAcceptClientPolicy {
	if c == nil {
		return nil
	}
	return c.serverPolicy.Load()
}

// policyMaxInt clamps a configured value down to a server ceiling. A ceiling of
// zero means "unstated", never "forbid everything" -- treating it as a real
// limit would let a server that set only one field silently zero out the rest.
func policyMaxInt(configured, ceiling int) int {
	if ceiling <= 0 || configured <= ceiling {
		return configured
	}
	return ceiling
}

// policyMinInt raises a configured value up to a server floor.
func policyMinInt(configured, floor int) int {
	if floor <= 0 || configured >= floor {
		return configured
	}
	return floor
}

// effectiveARQWindowSize is the ARQ window after any server ceiling. The window
// bounds how much unacknowledged data the server must track per stream, which
// is why a server cares about it.
func (c *Client) effectiveARQWindowSize() int {
	if policy := c.serverPolicySnapshot(); policy != nil {
		return policyMaxInt(c.cfg.ARQWindowSize, policy.MaxARQWindowSize)
	}
	return c.cfg.ARQWindowSize
}

// effectiveMaxPacketsPerBatch is the batch size after any server ceiling. The
// server performs the batching work, so it gets a say in the size.
func (c *Client) effectiveMaxPacketsPerBatch() int {
	if policy := c.serverPolicySnapshot(); policy != nil {
		return policyMaxInt(c.cfg.MaxPacketsPerBatch, policy.MaxPacketsPerBatch)
	}
	return c.cfg.MaxPacketsPerBatch
}

// effectiveCompressionMinSize is the compression threshold after any server
// floor. A floor stops a client from asking the server to compress every tiny
// packet.
func (c *Client) effectiveCompressionMinSize() int {
	if policy := c.serverPolicySnapshot(); policy != nil {
		return policyMinInt(c.cfg.CompressionMinSize, policy.MinCompressionMinSize)
	}
	return c.cfg.CompressionMinSize
}

// effectivePingAggressiveInterval is the aggressive ping interval after any
// server floor. This is the ceiling on how fast a client may poll, so it is the
// single most direct control a server has over the query rate it receives.
func (c *Client) effectivePingAggressiveInterval() time.Duration {
	configured := c.cfg.PingAggressiveInterval()
	policy := c.serverPolicySnapshot()
	if policy == nil || policy.MinPingAggressiveInterval <= 0 {
		return configured
	}

	floor := time.Duration(policy.MinPingAggressiveInterval * float64(time.Second))
	if configured < floor {
		return floor
	}
	return configured
}
