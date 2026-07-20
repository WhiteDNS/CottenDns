// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package client

import (
	"testing"
	"time"

	"cottendns-go/internal/config"
	VpnProto "cottendns-go/internal/vpnproto"
)

func policyTestClient(cfg config.ClientConfig) *Client {
	return &Client{cfg: cfg}
}

// With no policy from the server, every governed value must be exactly what the
// operator configured. This is the path every existing deployment takes.
func TestNoServerPolicyLeavesConfiguredValuesAlone(t *testing.T) {
	c := policyTestClient(config.ClientConfig{
		ARQWindowSize:                 4096,
		MaxPacketsPerBatch:            32,
		CompressionMinSize:            40,
		PingAggressiveIntervalSeconds: 0.08,
	})

	if got := c.effectiveARQWindowSize(); got != 4096 {
		t.Fatalf("ARQ window = %d, want the configured 4096", got)
	}
	if got := c.effectiveMaxPacketsPerBatch(); got != 32 {
		t.Fatalf("batch = %d, want the configured 32", got)
	}
	if got := c.effectiveCompressionMinSize(); got != 40 {
		t.Fatalf("compression min = %d, want the configured 40", got)
	}
	if got := c.effectivePingAggressiveInterval(); got != c.cfg.PingAggressiveInterval() {
		t.Fatalf("ping interval = %v, want the configured %v", got, c.cfg.PingAggressiveInterval())
	}
}

// A client asking for more than the server allows must be clamped down, and one
// asking for less than a server floor must be raised up.
func TestServerPolicyClampsGreedyClient(t *testing.T) {
	c := policyTestClient(config.ClientConfig{
		ARQWindowSize:                 8000,
		MaxPacketsPerBatch:            64,
		CompressionMinSize:            10,
		PingAggressiveIntervalSeconds: 0.05,
	})

	policy := VpnProto.SessionAcceptClientPolicy{
		MaxARQWindowSize:          2000,
		MaxPacketsPerBatch:        8,
		MinCompressionMinSize:     120,
		MinPingAggressiveInterval: 0.20,
	}
	c.serverPolicy.Store(&policy)

	if got := c.effectiveARQWindowSize(); got != 2000 {
		t.Fatalf("ARQ window = %d, want it clamped to the server's 2000", got)
	}
	if got := c.effectiveMaxPacketsPerBatch(); got != 8 {
		t.Fatalf("batch = %d, want it clamped to the server's 8", got)
	}
	if got := c.effectiveCompressionMinSize(); got != 120 {
		t.Fatalf("compression min = %d, want it raised to the server's 120", got)
	}
	want := time.Duration(0.20 * float64(time.Second))
	if got := c.effectivePingAggressiveInterval(); got != want {
		t.Fatalf("ping interval = %v, want it raised to the server's %v", got, want)
	}
}

// A modest client must not be inflated up to the server's ceiling: the policy
// states a limit, not a target.
func TestServerPolicyDoesNotRaiseModestClient(t *testing.T) {
	c := policyTestClient(config.ClientConfig{
		ARQWindowSize:      256,
		MaxPacketsPerBatch: 4,
	})

	policy := VpnProto.SessionAcceptClientPolicy{MaxARQWindowSize: 2000, MaxPacketsPerBatch: 8}
	c.serverPolicy.Store(&policy)

	if got := c.effectiveARQWindowSize(); got != 256 {
		t.Fatalf("ARQ window = %d, want the client's own smaller 256", got)
	}
	if got := c.effectiveMaxPacketsPerBatch(); got != 4 {
		t.Fatalf("batch = %d, want the client's own smaller 4", got)
	}
}

// A server that sets only some fields leaves the rest unstated. Unstated must
// mean "no limit", never "limit of zero" -- otherwise setting one field would
// silently zero out everything else and strangle the client.
func TestUnstatedPolicyFieldsAreNotTreatedAsZeroLimits(t *testing.T) {
	c := policyTestClient(config.ClientConfig{
		ARQWindowSize:      4096,
		MaxPacketsPerBatch: 32,
		CompressionMinSize: 40,
	})

	// Only the ARQ window is stated.
	policy := VpnProto.SessionAcceptClientPolicy{MaxARQWindowSize: 1000}
	c.serverPolicy.Store(&policy)

	if got := c.effectiveARQWindowSize(); got != 1000 {
		t.Fatalf("ARQ window = %d, want the stated 1000", got)
	}
	if got := c.effectiveMaxPacketsPerBatch(); got != 32 {
		t.Fatalf("batch = %d, want the configured 32 to survive an unstated ceiling", got)
	}
	if got := c.effectiveCompressionMinSize(); got != 40 {
		t.Fatalf("compression min = %d, want the configured 40 to survive an unstated floor", got)
	}
}

// The end-to-end client path: a real accept payload carrying a policy must be
// picked up, and one without a policy must leave the client unconstrained.
func TestApplyServerClientPolicyFromAcceptPayload(t *testing.T) {
	verify := [4]byte{1, 2, 3, 4}

	withPolicy := VpnProto.EncodeSessionAccept(300, 0x5A, 0, verify, VpnProto.SessionAcceptClientPolicy{
		MaxARQWindowSize: 512,
	}, false)

	c := policyTestClient(config.ClientConfig{ARQWindowSize: 4096})
	c.applyServerClientPolicy(withPolicy)
	if got := c.effectiveARQWindowSize(); got != 512 {
		t.Fatalf("ARQ window = %d, want the advertised 512", got)
	}

	bare := VpnProto.EncodeSessionAccept(300, 0x5A, 0, verify, VpnProto.SessionAcceptClientPolicy{}, false)
	c2 := policyTestClient(config.ClientConfig{ARQWindowSize: 4096})
	c2.applyServerClientPolicy(bare)
	if got := c2.effectiveARQWindowSize(); got != 4096 {
		t.Fatalf("ARQ window = %d, want the configured 4096 when no policy was sent", got)
	}
}
