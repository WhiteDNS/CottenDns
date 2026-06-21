// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the CottenpickDNS client.
// This file (mtu.go) handles MTU discovery and probing.
// ==============================================================================
package client

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	DnsParser "cottenpickdns-go/internal/dnsparser"
	Enums "cottenpickdns-go/internal/enums"
	"cottenpickdns-go/internal/logger"
	VpnProto "cottenpickdns-go/internal/vpnproto"
)

var ErrNoValidConnections = errors.New("no valid connections after mtu testing")

const (
	mtuProbeCodeLength  = 4
	mtuProbeRawResponse = 0
	mtuProbeBase64Reply = 1
	defaultMTUMinFloor  = 10
	defaultUploadMaxCap = 512
	// mtuHysteresisDivisor sets the re-clustering hysteresis band: a freshly
	// derived download MTU must exceed the current one by more than 1/N (here
	// 1/8 = 12.5%) before the session adopts it, so flapping resolvers do not
	// churn the session MTU. Stranded (unsustainable) points always move.
	mtuHysteresisDivisor = 8
)

var (
	maxUploadProbePacketType = VpnProto.MaxHeaderPacketType()
	mtuDownResponseReserve   = func() int {
		reserve := VpnProto.MaxHeaderRawSize() - VpnProto.HeaderRawSize(Enums.PACKET_MTU_DOWN_RES)
		if reserve < 0 {
			return 0
		}
		return reserve
	}()
)

type mtuRejectReason uint8

const (
	mtuRejectNone mtuRejectReason = iota
	mtuRejectUpload
	mtuRejectDownload
)

type mtuProbeOptions struct {
	IsRetry bool
	Quiet   bool
}

type mtuConnectionProbeResult struct {
	UploadBytes   int
	UploadChars   int
	DownloadBytes int
	ResolveTime   time.Duration
	UploadLoss    float64
	DownloadLoss  float64
}

type mtuScanCounters struct {
	completed      atomic.Int32
	valid          atomic.Int32
	rejectUpload   atomic.Int32
	rejectDownload atomic.Int32
}

// RunInitialMTUTests tests all connections before the client starts. With
// RESOLVER_TRANSPORT="auto" it probes over UDP first and, if no resolver passes,
// retries the whole fleet over DNS-over-TCP/53 — so a network that blocks or
// truncates UDP/53 transparently falls back to TCP. "udp"/"tcp" force a single
// transport.
func (c *Client) RunInitialMTUTests(ctx context.Context) error {
	if len(c.connections) == 0 {
		return ErrNoValidConnections
	}

	switch c.cfg.ResolverTransport {
	case "tcp":
		c.useTCP.Store(true)
	default: // "udp" or "auto" both start on UDP
		c.useTCP.Store(false)
	}

	err := c.runFullMTUTests(ctx)
	if err == nil {
		return nil
	}

	// auto fallback: zero usable resolvers over UDP -> retry the fleet over TCP.
	if c.cfg.ResolverTransport == "auto" && errors.Is(err, ErrNoValidConnections) && !c.useTCP.Load() {
		if c.log != nil {
			c.log.Warnf("<yellow>No resolvers passed over UDP/53 — retrying the whole fleet over TCP/53…</yellow>")
		}
		c.useTCP.Store(true)
		for i := range c.connections {
			c.prepareConnectionMTUScanState(&c.connections[i])
		}
		if tcpErr := c.runFullMTUTests(ctx); tcpErr == nil {
			if c.log != nil {
				c.log.Infof("<green>✅ Resolver transport fell back to TCP/53.</green>")
			}
			return nil
		}
		// TCP also failed — surface the original error, restore UDP default.
		c.useTCP.Store(false)
	}
	return err
}

// runFullMTUTests performs the original fully-sequential blocking MTU scan and
// blocks until every connection has been probed before returning.
func (c *Client) runFullMTUTests(ctx context.Context) error {
	uploadCaps := c.precomputeUploadCaps()
	workerCount := min(max(1, c.cfg.MTUTestParallelism), len(c.connections))
	c.logMTUStart(workerCount)
	for idx := range c.connections {
		c.prepareConnectionMTUScanState(&c.connections[idx])
	}

	counters := &mtuScanCounters{}
	c.runAllMTUProbeWorkers(ctx, uploadCaps, workerCount, counters, nil)

	c.balancer.RefreshValidConnections()
	validConns, minUpload, minDownload, minUploadChars := summarizeValidMTUConnections(c.connections)
	if len(validConns) == 0 {
		if c.log != nil {
			c.log.Errorf("<red>No valid connections found after MTU testing!</red>")
		}
		return ErrNoValidConnections
	}

	c.finalizeMTUSelection(validConns, minUpload, minDownload, minUploadChars)
	return nil
}

// finalizeMTUSelection runs Layer 2 clustering and, when MTU_ADAPTIVE_GROUPING
// is enabled, Layer 3 best-group selection: it raises the session MTU to the
// throughput-optimal operating point and demotes resolvers that cannot sustain
// it out of the active pool. It then applies the synced MTU, refreshes the
// balancer, primes resolver-recheck metadata, and logs the outcome. It returns
// the final set of connections kept in the active pool.
func (c *Client) finalizeMTUSelection(validConns []Connection, minUpload, minDownload, minUploadChars int) []Connection {
	// Cluster the full validated set BEFORE any demotion so every tier (including
	// the slower ones that may be demoted) is visible in the UI.
	groups := clusterConnectionsByMTU(c.connections, c.cfg.MTUGroupGapRatio)
	c.mtuGroups = groups

	opUpload, opDownload, poolSize, backups := 0, 0, 0, 0
	if c.cfg.MTUAdaptiveGrouping {
		u, d, n := selectMTUOperatingPoint(validConns)
		// Only act when the optimal point actually excludes someone; otherwise it
		// equals the global minimum and nothing changes.
		if d > 0 && n > 0 && n < len(validConns) {
			backups = c.markBackupResolversBelowMTU(u, d)
			if backups > 0 {
				c.balancer.RefreshValidConnections()
				// Run the session at the operating point: the active (primary) pool
				// all sustain it, while the slower resolvers stay in reserve and
				// only carry traffic if the whole primary pool fails.
				minUpload, minDownload, minUploadChars = u, d, c.encodedCharsForPayload(u)
				validConns = primaryMTUConnections(c.connections)
			}
			opUpload, opDownload, poolSize = u, d, n
		}
	}

	c.applySyncedMTUState(minUpload, minDownload, minUploadChars)
	c.balancer.RefreshValidConnections()
	c.initResolverRecheckMeta()

	c.logMTUCompletion(validConns)
	if opDownload > 0 {
		c.logMTUOperatingPoint(opUpload, opDownload, poolSize, backups)
	}
	c.logMTUGroups(groups)
	c.logResolverTierSummary()
	return validConns
}

// resolverTierCounts classifies every connection produced by MTU testing into
// the three operational states: active (valid and selected into the data pool),
// reserve (valid but held back as a backup because it cannot sustain the session
// MTU), and invalid (failed probing). active + reserve + invalid == len(conns).
func (c *Client) resolverTierCounts() (active, reserve, invalid int) {
	for i := range c.connections {
		conn := &c.connections[i]
		switch {
		case !conn.IsValid:
			invalid++
		case conn.Backup:
			reserve++
		default:
			active++
		}
	}
	return active, reserve, invalid
}

// logResolverTierSummary prints the final three-state breakdown after MTU
// testing so the operator can see exactly how many resolvers are active, held in
// reserve, and rejected.
func (c *Client) logResolverTierSummary() {
	if !c.mtuInfoEnabled() {
		return
	}
	active, reserve, invalid := c.resolverTierCounts()
	c.log.Infof(
		"<cyan>[RESOLVER STATES]</cyan> active=<green>%d</green> reserve=<yellow>%d</yellow> invalid=<red>%d</red> (total <cyan>%d</cyan>)",
		active, reserve, invalid, active+reserve+invalid,
	)
}

// recomputeMTUOperatingPoint re-derives the adaptive operating point over the
// resolvers that are still reachable (primary + backup) and re-applies the
// session MTU and backup tiers. It runs at session (re)establishment so that, if
// the fast/primary pool has shrunk (e.g. those resolvers died mid-session),
// surviving backups are promoted at a viable lower MTU instead of stranding the
// session at an MTU nothing left can carry. No-op when adaptive grouping is off.
func (c *Client) recomputeMTUOperatingPoint() {
	if c == nil || !c.cfg.MTUAdaptiveGrouping || c.balancer == nil {
		return
	}
	conns := c.balancer.AllValidConnectionsIncludingBackup()
	if len(conns) == 0 {
		return
	}
	u, d, n := selectMTUOperatingPoint(conns)
	if d <= 0 || n <= 0 {
		return
	}

	curUp, curDown := c.syncedUploadMTU, c.syncedDownloadMTU

	// Count how many surviving resolvers can still carry the CURRENT operating
	// MTU. Zero means the current point is stranded (its pool died) and we must
	// move — usually down to the survivors.
	curPool := 0
	if curDown > 0 && curUp > 0 {
		for _, cc := range conns {
			if cc.DownloadMTUBytes >= curDown && cc.UploadMTUBytes >= curUp {
				curPool++
			}
		}
	}

	// Hysteresis: avoid churning the session MTU on small fluctuations or
	// flapping resolvers. Adopt the freshly derived point only when there is no
	// current point yet, the current one is stranded, or the new one is a
	// materially better download MTU (> ~12.5% larger). Otherwise keep the
	// current MTU stable and just re-tier resolvers against it.
	if !mtuShouldAdoptOperatingPoint(curUp, curDown, d, curPool) {
		c.balancer.ReclassifyBackups(func(cc Connection) bool {
			return cc.DownloadMTUBytes < curDown || cc.UploadMTUBytes < curUp
		})
		return
	}

	c.balancer.ReclassifyBackups(func(cc Connection) bool {
		return cc.DownloadMTUBytes < d || cc.UploadMTUBytes < u
	})
	c.applySyncedMTUState(u, d, c.encodedCharsForPayload(u))
	if (curUp != u || curDown != d) && c.mtuInfoEnabled() {
		reason := "better pool available"
		if curPool == 0 && curDown > 0 {
			reason = "previous operating MTU stranded"
		}
		c.log.Infof(
			"<green>[ADAPTIVE MTU]</green> Re-derived operating point at session (re)start: upload=<cyan>%d</cyan> download=<cyan>%d</cyan> (was %d/%d) | active pool=<green>%d</green> | %s.",
			u, d, curUp, curDown, n, reason,
		)
	}
}

// mtuShouldAdoptOperatingPoint applies the re-clustering hysteresis policy: a
// freshly derived download MTU is adopted only when there is no current point
// yet, the current point is stranded (no survivor can carry it, curPool == 0),
// or the new download MTU is materially larger (> 1/mtuHysteresisDivisor). This
// keeps the session MTU stable under flapping/bad-resolver conditions.
func mtuShouldAdoptOperatingPoint(curUp, curDown, newDown, curPool int) bool {
	switch {
	case curDown <= 0 || curUp <= 0:
		return true
	case curPool == 0:
		return true
	case newDown > curDown+curDown/mtuHysteresisDivisor:
		return true
	default:
		return false
	}
}

// connectionsWithoutPreknownMTU returns the indices of connections that did not
// receive an MTU from the cache (invalid or zero download MTU) and therefore
// still need probing in a hybrid log-mode start.
func connectionsWithoutPreknownMTU(conns []Connection) []int {
	out := make([]int, 0, len(conns))
	for i := range conns {
		if conns[i].IsValid && conns[i].DownloadMTUBytes > 0 {
			continue
		}
		out = append(out, i)
	}
	return out
}

// markBackupResolversBelowMTU flags every valid connection that cannot sustain
// the given operating MTU as a backup (reserve). The connection stays valid and
// visible; the balancer keeps it out of the active pool and only selects it when
// no primary resolver remains. Returns the count moved to the backup tier.
func (c *Client) markBackupResolversBelowMTU(uploadMTU, downloadMTU int) int {
	marked := 0
	for i := range c.connections {
		conn := &c.connections[i]
		if !conn.IsValid || conn.Backup {
			continue
		}
		if conn.DownloadMTUBytes < downloadMTU || conn.UploadMTUBytes < uploadMTU {
			conn.Backup = true
			marked++
		}
	}
	return marked
}

// primaryMTUConnections returns the active (non-backup) valid connections.
func primaryMTUConnections(conns []Connection) []Connection {
	out := make([]Connection, 0, len(conns))
	for _, conn := range conns {
		if conn.IsValid && !conn.Backup {
			out = append(out, conn)
		}
	}
	return out
}

// runAllMTUProbeWorkers dispatches MTU probe jobs to workers. When onValid is
// non-nil it is called (with a copy of the connection) after each successful
// probe, from within the worker goroutine.
func (c *Client) runAllMTUProbeWorkers(ctx context.Context, uploadCaps map[string]int, workerCount int, counters *mtuScanCounters, onValid func(Connection)) {
	total := len(c.connections)
	if workerCount <= 1 {
		for idx := range c.connections {
			if ctx.Err() != nil {
				return
			}
			conn := &c.connections[idx]
			c.runConnectionMTUTest(ctx, conn, idx+1, total, uploadCaps[conn.Domain], counters)
			if onValid != nil && conn.IsValid {
				onValid(*conn)
			}
		}
		return
	}

	jobs := make(chan int, total)
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				conn := &c.connections[idx]
				c.runConnectionMTUTest(ctx, conn, idx+1, total, uploadCaps[conn.Domain], counters)
				if onValid != nil && conn.IsValid {
					onValid(*conn)
				}
			}
		}()
	}
	for idx := range c.connections {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- idx:
		}
	}
	close(jobs)
	wg.Wait()
}

// prepareConnectionMTUScanState resets a connection's MTU state before a probe
// run. IsValid is intentionally set to false: probeConnectionMTU sets it to
// false on every rejection/error path, and runConnectionMTUTest explicitly sets
// it to true only on a clean pass. Starting at false ensures the early-start
// tracker's onValid callback (which checks conn.IsValid after the probe) is
// only triggered for genuinely successful probes.
func (c *Client) prepareConnectionMTUScanState(conn *Connection) {
	if conn == nil {
		return
	}
	conn.IsValid = false
	conn.Backup = false
	conn.UploadMTUBytes = 0
	conn.UploadMTUChars = 0
	conn.DownloadMTUBytes = 0
	conn.MTUResolveTime = 0
	conn.UploadMTULoss = 0
	conn.DownloadMTULoss = 0
}

func (c *Client) runConnectionMTUTest(ctx context.Context, conn *Connection, serverID int, total int, maxUploadPayload int, counters *mtuScanCounters) {
	if conn == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			conn.IsValid = false
			if c.log != nil {
				c.log.Errorf(
					"💥 <red>MTU Probe Worker Panic: <cyan>%v</cyan> (Resolver: <cyan>%s</cyan>)</red>",
					recovered,
					conn.ResolverLabel,
				)
			}
			if counters != nil {
				completed := counters.completed.Add(1)
				rejectedNow := counters.rejectUpload.Add(1) + counters.rejectDownload.Load()
				if c.log != nil && c.log.Enabled(logger.LevelWarn) {
					c.log.Warnf(
						"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>PANIC</yellow> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
						completed,
						total,
						conn.Domain,
						conn.ResolverLabel,
						counters.valid.Load(),
						rejectedNow,
					)
				}
			}
		}
	}()

	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf(
			"<green>Testing Resolver: <cyan>%s</cyan> for Domain: <cyan>%s</cyan> (<cyan>%d / %d</cyan>)</green>",
			conn.ResolverLabel,
			conn.Domain,
			serverID,
			total,
		)
	}

	result, reason := c.probeConnectionMTU(ctx, conn, maxUploadPayload)
	if counters == nil {
		return
	}

	switch reason {
	case mtuRejectUpload:
		completed := counters.completed.Add(1)
		rejectedNow := counters.rejectUpload.Add(1) + counters.rejectDownload.Load()
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf(
				"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>UPLOAD_MTU</yellow> | value=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
				completed,
				total,
				conn.Domain,
				conn.ResolverLabel,
				result.UploadBytes,
				counters.valid.Load(),
				rejectedNow,
			)
		}
		return
	case mtuRejectDownload:
		completed := counters.completed.Add(1)
		rejectedNow := counters.rejectUpload.Load() + counters.rejectDownload.Add(1)
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf(
				"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>DOWNLOAD_MTU</yellow> | value=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
				completed,
				total,
				conn.Domain,
				conn.ResolverLabel,
				result.DownloadBytes,
				counters.valid.Load(),
				rejectedNow,
			)
		}
		return
	}

	conn.IsValid = true
	conn.UploadMTUBytes = result.UploadBytes
	conn.UploadMTUChars = result.UploadChars
	conn.DownloadMTUBytes = result.DownloadBytes
	conn.MTUResolveTime = result.ResolveTime
	conn.UploadMTULoss = result.UploadLoss
	conn.DownloadMTULoss = result.DownloadLoss

	completed := counters.completed.Add(1)
	validNow := counters.valid.Add(1)
	rejectedNow := counters.rejectUpload.Load() + counters.rejectDownload.Load()
	if c.log != nil && c.log.Enabled(logger.LevelInfo) {
		c.log.Infof(
			"<green>✅ Accepted (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | upload=<cyan>%d</cyan> | download=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></green>",
			completed,
			total,
			conn.Domain,
			conn.ResolverLabel,
			conn.UploadMTUBytes,
			conn.DownloadMTUBytes,
			validNow,
			rejectedNow,
		)
	}
	c.appendResolverCacheEntry(conn)
}

func (c *Client) probeConnectionMTU(ctx context.Context, conn *Connection, maxUploadPayload int) (mtuConnectionProbeResult, mtuRejectReason) {
	var result mtuConnectionProbeResult

	probeTransport, err := c.newQueryTransport(conn.ResolverLabel)
	if err != nil {
		conn.IsValid = false
		return result, mtuRejectUpload
	}
	defer probeTransport.Close()

	upOK, upBytes, upChars, upRTT, upLoss, err := c.testUploadMTU(ctx, conn, probeTransport, maxUploadPayload)
	if err != nil || !upOK {
		conn.IsValid = false
		result.UploadBytes = upBytes
		result.UploadChars = upChars
		return result, mtuRejectUpload
	}
	result.UploadBytes = upBytes
	result.UploadChars = upChars
	result.UploadLoss = upLoss

	downOK, downBytes, downRTT, downLoss, err := c.testDownloadMTU(ctx, conn, probeTransport, upBytes)
	if err != nil || !downOK {
		conn.IsValid = false
		result.DownloadBytes = downBytes
		return result, mtuRejectDownload
	}
	result.DownloadBytes = downBytes
	result.DownloadLoss = downLoss
	result.ResolveTime = averageMTUProbeRTT(upRTT, downRTT)
	return result, mtuRejectNone
}

func (c *Client) precomputeUploadCaps() map[string]int {
	caps := make(map[string]int, len(c.cfg.Domains))
	for _, domain := range c.cfg.Domains {
		if _, exists := caps[domain]; exists {
			continue
		}
		caps[domain] = c.maxUploadMTUPayload(domain)
	}
	return caps
}

func (c *Client) testUploadMTU(ctx context.Context, conn *Connection, probeTransport queryExchanger, maxPayload int) (bool, int, int, time.Duration, float64, error) {
	if maxPayload <= 0 {
		return false, 0, 0, 0, 0, nil
	}
	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf("<cyan>[MTU]</cyan> Testing upload MTU for %s", conn.Domain)
	}

	maxLimit := c.cfg.MaxUploadMTU
	if maxLimit <= 0 || maxLimit > defaultUploadMaxCap {
		maxLimit = defaultUploadMaxCap
	}
	if maxPayload > maxLimit {
		maxPayload = maxLimit
	}

	best, bestRTT, bestLoss := c.binarySearchMTU(
		ctx,
		"upload mtu",
		c.cfg.MinUploadMTU,
		maxPayload,
		func(candidate int, isRetry bool) (bool, time.Duration, error) {
			return c.sendUploadMTUProbe(ctx, conn, probeTransport, candidate, mtuProbeOptions{
				IsRetry: isRetry,
			})
		},
	)
	if best < max(defaultMTUMinFloor, c.cfg.MinUploadMTU) {
		return false, 0, 0, 0, 0, nil
	}
	return true, best, c.encodedCharsForPayload(best), bestRTT, bestLoss, nil
}

func (c *Client) testDownloadMTU(ctx context.Context, conn *Connection, probeTransport queryExchanger, uploadMTU int) (bool, int, time.Duration, float64, error) {
	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf("<cyan>[MTU]</cyan> Testing download MTU for %s", conn.Domain)
	}
	best, bestRTT, bestLoss := c.binarySearchMTU(
		ctx,
		"download mtu",
		c.cfg.MinDownloadMTU,
		c.cfg.MaxDownloadMTU,
		func(candidate int, isRetry bool) (bool, time.Duration, error) {
			return c.sendDownloadMTUProbe(ctx, conn, probeTransport, candidate, uploadMTU, mtuProbeOptions{
				IsRetry: isRetry,
			})
		},
	)
	if best < max(defaultMTUMinFloor, c.cfg.MinDownloadMTU) {
		return false, 0, 0, 0, nil
	}
	return true, best, bestRTT, bestLoss, nil
}

func (c *Client) binarySearchMTU(ctx context.Context, label string, minValue, maxValue int, testFn func(int, bool) (bool, time.Duration, error)) (int, time.Duration, float64) {
	if maxValue <= 0 {
		return 0, 0, 0
	}

	low := max(minValue, defaultMTUMinFloor)
	high := maxValue
	if high < low {
		if c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(
				"<cyan>[MTU]</cyan> Invalid %s range: low=%d, high=%d. Skipping.",
				label,
				low,
				high,
			)
		}
		return 0, 0, 0
	}
	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf(
			"<cyan>[MTU]</cyan> Starting binary search for %s. Range: %d-%d",
			label,
			low,
			high,
		)
	}

	check := func(value int) (bool, time.Duration, float64) {
		return c.evaluateMTUCandidate(ctx, value, testFn)
	}

	if ok, rtt, loss := check(high); ok {
		if c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf("<cyan>[MTU]</cyan> Max MTU %d is valid.", high)
		}
		return high, rtt, loss
	}
	if low == high {
		if c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(
				"<cyan>[MTU]</cyan> Only one MTU candidate (%d) existed and it failed.",
				low,
			)
		}
		return 0, 0, 0
	}
	best := low
	bestRTT := time.Duration(0)
	bestLoss := 0.0
	if ok, rtt, loss := check(low); !ok {
		if c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(
				"<cyan>[MTU]</cyan> Both boundary MTUs failed (min=%d, max=%d). Skipping middle checks.",
				low,
				high,
			)
		}
		return 0, 0, 0
	} else {
		bestRTT = rtt
		bestLoss = loss
	}

	left := low + 1
	right := high - 1
	for left <= right {
		if err := ctx.Err(); err != nil {
			return 0, 0, 0
		}
		mid := (left + right) / 2
		if ok, rtt, loss := check(mid); ok {
			best = mid
			bestRTT = rtt
			bestLoss = loss
			left = mid + 1
		} else {
			right = mid - 1
		}
	}
	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf("<cyan>[MTU]</cyan> Binary search result: %d (loss=%.0f%%)", best, bestLoss*100)
	}
	return best, bestRTT, bestLoss
}

// evaluateMTUCandidate decides whether a single MTU value is acceptable and
// reports its measured loss. With MTU_PROBE_SAMPLES <= 1 it keeps the legacy
// behavior (accept if any of mtuTestRetries attempts succeed; loss reported as
// 0 on success, 1 on failure). With MTU_PROBE_SAMPLES > 1 it switches to
// loss-aware probing: it sends that many independent probes and accepts the
// candidate only if the observed loss fraction is at or below MTU_MAX_LOSS,
// returning the actual measured loss so the caller can record the loss at the
// chosen MTU edge.
func (c *Client) evaluateMTUCandidate(ctx context.Context, value int, testFn func(int, bool) (bool, time.Duration, error)) (bool, time.Duration, float64) {
	samples := c.cfg.MTUProbeSamples
	if samples > 1 {
		// Probe-cost control (coarse-then-refine): stop sampling this candidate as
		// soon as the accept/reject verdict is locked — once enough successes make
		// the loss budget unbeatable, or once failures exceed it — instead of
		// always sending all K probes. The decision is identical to sampling the
		// full K; only the probe count shrinks (helpful with large resolver lists).
		allowedFail := int(float64(samples) * c.cfg.MTUMaxLoss)
		neededSuccess := samples - allowedFail
		success, failed := 0, 0
		var sumRTT time.Duration
		for i := 0; i < samples; i++ {
			if err := ctx.Err(); err != nil {
				return false, 0, 1
			}
			passed, rtt, err := testFn(value, i > 0)
			if err != nil && c.log != nil && c.log.Enabled(logger.LevelDebug) {
				c.log.Debugf("MTU test callable raised for %d: %v", value, err)
			}
			if err == nil && passed {
				success++
				if rtt > 0 {
					sumRTT += rtt
				}
				if success >= neededSuccess {
					break // accept locked: remaining probes cannot push loss over budget
				}
			} else {
				failed++
				if failed > allowedFail {
					break // reject locked: loss already exceeds budget
				}
			}
		}
		sampled := success + failed
		loss := 0.0
		if sampled > 0 {
			loss = float64(failed) / float64(sampled)
		}
		var avgRTT time.Duration
		if success > 0 {
			avgRTT = sumRTT / time.Duration(success)
		}
		ok := failed <= allowedFail
		if c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(
				"<cyan>[MTU]</cyan> Candidate %d bytes: loss≈%.0f%% (%d ok / %d sampled of %d), accept=%v (max=%.0f%%)",
				value, loss*100, success, sampled, samples, ok, c.cfg.MTUMaxLoss*100,
			)
		}
		return ok, avgRTT, loss
	}

	// Legacy: accept if any retry succeeds.
	for attempt := 0; attempt < c.mtuTestRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return false, 0, 1
		}
		passed, measuredRTT, err := testFn(value, attempt > 0)
		if err != nil && c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf("MTU test callable raised for %d: %v", value, err)
		}
		if err == nil && passed {
			return true, measuredRTT, 0
		}
	}
	return false, 0, 1
}

func (c *Client) sendUploadMTUProbe(ctx context.Context, conn *Connection, probeTransport queryExchanger, mtuSize int, options mtuProbeOptions) (bool, time.Duration, error) {
	if mtuSize < 1+mtuProbeCodeLength {
		return false, 0, nil
	}
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	c.logMTUProbe(
		options.IsRetry,
		options.Quiet,
		"<magenta>[MTU Probe]</magenta> Testing Upload MTU: <yellow>%d</yellow> bytes via <cyan>%s</cyan>",
		mtuSize,
		conn.ResolverLabel,
	)

	payload, code, useBase64, err := c.buildMTUProbePayload(mtuSize)
	if err != nil {
		return false, 0, err
	}

	query, err := c.buildMTUProbeQuery(conn.Domain, Enums.PACKET_MTU_UP_REQ, payload)
	if err != nil {
		return false, 0, nil
	}

	startedAt := time.Now()
	response, err := probeTransport.exchange(query, c.mtuTestTimeout)
	if err != nil {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	rtt := time.Since(startedAt)

	packet, err := DnsParser.ExtractVPNResponseMatching(response, useBase64, c.cfg.Domains)
	if err != nil {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if packet.PacketType != Enums.PACKET_MTU_UP_RES {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if len(packet.Payload) != 6 {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if binary.BigEndian.Uint32(packet.Payload[:mtuProbeCodeLength]) != code {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	ok := int(binary.BigEndian.Uint16(packet.Payload[mtuProbeCodeLength:mtuProbeCodeLength+2])) == mtuSize
	if ok {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>🟢 Upload test passed: Upload MTU <green>%d</green> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
	} else {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
	}
	return ok, rtt, nil
}

func (c *Client) sendDownloadMTUProbe(ctx context.Context, conn *Connection, probeTransport queryExchanger, mtuSize int, uploadMTU int, options mtuProbeOptions) (bool, time.Duration, error) {
	if mtuSize < defaultMTUMinFloor {
		return false, 0, nil
	}
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	c.logMTUProbe(
		options.IsRetry,
		options.Quiet,
		"<magenta>[MTU Probe]</magenta> Testing Download MTU: <yellow>%d</yellow> bytes via <cyan>%s</cyan>",
		mtuSize,
		conn.ResolverLabel,
	)

	effectiveDownloadSize := effectiveDownloadMTUProbeSize(mtuSize)
	if effectiveDownloadSize < defaultMTUMinFloor {
		return false, 0, nil
	}
	requestLen := max(1+mtuProbeCodeLength+2, uploadMTU)
	payload, code, useBase64, err := c.buildMTUProbePayload(requestLen)
	if err != nil {
		return false, 0, err
	}
	binary.BigEndian.PutUint16(payload[1+mtuProbeCodeLength:1+mtuProbeCodeLength+2], uint16(effectiveDownloadSize))

	query, err := c.buildMTUProbeQuery(conn.Domain, Enums.PACKET_MTU_DOWN_REQ, payload)
	if err != nil {
		return false, 0, nil
	}

	startedAt := time.Now()
	response, err := probeTransport.exchange(query, c.mtuTestTimeout)
	if err != nil {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (No Response)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	rtt := time.Since(startedAt)

	packet, err := DnsParser.ExtractVPNResponseMatching(response, useBase64, c.cfg.Domains)
	if err != nil {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Unexpected Packet Type)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}

	if packet.PacketType != Enums.PACKET_MTU_DOWN_RES {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Unexpected Packet Type)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if len(packet.Payload) != effectiveDownloadSize {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Data Size Mismatch)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if len(packet.Payload) < 1+mtuProbeCodeLength+1 {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Data Size Mismatch)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if binary.BigEndian.Uint32(packet.Payload[:mtuProbeCodeLength]) != code {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Data Size Mismatch)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	ok := int(binary.BigEndian.Uint16(packet.Payload[mtuProbeCodeLength:mtuProbeCodeLength+2])) == effectiveDownloadSize
	if ok {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>🟢 Download test passed: Download MTU <green>%d</green> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
	} else {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Data Size Mismatch)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
	}
	return ok, rtt, nil
}

func (c *Client) buildMTUProbeQuery(domain string, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelTXTQueryRaw(domain, VpnProto.BuildOptions{
		SessionID:      255,
		PacketType:     packetType,
		StreamID:       1,
		SequenceNum:    1,
		FragmentID:     0,
		TotalFragments: 1,
		Payload:        payload,
	})
}

func (c *Client) maxUploadMTUPayload(domain string) int {
	maxChars := DnsParser.CalculateMaxEncodedQNameChars(domain)
	if maxChars <= 0 {
		return 0
	}

	low := 0
	high := maxChars
	best := 0
	for low <= high {
		mid := (low + high) / 2
		if c.canBuildUploadPayload(domain, mid) {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return best
}

func (c *Client) canBuildUploadPayload(domain string, payloadLen int) bool {
	if payloadLen <= 0 {
		return true
	}

	buf := c.udpBufferPool.Get().([]byte)
	defer c.udpBufferPool.Put(buf)

	if payloadLen > len(buf) {
		return false
	}

	payload := buf[:payloadLen]
	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:      255,
		PacketType:     Enums.PACKET_MTU_UP_REQ,
		SessionCookie:  255,
		StreamID:       0xFFFF,
		SequenceNum:    0xFFFF,
		FragmentID:     0xFF,
		TotalFragments: 0xFF,
		Payload:        payload,
	}, c.codec)
	if err != nil {
		return false
	}

	_, err = DnsParser.BuildTunnelQuestionName(domain, encoded)
	return err == nil
}

func (c *Client) buildMTUProbePayload(length int) ([]byte, uint32, bool, error) {
	if length <= 0 {
		return nil, 0, false, nil
	}

	payload := make([]byte, length)
	useBase64 := c != nil && c.cfg.BaseEncodeData
	payload[0] = mtuProbeRawResponse
	if useBase64 {
		payload[0] = mtuProbeBase64Reply
	}

	code := c.mtuProbeCounter.Add(1)
	binary.BigEndian.PutUint32(payload[1:1+mtuProbeCodeLength], code)

	return payload, code, useBase64, nil
}

func averageMTUProbeRTT(values ...time.Duration) time.Duration {
	var sum time.Duration
	count := 0
	for _, value := range values {
		if value <= 0 {
			continue
		}
		sum += value
		count++
	}
	if count == 0 {
		return 0
	}
	return sum / time.Duration(count)
}

func summarizeValidMTUConnections(connections []Connection) (validConns []Connection, minUpload int, minDownload int, minUploadChars int) {
	validConns = make([]Connection, 0, len(connections))
	for _, conn := range connections {
		if !conn.IsValid {
			continue
		}
		validConns = append(validConns, conn)

		if conn.UploadMTUBytes > 0 && (minUpload == 0 || conn.UploadMTUBytes < minUpload) {
			minUpload = conn.UploadMTUBytes
		}
		if conn.DownloadMTUBytes > 0 && (minDownload == 0 || conn.DownloadMTUBytes < minDownload) {
			minDownload = conn.DownloadMTUBytes
		}
		if conn.UploadMTUChars > 0 && (minUploadChars == 0 || conn.UploadMTUChars < minUploadChars) {
			minUploadChars = conn.UploadMTUChars
		}
	}
	return validConns, minUpload, minDownload, minUploadChars
}

// applyPreknownMTUsFromLog applies MTU values that were pre-filled from log files,
// skipping the full MTU scan. It writes the pre-known entries to the MTU success
// file and the resolver cache log so future sessions can reuse them.
// Returns ErrNoValidConnections when no connections have pre-filled MTU values.
func (c *Client) applyPreknownMTUsFromLog(ctx context.Context) error {
	if len(c.connections) == 0 {
		return ErrNoValidConnections
	}

	// Hybrid start: trust cached MTUs for resolvers that have a log entry, but
	// still probe any resolver in the CURRENT list that has none — so a changed
	// or extended resolver list is always fully covered. Caching is only a
	// background accelerator for known resolvers; it never gates out new ones.
	if scanned := c.scanConnectionsWithoutPreknownMTU(ctx); scanned > 0 && c.log != nil {
		c.log.Infof(
			"<green>⚡ Cache start: scanned <cyan>%d</cyan> resolver(s) not present in the cache (new/changed list)</green>",
			scanned,
		)
	}

	validConns, minUpload, minDownload, minUploadChars := summarizeValidMTUConnections(c.connections)
	if len(validConns) == 0 {
		return ErrNoValidConnections
	}

	// Persist the working resolvers (cached + freshly scanned) to the cache log.
	for i := range c.connections {
		conn := &c.connections[i]
		if conn.IsValid {
			c.appendResolverCacheEntry(conn)
		}
	}

	c.balancer.RefreshValidConnections()

	if c.log != nil {
		c.log.Infof(
			"<green>⚡ Using <cyan>%d</cyan> resolvers (cache + fresh scan of new entries)</green>",
			len(validConns),
		)
	}
	c.finalizeMTUSelection(validConns, minUpload, minDownload, minUploadChars)
	return nil
}

// scanConnectionsWithoutPreknownMTU probes only the connections that did not get
// an MTU from the cache (resolvers new to the user's list). Preknown connections
// are left untouched. Returns the number of connections scanned.
func (c *Client) scanConnectionsWithoutPreknownMTU(ctx context.Context) int {
	indices := connectionsWithoutPreknownMTU(c.connections)
	if len(indices) == 0 {
		return 0
	}
	for _, idx := range indices {
		c.prepareConnectionMTUScanState(&c.connections[idx])
	}

	uploadCaps := c.precomputeUploadCaps()
	total := len(c.connections)
	workerCount := min(max(1, c.cfg.MTUTestParallelism), len(indices))
	counters := &mtuScanCounters{}

	if workerCount <= 1 {
		for _, idx := range indices {
			if ctx.Err() != nil {
				break
			}
			conn := &c.connections[idx]
			c.runConnectionMTUTest(ctx, conn, idx+1, total, uploadCaps[conn.Domain], counters)
		}
		return len(indices)
	}

	jobs := make(chan int, len(indices))
	var wg sync.WaitGroup
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				conn := &c.connections[idx]
				c.runConnectionMTUTest(ctx, conn, idx+1, total, uploadCaps[conn.Domain], counters)
			}
		}()
	}
	for _, idx := range indices {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return len(indices)
		case jobs <- idx:
		}
	}
	close(jobs)
	wg.Wait()
	return len(indices)
}

func (c *Client) encodedCharsForPacketPayload(packetType uint8, payloadLen int) int {
	if payloadLen <= 0 {
		return 0
	}

	buf := c.udpBufferPool.Get().([]byte)
	defer c.udpBufferPool.Put(buf)

	if payloadLen > len(buf) {
		return 0
	}

	payload := buf[:payloadLen]
	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:       255,
		PacketType:      packetType,
		SessionCookie:   255,
		StreamID:        0xFFFF,
		SequenceNum:     0xFFFF,
		FragmentID:      0xFF,
		TotalFragments:  0xFF,
		CompressionType: 0xFF,
		Payload:         payload,
	}, c.codec)

	if err != nil {
		return 0
	}

	return len(encoded)
}

func (c *Client) encodedCharsForPayload(payloadLen int) int {
	return c.encodedCharsForPacketPayload(maxUploadProbePacketType, payloadLen)
}

func effectiveDownloadMTUProbeSize(downloadMTU int) int {
	if downloadMTU <= 0 {
		return 0
	}

	return downloadMTU + mtuDownResponseReserve
}

func computeSafeUploadMTU(uploadMTU int, cryptoOverhead int) int {
	if uploadMTU <= 0 {
		return 0
	}

	safe := uploadMTU - cryptoOverhead
	if safe < 64 {
		safe = 64
	}

	if safe > uploadMTU {
		return uploadMTU
	}

	return safe
}

func mtuCryptoOverhead(method int) int {
	switch method {
	case 2:
		return 16
	case 3, 4, 5:
		return 28
	default:
		return 0
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
