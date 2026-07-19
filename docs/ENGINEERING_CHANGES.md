# CottenDNS — Engineering Changes & Design Notes

A technical walkthrough of the changes made to CottenDNS, written for network
engineers who want to evaluate the design. It explains **what problem each change
solves**, **how it works**, **how it is wired into the data path**, and **why it
helps** on hostile DNS networks. Honest caveats are called out where they exist.

---

## 0. System model (read this first)

CottenDNS tunnels TCP over DNS. The client exposes a local SOCKS5/TCP
listener, chops each stream into DNS-safe packets, and sends them as the QNAME
labels of DNS **queries** through one or more recursive resolvers to an
authoritative CottenDNS server. The server reassembles the stream, makes the
real outbound connection, and returns downstream data inside DNS **answers**
(TXT/CNAME/A/NULL/HTTPS records).

```
app ──TCP──> client ──DNS query (UDP/53)──> resolver(s) ──> CottenDNS server ──> internet
app <──TCP── client <──DNS answer──────────── resolver(s) <───────────────────────┘
```

Two structural facts drive almost every design decision below:

1. **MTU is a session-global, server-negotiated property.** A single
   `SESSION_INIT` fixes one upload MTU and one download MTU for the entire
   session. The server sizes *every* download packet to that one download MTU,
   and those answers return through whichever resolver carried the poll. You
   therefore cannot run different resolvers at different MTUs inside one session
   without either multiple sessions or per-poll renegotiation.
2. **Loss is bidirectional and path-dependent.** The resolver↔server and
   resolver↔client legs are lossy, asymmetric, rate-limited, and the resolver
   itself silently truncates oversized answers. The reliability layer must treat
   loss as normal, not exceptional.

The transport is UDP/53 by default, with an automatic fallback to
**DNS-over-TCP/53** when UDP is filtered (§10). Everything that follows is built
around the two facts above and applies to both transports.

---

## 1. Reliability core: ARQ correctness & efficiency

**Problem.** The selective-repeat ARQ (per-stream windows, ACK/NACK, RTO
retransmission) had two scaling issues: (a) background session sweeps iterated a
full session table, and (b) the retransmit checker rescanned the whole send
buffer on every tick even when nothing was due.

**What changed.**
- **Active-ID sweeps.** Session housekeeping now iterates an `activeIDs` set
  maintained at insert/remove instead of scanning the whole (now 65535-slot)
  session array. O(active) instead of O(capacity).
- **O(1) retransmit deadline hint.** Each ARQ keeps `minRetransmitAt`, a provable
  lower bound on the earliest moment any buffered packet could need action (RTO
  due-time or TTL expiry). A tick where `now < minRetransmitAt` skips the entire
  send-buffer scan. The hint is invalidated at every send/dispatch and recomputed
  after each real scan, so it can never skip a due retransmit.

**Why it helps.** The reliability layer stays cheap as the number of concurrent
sessions/streams grows, which matters once the session space is widened (§3).

---

## 2. Forward Error Correction (FEC) on the download path

**Problem.** Under heavy loss, ARQ recovers by retransmitting — but each
retransmit costs a full resolver round-trip (often hundreds of ms). At 30–75%
loss the tunnel spends most of its time waiting for retransmits. We want the
client to *reconstruct* lost downstream packets without a round-trip.

**Mechanism — Reed-Solomon over packet blocks.**
- `internal/fec/fec.go`: block codec. `EncodePackets(packets, parityShards)`
  turns `N` data packets into `N + K` equal-size shards; any `N` of the `N+K`
  shards reconstruct the block. `ParityForLoss(dataShards, lossFrac)` sizes `K`
  for a target loss.
- `internal/fec/stream.go`: a stateful streaming layer. `Encoder` buffers data
  units and emits framed shards at each block boundary (`Flush()` bounds latency
  when the stream pauses); `Decoder` collects shards and returns the recovered
  data units once a block is decodable. Shard frame header (9 bytes):
  `blockID(4) | shardIndex(1) | dataShards(1) | parityShards(1) | shardSize(2)`.
- `internal/vpnproto/fec_unit.go`: each block element is one data packet
  serialized as `seq(2) | fragID(1) | payload`, so a recovered unit can be
  replayed into ARQ exactly as if its `STREAM_DATA` had arrived.

**How it is wired (server → client), default-off, byte-identical when disabled.**
- New packet type `PACKET_FEC_SHARD = 0x38`, flagged `valid | stream` (carries a
  StreamID for routing, no seq/frag of its own).
- **Server** (`internal/udpserver/stream_server.go`): when a stream has FEC on,
  `STREAM_DATA`/`STREAM_RESEND` popped from the transmit queue at *dequeue time*
  are folded into the stream's `fec.Encoder` and emitted as `PACKET_FEC_SHARD`
  frames through the **same** transmit queue. ARQ above is untouched — it still
  tracks, dedups, and retransmits the underlying data packets, providing the
  backstop when a block is lost beyond recovery. A trailing partial block is
  flushed when the queue drains so a paused stream's tail is not stuck below a
  block boundary.
- **Client** (`internal/client/stream_client.go`): a per-stream `fec.Decoder`
  ingests shards routed by StreamID and replays each recovered unit into the
  stream's ARQ via `ReceiveData`. ARQ dedups by sequence number, so a unit that
  also arrived directly is a harmless no-op; a recovered one saves a retransmit.

**Why it helps.** FEC converts loss into redundancy paid *up front* instead of
latency paid *per loss*. With `block=4, parity=12` a block survives losing 12 of
16 shards — i.e. **~75% shard loss** — with no round-trip. ARQ remains the
correctness backstop, so FEC is a pure latency/throughput optimization, never a
reliability risk.

**Validation.** Codec + stream tests prove reconstruction at 75% loss; a
server-side integration test drives the live `feedFECData → flushFEC → popFECShard`
path through a `fec.Decoder` with 50% shard loss; an end-to-end test echoes 64 KB
with FEC forced on through the real binaries.

---

## 3. Loss-triggered (automatic) FEC

**Problem.** Always-on FEC wastes bandwidth on healthy links; manually toggling
it per deployment is impractical. We want FEC that switches on only when a stream
is actually losing packets, and scales its strength to the loss.

**Mechanism — server-autonomous, zero protocol/ARQ change.** The server's
`PushTXPacket` is the single funnel for both `STREAM_DATA` (originals) and
`STREAM_RESEND` (retransmits), so each stream can measure *its own* download loss
from the retransmit rate over a sliding window (64 sends) with no new signaling:

```
loss ≈ retransmits / (originals + retransmits)   (per window, per stream)
```

When loss crosses `FEC_AUTO_LOSS_THRESHOLD`, the stream turns FEC on with parity
= `ParityForLoss(block, loss)`, clamped to `[FEC_PARITY, FEC_AUTO_MAX_PARITY]`.
One or two clean windows relax parity toward the base without flapping. After
three consecutive below-threshold windows, FEC fully disengages and the stream
returns to raw ARQ packets with **zero FEC bandwidth or Reed-Solomon CPU
overhead**. The encoder object is retained only to keep block IDs monotonic if
loss later re-engages FEC; its partial block and queued shards are discarded,
and ARQ remains the delivery backstop. A dequeue/disengage race sends the packet
raw immediately instead of waiting for its retransmission timer.

**Config.** `FEC_AUTO_ENABLED` (default true), `FEC_AUTO_LOSS_THRESHOLD` (0.3),
`FEC_AUTO_MAX_PARITY` (0 → auto-caps at 4× block). `FEC_DOWNLOAD_ENABLED`
(always-on, fixed parity) takes precedence when set.

**Why it helps.** Healthy links stay lean; links that start losing packets
self-protect within ~64 packets, transparently to the client (which already
handles raw data and shards interchangeably). It directly targets the project's
goal of remaining usable at very high loss without operator intervention.

**Caveat.** The loss signal is the retransmit rate, which is a proxy for true
path loss; it reacts at window granularity, not instantaneously.

---

## 4. More transport channels, accepted by the server by default

**Problem.** Carrying everything over TXT is a fingerprint, and answering a
non-TXT query (e.g. `A`) with a TXT record is protocol-incoherent and gets
dropped by strict resolvers. We want the client to be able to *rotate the DNS
record type* it queries, and the server to answer with a matching record type.

**Mechanism.**
- **Query-type rotation (client → server).** The client rotates `QUERY_TYPES`
  (e.g. `["TXT","CNAME","NULL","HTTPS"]`) per query. The tunnel payload always
  rides in the QNAME labels, so the server reads it regardless of record type.
  The server's domain matcher accepts **any** tunnel-transport query type by
  default (`IsTunnelTransportQueryType`), so the client can switch delivery
  method with no server reconfiguration.
- **Response RR-type matching (server → client).**
  `BuildVPNResponsePacketMatchingQuery` picks an answer encoding that matches the
  question:
  - `TXT` → TXT chunks (default; highest capacity over recursive resolvers).
  - `NULL` → the frame verbatim in the answer RDATA
    (`internal/dnsparser/transport_rrchannels.go`).
  - `HTTPS`/`SVCB` → the frame inside a service-binding SvcParam (private key),
    with a root TargetName — looks like an ordinary service record.
  - `A` → IPv4 A-records (`internal/dnsparser/transport_arecord.go`,
    index byte + 3 data bytes/record, reorder-safe, ~766 B cap, opt-in).
  - other types → CNAME target, with automatic fallback to TXT for large frames.
  The client's `ExtractVPNResponseMatching` auto-detects and decodes whichever
  channel was used, so no negotiation is required.

**Why it helps.** It breaks the "all-TXT" fingerprint, lets the client adapt to
resolvers/paths that handle some record types better than others, and keeps the
answer RR-type a legal match for the question (important for resolvers that
validate that). IPv6/AAAA is intentionally not used as a data channel because the
target networks commonly block IPv6.

**Validation.** Round-trip tests for NULL/HTTPS/SVCB/A; an end-to-end test runs
the client rotating `["TXT","CNAME","NULL","HTTPS"]` and echoes 64 KB intact.

---

## 5. Dynamic encryption: server auto-detects the client's method

**Problem.** Pinning one cipher per deployment is brittle; we want a client to
change its encryption method without the server being reconfigured.

**Mechanism.** Methods: 0 None, 1 XOR, 2 ChaCha20, 3/4/5 AES-128/192/256-GCM
(3–5 are AEAD). With `ENCRYPTION_AUTO_DETECT` (default true), the server builds a
codec set and trial-decrypts each inbound frame, **AEAD methods first** (they
authenticate, so they cannot be mis-detected), falling back to the unauthenticated
ciphers. The first codec that yields a valid frame is used.

**Why it helps.** A client can pick a rarer/stronger cipher (or rotate) and the
server simply reads it. AEAD-first ordering avoids false positives from the
unauthenticated ciphers.

---

## 6. Larger session space

The session ID was widened from **uint8 (256)** to **uint16 (65535)** across the
wire header, `SESSION_INIT`/`SESSION_ACCEPT` payloads, the server session store,
and ARQ. This removes the 256-concurrent-session ceiling so a single server can
host far more users — which is why the ARQ/sweep efficiency work in §1 matters.

---

## 7. Adaptive per-group MTU (the core throughput change)

**Problem.** The client measured each resolver's viable MTU but then applied the
**global minimum** across all of them. One slow resolver (small payload limit)
dragged every resolver down to its MTU, wasting throughput on the majority that
could carry much larger packets.

Recall the constraint from §0: a session has **one** MTU. So we cannot simply run
each resolver at its own MTU within one session. The design works *with* that
constraint.

### 7.1 Loss-aware measurement
`MTU_PROBE_SAMPLES > 1` switches probing from "accept if any retry passes" to
**loss-aware**: each candidate MTU is probed K times and accepted only if
measured loss ≤ `MTU_MAX_LOSS`. This yields a real per-resolver loss curve and a
robust MTU edge instead of a brittle single-success edge.

To bound probe cost on large resolver fleets, the sampler is **coarse-then-refine**:
it early-exits a candidate the moment the verdict is locked — once enough
successes make the loss budget unbeatable, or once failures exceed it — instead
of always sending all K probes.

**Loss reporting fix.** Early-exit probing must not make the UI lie. A candidate
can be rejected after the first failed probe when the configured loss budget is
zero; reporting `failures / sampled` made that look like **100% loss** even when
the configured budget was, for example, 1 failure out of 6 probes. The client now
reports `failures / MTU_PROBE_SAMPLES` for loss-aware candidates while keeping the
same early-stop verdict. That preserves fast startup and lets operators see
intermediate values (16.7%, 25%, 40%, ...) instead of only 0%/100%.

**Caveat.** `MTU_PROBE_SAMPLES = 1` intentionally keeps the legacy pass/fail
mode, so it can still only report 0% on pass or 100% on failure. Meaningful loss
percentages require `MTU_PROBE_SAMPLES > 1`.

### 7.2 Throughput-optimal operating point (joint upload+download)
Instead of the global minimum, the client picks the operating point that
maximizes aggregate throughput. For each resolver's own `(upload, download)` as a
candidate floor, it forms the pool that sustains **both** and scores it:

```
score(U, D) = (U + D) × (number of resolvers with upload ≥ U and download ≥ D)
```

The winning `(U, D)` balances per-packet size against resolver count in both
directions: a few slow resolvers cannot throttle the session, **and** a single
fast outlier cannot strand the crowd. (`selectMTUOperatingPoint` in
`internal/client/mtu_cluster.go`.)

### 7.3 Three explicit resolver states: active / reserve / invalid
MTU testing now classifies every resolver into one of three states:

| State | Condition | Role |
|---|---|---|
| **active** | `IsValid && !Backup` | in the data pool; carries traffic |
| **reserve** | `IsValid && Backup` | sustains *less* than the session MTU; held as failover |
| **invalid** | `!IsValid` | failed probing |

Crucially, resolvers that cannot sustain the operating MTU are **not discarded** —
they are kept as **reserves**. The balancer
(`internal/client/balancer.go`) selects primaries during normal operation and
**automatically falls back to reserves only when no primary remains** (one choke
point in `rebuildValidIndices`, so every selection strategy inherits it). A
`[RESOLVER STATES] active=X reserve=Y invalid=Z` summary is logged after testing.

### 7.4 Re-clustering on degradation, with hysteresis
At session (re)establishment, `recomputeMTUOperatingPoint` re-derives the
operating point over the **surviving** resolvers (primary + reserve). If the fast
pool has died, surviving reserves are **promoted at a viable lower MTU** instead
of stranding the session at an MTU nothing left can carry. To avoid thrashing the
session MTU when resolvers flap, a **hysteresis** rule
(`mtuShouldAdoptOperatingPoint`) only changes the MTU when there is no current
point, the current point is *stranded* (no survivor sustains it), or a new point
is *materially* better (> 12.5% larger download MTU). The server honors whatever
MTU the client negotiates in the new `SESSION_INIT`
(`applyMTUFromSessionInit`, validated server-side).

### 7.5 MTU-weighted balancing
A new balancing strategy (`RESOLVER_BALANCING_STRATEGY = 5`) selects active-pool
resolvers with probability proportional to their download MTU, so a resolver that
can carry 4000-byte answers receives ~4× the traffic of one capped at 1000.

**Why all of this helps.** On a realistic mixed fleet (say 40 resolvers at 4000 B
+ 10 at 1000 B), the old behavior ran everyone at 1000 B. The new behavior runs
the session at 4000 B over the 40-resolver pool (≈4× the per-query payload), keeps
the 10 slow ones as reserves, weights traffic toward the fastest resolvers, and —
if those 40 die — automatically drops to 1000 B on the survivors instead of going
dark. It stays **one session per client** (no extra server session pressure),
which is why it scales to the larger session space in §6.

**Caveat.** Re-derivation happens at session (re)establishment (a deliberate
race-free design), so promotion of reserves occurs on the next restart after
primary loss (which a stalled session triggers via inactivity/timeout), not
instantaneously. Hysteresis keeps that bounded and stable.

---

## 8. Caching is a background accelerator, never a gate

**Problem.** Log-based fast-start reused cached per-resolver MTUs to skip the full
scan — but if the user changed their resolver list, new resolvers (absent from
the cache) were silently ignored.

**What changed.** Log-mode start is now **hybrid**: it trusts the cache for
resolvers that have an entry but **always probes any resolver in the current list
that has none** (`scanConnectionsWithoutPreknownMTU`). The cache is written in the
background while running (`appendResolverCacheEntry`) and only *accelerates* known
resolvers at startup; it can never drop a new/changed resolver list. Per-resolver
loss is also persisted (`UPLOSS=/DOWNLOSS=`, backward-compatible) so the UI is
consistent across restarts; resolver tiers are **re-derived** on load (more
correct than persisting a possibly-stale flag).

---

## 9. DPI-resistance & duplication (threat model: passive DPI)

- **Query-type rotation** (§4) breaks the all-TXT fingerprint.
- **Type-matched responses** (§4) keep answers protocol-coherent.
- **Domain-diverse duplication** (`DUPLICATION_PREFER_DISTINCT_DOMAINS`): when a
  packet is duplicated for loss resistance, copies are spread across multiple
  tunnel domains rather than hammering one.
- **Adaptive duplication** (`ADAPTIVE_DUPLICATION`): the client raises the upload
  duplication count toward a target delivery probability based on the measured
  aggregate loss (`ceil(ln(1-target)/ln(lossFrac))`, capped), then hands off to
  FEC on the download side for the heavy-loss regime.

These target a **passive** DPI threat model (pattern/fingerprint observation), not
an active prober.

---

## 10. Transport diversity: DNS-over-TCP/53 fallback

**Problem.** The only data path used to be plain **UDP/53**. Highly restrictive
networks frequently filter, truncate, or hijack UDP/53 while still allowing
TCP/53. (DoH/DoT on 443 are often blocked outright in these environments, so they
are deliberately *not* the chosen fallback.)

**Server.** A DNS-over-TCP listener runs on the **same host:port** as UDP
(`server_tcp.go`), reading RFC 1035 §4.2.2 length-prefixed messages and replying
length-prefixed, routed through the **exact same** transport-agnostic
`safeHandlePacket`. Default on (`TCP_LISTENER_ENABLED`), connection-capped,
load-shedding, graceful shutdown — so all tunnel logic (sessions, FEC, channels,
encryption) is shared with UDP, no duplication.

**Client.** Client-wide transport via `RESOLVER_TRANSPORT = auto | udp | tcp`:
- **`auto` (default)** probes over UDP first; if **zero** resolvers pass MTU
  testing, it flips to TCP and **re-probes the whole fleet over TCP/53**. On a
  UDP-working network TCP is never attempted (zero cost).
- A `queryExchanger` abstraction makes the probe, session-init, and health paths
  transport-agnostic.
- A persistent **per-resolver TCP connection manager** (`tcp_data.go`) serves the
  high-throughput data plane (a handshake-per-query would be far too slow). Each
  connection's read loop feeds the **existing `rxChannel`**, so the inbound path
  (`handleInboundPacket`) treats TCP and UDP responses identically. Lazy dial,
  re-dial on failure, clean shutdown.

**Why it helps.** It changes what is *possible* on UDP-blocked networks, not just
what is faster. Because TCP wraps the whole DNS message, **every response channel
(TXT/CNAME/A/NULL/HTTPS) works unchanged over TCP** — validated end-to-end.

**Survival-path hardening.** The TCP listener now has explicit guardrails for
long-lived fallback use: `TCP_MAX_CONNS_PER_IP`, `TCP_MAX_QUERIES_PER_CONN`,
`TCP_READ_IDLE_TIMEOUT_SECONDS`, and `TCP_WRITE_TIMEOUT_SECONDS`. The defaults
keep persistent DNS-over-TCP useful (`TCP_MAX_QUERIES_PER_CONN = 0` means
unlimited) while bounding connection floods and idle clients. This is important
because TCP/53 is not a secondary convenience path in censored networks; it may
be the only viable transport.

---

## 11. Intelligent rate limiting (redistribution, not a global throttle)

**Problem.** Over-sending to a resolver past its rate limit is self-defeating: it
returns REFUSED/SERVFAIL (wasted round-trips + ARQ retransmits), silently drops
queries (full RTO stalls), or — worst — flags/blocks the client IP. You never had
that throughput; pushing harder only manufactures errors and risk.

**Mechanism.** A per-resolver AIMD pacer (`resolver_pacer.go`). The client already
sees the overload signal (`RCODE != 0` → `trackResolverFailure`, plus timeouts) at
one choke point, `recordResolverHealthEvent`. On a throttle signal the resolver
enters an exponentially-growing **cooldown window** and is deprioritized in
selection (`orderByPacing` at the data-plane spread and control-packet
selection); sustained success additively shrinks the window back to zero.

**Why it doesn't hurt throughput.** It is **redistribution**: the client's total
capacity is the sum of each resolver's sustainable rate; the pacer keeps each
under its own ceiling and shifts overflow to resolvers with headroom, so the
*aggregate* goes up and stays stable. It is **self-gating** (healthy resolvers,
interval 0, are never paced — does nothing on a clean network) and **never idles**
(a paced resolver is still used as a fallback when nothing else is free). It also
lowers the burst fingerprint. Default on (`RESOLVER_RATE_LIMIT_ENABLED`).

---

## 12. QNAME reshaping (anti-fingerprint, desync-proof)

**Problem.** The encoded payload used to ride as a single chain of uniformly
**maximum-length (63-char)** labels under one domain — a classic DNS-tunnel
fingerprint.

**Mechanism.** `QNAME_LABEL_LENGTH` (1..63) controls the target label length;
labels are split shorter and **jittered** per query (`qname_shape.go`), so the
query name looks more like ordinary multi-label subdomains.

**Why it can never desync client and server.** The receiver recovers the payload
by **concatenating all labels and stripping the dots** (server `stripLabelDots`,
client CNAME/A decoders) — label *boundaries are irrelevant to decoding*. The
sender may split however it likes. The single invariant that must hold — the
client's capacity math agreeing with how many labels the builder emits — is
centralized in `qnameLabelCount`, shared by the wire builder, `encodedQNameLen`,
and `CalculateMaxEncodedQNameChars`, so a name can never exceed 253 bytes. The
default (63) is **byte-identical** to the legacy greedy split; reshaping is opt-in.

**Trade-off.** Shorter labels mean more dots, i.e. less payload per query — a
throughput/stealth knob the operator tunes (hence default 63).

---

## 13. How the pieces fit together (hostile-network stack)

```
Transport:                   UDP/53, auto-fallback to DNS-over-TCP/53 when UDP is blocked
Upload  (client → server):   adaptive duplication ── across diverse domains
Both:                        ARQ (ACK/NACK, RTO, retransmit)  ← correctness backstop
Download(server → client):   auto-FEC (Reed-Solomon)  ← reconstruct without round-trip
Path selection:              adaptive per-group MTU + reserves + MTU-weighted balancing
Rate control:                per-resolver AIMD pacing (redistribute off throttling resolvers)
Anti-fingerprint:            query-type rotation + type-matched responses + QNAME reshaping
```

Each layer degrades independently: FEC reduces retransmits, ARQ guarantees
eventual delivery, duplication protects uploads, pacing avoids throttle/IP-blocks,
the MTU/reserve logic keeps the path usable as resolvers come and go, and the TCP
fallback keeps the tunnel alive when UDP/53 is filtered.

---

## 14. Paired operational presets

**Problem.** Operators had to hand-tune many interacting knobs for different
network conditions. That is error-prone: a "fast" client profile can accidentally
request compression or packet behavior the server does not allow, and a
TCP-heavy client can be paired with a server config that is not tuned for
long-lived DNS-over-TCP connections.

**Mechanism.** Both config loaders now understand `CONFIG_PRESET`, with the same
valid names on both sides:

| Preset | Client intent | Server intent |
|---|---|---|
| `default` | Existing explicit config values | Existing explicit config values |
| `speed` | Lower base duplication, MTU-weighted selection, LZ4, loss-aware MTU probing | Higher request/batch headroom, all compression types allowed, auto-FEC threshold tuned for moderate loss |
| `survival` | More duplication, smaller QNAME/EDNS shape, lower MTU ceilings, stricter loss-aware probing | Earlier auto-FEC, duplicated control blocks, longer TCP idle tolerance |
| `tcp-survival` | Force `RESOLVER_TRANSPORT = "tcp"` and keep duplication modest for persistent TCP/53 | Keep TCP listener enabled with higher connection caps and longer idle timeout |

Preset application is **non-destructive**: explicit values in the TOML file (or
CLI overrides) win over preset defaults. That means a bundled preset can be used
as a base profile while still letting an operator override one knob safely.

**Bundled pairs.**

```
client_config.speed.toml        + server_config.speed.toml
client_config.survival.toml     + server_config.survival.toml
client_config.tcp-survival.toml + server_config.tcp-survival.toml
```

The release packagers include these files plus `CONFIG_PRESETS.md`, so the
profiles are available in built artifacts, not only in the source tree.

**Validation.** Config tests cover preset parsing, explicit-value precedence,
CLI/override preset application, and all bundled preset TOML files. The shipped
template test accepts the expected placeholder client-key error but fails if any
preset is malformed before that point.

---

## 15. Validation summary

- **Unit tests** across `fec`, `vpnproto`, `dnsparser`, `udpserver`, `client`,
  `config` — including FEC reconstruction at 75% loss, auto-FEC enable/scale on
  loss, joint operating-point selection, reserve promotion, hysteresis, hybrid
  cache selection, MTU-weighted bias, loss-aware MTU reporting, the transport
  channels, the AIMD pacer (throttle/recover, redistribution ordering), TCP
  framing, config presets, and QNAME-shaping round-trip/bounds.
- **Server-side validation** that the server honors and clamps the client's
  per-session MTU (including a lowered value re-derived after primary-pool loss),
  the DNS-over-TCP framing/pipelining, and TCP connection guardrails.
- **End-to-end tests** (real client + server binaries over loopback), each a
  byte-exact 64 KB echo: baseline; encryption auto-detect; FEC-on download;
  query-type rotation over the new channels (UDP); full tunnel over **TCP/53**;
  **TCP/53 + NULL/HTTPS/CNAME** together; and **reshaped QNAME + TCP/53 + the
  non-TXT channels** stacked.
- **Cross-compilation** verified for linux/amd64, linux/arm64, darwin/arm64,
  windows/amd64, android/arm64.

---

## 16. Config quick reference (new/changed keys)

**Server (`server_config.toml`):**
- `TCP_LISTENER_ENABLED` (true) / `TCP_MAX_CONNS` (2048) — DNS-over-TCP/53 listener.
- `TCP_MAX_CONNS_PER_IP` (128) / `TCP_MAX_QUERIES_PER_CONN` (0) /
  `TCP_READ_IDLE_TIMEOUT_SECONDS` (30.0) / `TCP_WRITE_TIMEOUT_SECONDS` (15.0) —
  TCP/53 survival-path guardrails.
- `CONFIG_PRESET` (`default`, `speed`, `survival`, `tcp-survival`) — paired
  operational profile; explicit TOML/CLI values still win.
- `ENCRYPTION_AUTO_DETECT` (true) — trial-decrypt the client's cipher.
- `A_RECORD_DATA_DELIVERY` (false) — answer A queries with A-record data.
- `FEC_DOWNLOAD_ENABLED` (false) / `FEC_BLOCK_SIZE` (4) / `FEC_PARITY` (4) —
  always-on FEC.
- `FEC_AUTO_ENABLED` (true) / `FEC_AUTO_LOSS_THRESHOLD` (0.3) /
  `FEC_AUTO_MAX_PARITY` (0=auto) — loss-triggered FEC.

**Client (`client_config.toml`):**
- `CONFIG_PRESET` (`default`, `speed`, `survival`, `tcp-survival`) — paired
  operational profile; explicit TOML/CLI values still win.
- `RESOLVER_TRANSPORT` (auto) — `auto` (UDP, fall back to TCP/53 if UDP finds no
  resolvers) | `udp` | `tcp`.
- `RESOLVER_RATE_LIMIT_ENABLED` (true) — per-resolver adaptive pacing.
- `QNAME_LABEL_LENGTH` (63) — QNAME label reshaping (smaller = shorter, jittered
  labels; lower fingerprint, less capacity).
- `DNS_RANDOMIZE_QUERY_ID` (true) — random DNS transaction ID per query instead of
  a sequential counter. Client-only; the server echoes the ID without validating
  it, so no server change is needed.
- `DNS_EDNS_COOKIE` (true) — add an RFC 7873 EDNS Client Cookie to each query's OPT
  record so it looks like a modern stub on the client→resolver leg. The recursive
  resolver terminates EDNS, so the cookie never reaches the server (client-only).
- `DNS_QNAME_CASE_RANDOMIZATION` (false) — DNS 0x20 mixed-case QNAME. The server
  lowercases the name before decoding (`writeLowerASCIILabel` at parse time), so it
  is server-transparent and cannot desync. Modest anti-detection value (does not
  reduce label entropy); opt-in.
- `EDNS_UDP_SIZE` (4096, clamped to [512, 4096]) — advertised requestor UDP payload
  size in the OPT record. Smaller looks more like a modern stub but can cap answer
  size and hurt throughput. Client-only.
- `RESOLVER_IGNORE_INJECTED_NXDOMAIN` (true) — on-path DNS-poisoning hardening. A
  forged NXDOMAIN (no tunnel payload) is treated as injection noise: it does not
  consume the pending query sample, so the genuine authoritative answer is still
  scored as a success, and the resolver is never throttled or disabled for it.
  Genuine unreachability is still caught by the pending sample timing out (a signal
  injection cannot forge). Client-only; zero extra queries/bytes. It actively
  *recovers* throughput under poisoning by keeping working resolvers in the pool.
- `QUERY_TYPES` — DNS record types to rotate (TXT/CNAME/A/NULL/HTTPS/SVCB/…).
- `MTU_PROBE_SAMPLES` (1) / `MTU_MAX_LOSS` (0.0) — loss-aware probing.
- `MTU_ADAPTIVE_GROUPING` (true) / `MTU_GROUP_GAP_RATIO` (0.25) — adaptive MTU.
- `RESOLVER_BALANCING_STRATEGY` — 1 random, 2 round-robin, 3 least-loss,
  4 lowest-latency, **5 MTU-weighted**.
- `DUPLICATION_PREFER_DISTINCT_DOMAINS`, `ADAPTIVE_DUPLICATION`,
  `ADAPTIVE_DUPLICATION_TARGET_DELIVERY`.

---

*All changes keep ARQ as the correctness backstop; every optimization above is
designed to fail safe — if FEC, MTU grouping, or a transport channel does not
help on a given path, the tunnel still delivers via ARQ over the surviving
resolvers.*
</content>
