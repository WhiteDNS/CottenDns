// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"sort"
	"time"

	Enums "cottenpickdns-go/internal/enums"
	VpnProto "cottenpickdns-go/internal/vpnproto"
)

func (c *Client) selectTargetConnections(packetType uint8, streamID uint16) []Connection {
	connections, err := c.selectTargetConnectionsForPacket(packetType, streamID)
	if err != nil {
		return nil
	}

	return connections
}

// asyncStreamDispatcher cycles through all active streams using a fair Round-Robin algorithm
// and transmits the highest priority packets to the TX workers, packing control blocks when possible.
func (c *Client) asyncStreamDispatcher(ctx context.Context) {
	c.log.Debugf("Stream Dispatcher started")
	defer c.asyncWG.Done()

	var rrCursor int32 = -1
	var cachedVersion uint64
	var cachedIDs []int32
	var cachedStreams map[uint16]*Stream_client
	idlePoll := c.cfg.DispatcherIdlePollInterval()
	idleTimer := time.NewTimer(idlePoll)
	defer idleTimer.Stop()

	waitForWork := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-c.txSignal:
		case <-idleTimer.C:
		}
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}
		idleTimer.Reset(idlePoll)
		return true
	}

	waitForTxCapacity := func(required int) bool {
		if required <= 0 {
			return true
		}
		for {
			if c.txChannelHasCapacity(required) {
				return true
			}

			select {
			case <-ctx.Done():
				return false
			case <-c.txSpaceSignal:
			case <-idleTimer.C:
			}

			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(idlePoll)
		}
	}

dispatchLoop:
	for {
		currentVersion := c.streamSetVersion.Load()
		if currentVersion != cachedVersion || cachedIDs == nil || cachedStreams == nil {
			c.streamsMu.RLock()
			streamCount := len(c.active_streams)
			ids := make([]int32, 0, streamCount+1)
			streams := make(map[uint16]*Stream_client, streamCount)
			for id, stream := range c.active_streams {
				ids = append(ids, int32(id))
				streams[id] = stream
			}
			c.streamsMu.RUnlock()
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			cachedIDs = ids
			cachedStreams = streams
			cachedVersion = currentVersion
		}

		ids := cachedIDs
		streams := cachedStreams

		if c.orphanQueue != nil && c.orphanQueue.FastSize() > 0 {
			ids = append(ids[:len(ids):len(ids)], -1)
		}

		if len(ids) == 0 {
			if !waitForWork() {
				return
			}
			continue
		}

		selected, peekedItem, selectedStreamID, selectedID := c.selectNextDispatchStream(ids, streams, &rrCursor)

		if selectedID == -2 || peekedItem == nil {
			if !waitForWork() {
				return
			}
			continue
		}

		conns := c.selectTargetConnections(peekedItem.PacketType, selectedStreamID)
		if len(conns) == 0 {
			// No valid connections available for this packet. Don't block the
			// dispatcher — doing so would stall ALL streams until a resolver
			// comes back. Instead, pop and discard non-retriable control packets
			// so the queue doesn't jam, and leave data/resend packets for ARQ
			// retransmission.
			if peekedItem.PacketType != Enums.PACKET_STREAM_DATA && peekedItem.PacketType != Enums.PACKET_STREAM_RESEND {
				if selected != nil {
					if dropped, _, ok := selected.PopNextTXPacket(); ok && dropped != nil {
						selected.ReleaseTXPacket(dropped)
					}
				} else if selectedID == -1 {
					c.orphanQueue.Pop(func(p VpnProto.Packet) uint64 {
						return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
					})
				}
			}
			if !waitForWork() {
				return
			}
			continue dispatchLoop
		}

		if !waitForTxCapacity(1) {
			if ctx.Err() != nil {
				return
			}
			continue dispatchLoop
		}

		var item *clientStreamTXPacket
		var ok bool
		if selected != nil {
			item, _, ok = selected.PopNextTXPacket()
			if !ok || item == nil {
				continue dispatchLoop
			}
		} else {
			p, _, ok := c.orphanQueue.Pop(func(p VpnProto.Packet) uint64 {
				return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
			})
			if !ok {
				continue dispatchLoop
			}
			item = &clientStreamTXPacket{
				PacketType:     p.PacketType,
				SequenceNum:    p.SequenceNum,
				FragmentID:     p.FragmentID,
				TotalFragments: p.TotalFragments,
				Payload:        nil,
			}
		}

		if selected != nil &&
			(item.PacketType == Enums.PACKET_STREAM_DATA || item.PacketType == Enums.PACKET_STREAM_RESEND) &&
			!c.shouldTransmitQueuedStreamPacket(selected, item) {
			selected.ReleaseTXPacket(item)
			continue dispatchLoop
		}

		finalPacketType, finalPayload, wasPacked := c.packControlBlocks(item, selected, selectedID, selectedStreamID, ids, streams)

		c.pingManager.NotifyPacket(finalPacketType, false)

		opts := VpnProto.BuildOptions{
			SessionID:     c.sessionID,
			SessionCookie: c.sessionCookie,
			PacketType:    finalPacketType,
			CompressionType: func() uint8 {
				if wasPacked {
					return c.uploadCompression
				}
				return item.CompressionType
			}(),
			Payload: finalPayload,
		}

		if wasPacked {
			opts.StreamID = 0
		} else {
			opts.StreamID = selectedStreamID
			opts.SequenceNum = item.SequenceNum
			opts.FragmentID = item.FragmentID
			opts.TotalFragments = item.TotalFragments
		}

		task := rawOutboundTask{
			packetType: finalPacketType,
			payload:    finalPayload,
			opts:       opts,
			wasPacked:  wasPacked,
			item:       item,
			selected:   selected,
			conns:      conns,
		}

		select {
		case c.txChannel <- task:
		case <-ctx.Done():
			if !wasPacked && selected != nil {
				selected.ReleaseTXPacket(item)
			}
			return
		}
	}
}

// selectNextDispatchStream performs one fair round-robin scan over the active
// stream IDs (plus the orphan-queue sentinel -1), starting just past *rrCursor,
// and returns the first stream/orphan that has a packet ready to send. It peeks
// (does not pop) the chosen packet and advances *rrCursor to the id following
// the first candidate examined.
//
// A PING on the control stream (id 0) is deferred when any other stream or the
// orphan queue has work, so data/control traffic is not starved by keepalives.
//
// When nothing is ready it returns selectedID == -2 and a nil item. Note: as in
// the original inline loop, `selected` is only assigned on the stream branch and
// is intentionally not cleared when a later orphan pick wins — callers key off
// selectedID, and this preserves the pre-extraction behavior exactly.
func (c *Client) selectNextDispatchStream(
	ids []int32,
	streams map[uint16]*Stream_client,
	rrCursor *int32,
) (selected *Stream_client, peekedItem *clientStreamTXPacket, selectedStreamID uint16, selectedID int32) {
	var peekedOK bool
	selectedID = -2
	rrApplied := false

	startIndex := -1
	for i, id := range ids {
		if id >= *rrCursor {
			startIndex = i
			break
		}
	}
	if startIndex == -1 {
		startIndex = 0
	}

	for i := 0; i < len(ids); i++ {
		idx := (startIndex + i) % len(ids)
		id := ids[idx]

		if id == -1 {
			if c.orphanQueue == nil || c.orphanQueue.FastSize() == 0 {
				continue
			}
			p, _, ok := c.orphanQueue.Peek()
			if !ok {
				continue
			}

			peekedItem = &clientStreamTXPacket{
				PacketType:     p.PacketType,
				SequenceNum:    p.SequenceNum,
				FragmentID:     p.FragmentID,
				TotalFragments: p.TotalFragments,
				Payload:        nil,
			}

			selectedStreamID = p.StreamID
			selectedID = -1
			peekedOK = true
		} else {
			s := streams[uint16(id)]
			if s == nil || s.txQueue == nil {
				continue
			}
			peekedItem, _, peekedOK = s.txQueue.Peek()
			if peekedOK {
				selectedStreamID = uint16(id)
				selectedID = int32(id)
				selected = s
			}
		}

		if peekedOK && peekedItem != nil {
			if !rrApplied {
				*rrCursor = id + 1
				rrApplied = true
			}

			if id == 0 && peekedItem.PacketType == Enums.PACKET_PING {
				hasOtherWork := false
				for _, otherID := range ids {
					if otherID == 0 {
						continue
					}
					if otherID == -1 {
						if c.orphanQueue != nil && c.orphanQueue.FastSize() > 0 {
							hasOtherWork = true
							break
						}
						continue
					}
					os := streams[uint16(otherID)]
					if os != nil && os.txQueue != nil && os.txQueue.FastSize() > 0 {
						hasOtherWork = true
						break
					}
				}
				if hasOtherWork {
					peekedItem = nil
					peekedOK = false
					continue
				}
			}

			break
		}
	}

	return selected, peekedItem, selectedStreamID, selectedID
}

// packControlBlocks attempts to coalesce the selected packet together with other
// pending packable control packets (from the selected stream, the orphan queue,
// and other streams) into a single PACKET_PACKED_CONTROL_BLOCKS frame.
//
// It returns the packet type and payload to actually transmit and whether
// packing occurred. When packing succeeds and the packet came from a real
// stream, the original item is released here (mirroring the inline behavior it
// was extracted from). When the packet is not packable, packing is disabled
// (maxPackedBlocks <= 1), or only the single block could be gathered, the
// original packet type and payload are returned unchanged.
func (c *Client) packControlBlocks(
	item *clientStreamTXPacket,
	selected *Stream_client,
	selectedID int32,
	selectedStreamID uint16,
	ids []int32,
	streams map[uint16]*Stream_client,
) (finalPacketType uint8, finalPayload []byte, wasPacked bool) {
	maxBlocks := c.maxPackedBlocks
	if maxBlocks < 1 {
		maxBlocks = 1
	}

	if !VpnProto.IsPackableControlPacket(item.PacketType, len(item.Payload)) || maxBlocks <= 1 {
		return item.PacketType, item.Payload, false
	}

	payload := make([]byte, 0, maxBlocks*VpnProto.PackedControlBlockSize)
	payload = VpnProto.AppendPackedControlBlock(payload, item.PacketType, selectedStreamID, item.SequenceNum, item.FragmentID, item.TotalFragments)
	blocks := 1

	if selected != nil {
		for blocks < maxBlocks {
			popped, poppedOK := selected.txQueue.PopAnyIf(2, func(p *clientStreamTXPacket) bool {
				return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
			}, func(p *clientStreamTXPacket) uint64 {
				return Enums.PacketIdentityKey(selected.StreamID, p.PacketType, p.SequenceNum, p.FragmentID)
			})
			if !poppedOK {
				break
			}
			selected.NoteTXPacketDequeued(popped)
			payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, selected.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
			blocks++
			selected.ReleaseTXPacket(popped)
		}
	} else if selectedID == -1 {
		for blocks < maxBlocks {
			popped, poppedOK := c.orphanQueue.PopAnyIf(2, func(p VpnProto.Packet) bool {
				return VpnProto.IsPackableControlPacket(p.PacketType, 0)
			}, func(p VpnProto.Packet) uint64 {
				return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
			})
			if !poppedOK {
				break
			}
			payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, popped.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
			blocks++
		}
	}

	if blocks < maxBlocks {
		for _, otherID := range ids {
			if blocks >= maxBlocks {
				break
			}
			if otherID == selectedID {
				continue
			}

			if otherID == -1 {
				for blocks < maxBlocks {
					popped, poppedOK := c.orphanQueue.PopAnyIf(2, func(p VpnProto.Packet) bool {
						return VpnProto.IsPackableControlPacket(p.PacketType, 0)
					}, func(p VpnProto.Packet) uint64 {
						return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
					})
					if !poppedOK {
						break
					}
					payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, popped.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
					blocks++
				}
				continue
			}

			otherStream := streams[uint16(otherID)]
			if otherStream == nil || otherStream.txQueue == nil {
				continue
			}
			for blocks < maxBlocks {
				popped, poppedOK := otherStream.txQueue.PopAnyIf(2, func(p *clientStreamTXPacket) bool {
					return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
				}, func(p *clientStreamTXPacket) uint64 {
					return Enums.PacketIdentityKey(uint16(otherID), p.PacketType, p.SequenceNum, p.FragmentID)
				})
				if !poppedOK {
					break
				}
				otherStream.NoteTXPacketDequeued(popped)
				payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, uint16(otherID), popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
				blocks++
				otherStream.ReleaseTXPacket(popped)
			}
		}
	}

	if blocks > 1 {
		if selected != nil {
			selected.ReleaseTXPacket(item)
		}
		return Enums.PACKET_PACKED_CONTROL_BLOCKS, payload, true
	}

	return item.PacketType, item.Payload, false
}
