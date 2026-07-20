// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// reuseport_unix.go — SO_REUSEPORT UDP listeners.
//
// One socket read by N goroutines serialises on a single kernel receive queue,
// which is the throughput ceiling for a high-packet-rate DNS tunnel long before
// CPU saturates. SO_REUSEPORT lets several sockets bind the same address, and
// the kernel hashes each datagram to one of them, so every reader gets its own
// queue and the contention disappears.
//
// All the sockets share one local address, so a reply written on any of them
// leaves with the same source ip:port. Replying on the socket the request
// arrived on is therefore an affinity choice that also spreads transmit load,
// not a correctness requirement.
// ==============================================================================

//go:build linux || android || darwin || freebsd || netbsd || openbsd || dragonfly

package udpserver

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePortSupported reports whether this build can open SO_REUSEPORT sockets.
const reusePortSupported = true

func listenUDPReusePort(addr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctrlErr error
			if err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					ctrlErr = err
					return
				}
				ctrlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			return ctrlErr
		},
	}

	pc, err := lc.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, err
	}

	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, errReusePortUnsupported
	}
	return conn, nil
}
