//go:build windows

// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================
package client

import "syscall"

func isConnBrokenErrno(errno syscall.Errno) bool {
	switch errno {
	case syscall.WSAECONNABORTED, syscall.WSAECONNRESET:
		return true
	}
	return false
}
