//go:build !linux && !windows

package desync

import (
	"errors"
	"net"
	"runtime"
)

// sendRaw is unavailable on this platform (only Linux raw sockets and
// Windows+WinDivert are supported).
func sendRaw(_ net.IP, _ []byte) error {
	return errors.New("raw segment injection needs Linux root or Windows+WinDivert; host is " + runtime.GOOS)
}
