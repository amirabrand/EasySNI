//go:build windows

package desync

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"unsafe"
)

// Windows raw injection via WinDivert. WinDivert.dll must be reachable (place it
// next to the executable) and the app must run as Administrator so the driver
// (WinDivert64.sys) can be installed/started. We open a single write-only
// handle and inject crafted IPv4+TCP segments outbound.
//
// NOTE: this path is compiled for Windows but cannot be exercised in the build
// sandbox (no Windows, no WinDivert). It follows the documented WinDivert v2
// API; if a call signature ever changes, it is isolated to this file.

const (
	winDivertLayerNetwork  = 0
	winDivertFlagWriteOnly = 0x0008 // SEND_ONLY: handle may only inject
	addrOutboundBit        = 1 << 17
)

var (
	wdOnce   sync.Once
	wdDLL    *syscall.LazyDLL
	wdOpen   *syscall.LazyProc
	wdSend   *syscall.LazyProc
	iphlp    *syscall.LazyDLL
	getBestI *syscall.LazyProc

	wdMu     sync.Mutex
	wdHandle uintptr // 0 = not open
)

func wdLoad() {
	wdDLL = syscall.NewLazyDLL("WinDivert.dll")
	wdOpen = wdDLL.NewProc("WinDivertOpen")
	wdSend = wdDLL.NewProc("WinDivertSend")
	iphlp = syscall.NewLazyDLL("iphlpapi.dll")
	getBestI = iphlp.NewProc("GetBestInterface")
}

const invalidHandle = ^uintptr(0)

func wdEnsureHandle() error {
	wdOnce.Do(wdLoad)
	if err := wdDLL.Load(); err != nil {
		return fmt.Errorf("WinDivert.dll not found — place it next to the app: %v", err)
	}
	wdMu.Lock()
	defer wdMu.Unlock()
	if wdHandle != 0 && wdHandle != invalidHandle {
		return nil
	}
	filter, _ := syscall.BytePtrFromString("false") // capture nothing; inject only
	h, _, callErr := wdOpen.Call(
		uintptr(unsafe.Pointer(filter)),
		uintptr(winDivertLayerNetwork),
		uintptr(0), // priority
		uintptr(winDivertFlagWriteOnly),
	)
	if h == invalidHandle || h == 0 {
		return fmt.Errorf("WinDivertOpen failed (%v) — run as Administrator and ensure WinDivert64.sys is present", callErr)
	}
	wdHandle = h
	return nil
}

// bestInterface returns the outbound interface index for dst (best effort).
func bestInterface(dst net.IP) uint32 {
	d4 := dst.To4()
	if d4 == nil {
		return 0
	}
	// IPAddr DWORD is the in_addr in memory order (a,b,c,d) -> LE integer.
	addr := uint32(d4[0]) | uint32(d4[1])<<8 | uint32(d4[2])<<16 | uint32(d4[3])<<24
	var idx uint32
	ret, _, _ := getBestI.Call(uintptr(addr), uintptr(unsafe.Pointer(&idx)))
	if ret != 0 { // non-NO_ERROR
		return 0
	}
	return idx
}

// sendRaw injects a pre-built IPv4+TCP segment outbound via WinDivert.
func sendRaw(dst net.IP, seg []byte) error {
	if len(seg) == 0 {
		return nil
	}
	if err := wdEnsureHandle(); err != nil {
		return err
	}
	// WINDIVERT_ADDRESS is 80 bytes: set Outbound flag + the interface index.
	var addr [80]byte
	binary.LittleEndian.PutUint32(addr[8:12], addrOutboundBit) // Layer=0, Outbound=1
	binary.LittleEndian.PutUint32(addr[16:20], bestInterface(dst))

	var sendLen uint32
	wdMu.Lock()
	h := wdHandle
	wdMu.Unlock()
	ret, _, callErr := wdSend.Call(
		h,
		uintptr(unsafe.Pointer(&seg[0])),
		uintptr(uint32(len(seg))),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&addr[0])),
	)
	if ret == 0 {
		return fmt.Errorf("WinDivertSend failed (%v)", callErr)
	}
	return nil
}
