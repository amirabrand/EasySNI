//go:build windows

package tun2socks

import (
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Windows transparent-routing helper. After tun2socks creates the "wintun"
// adapter we give it an address, point the system default route at it (using
// the 0/1 + 128/1 split so the original default route survives for the
// excluded host routes), and add host routes for the proxy/bridge IPs via the
// physical gateway so those connections don't loop back into the tunnel.
//
// All of this needs Administrator rights; every command is best-effort and
// logged, never fatal. Cannot be exercised in the Linux build sandbox.

const (
	tunAdapter = "wintun"
	tunAddr    = "172.19.0.2"
	tunMask    = "255.255.255.0"
	tunGW      = "172.19.0.1"
)

var (
	routeMu     sync.Mutex
	addedHosts  []string
	routesUp    bool
	savedGWNote string
)

func runHidden(name string, args ...string) (string, error) {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := c.CombinedOutput()
	return string(out), err
}

// defaultGateway returns the current IPv4 default gateway (next hop) before we
// override routing, so we can keep proxy/bridge traffic on the real link.
func defaultGateway() string {
	out, _ := runHidden("powershell", "-NoProfile", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop")
	return strings.TrimSpace(out)
}

func tunRoutesUp(log func(string, string), excludes []string) {
	routeMu.Lock()
	defer routeMu.Unlock()
	if routesUp {
		return
	}
	// wait for the wintun adapter to appear (up to ~8s)
	ok := false
	for i := 0; i < 16; i++ {
		out, _ := runHidden("netsh", "interface", "ipv4", "show", "interfaces")
		if strings.Contains(strings.ToLower(out), tunAdapter) {
			ok = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !ok {
		log("TUN adapter '"+tunAdapter+"' not visible yet — if traffic doesn't flow, run as Administrator.", "WARN")
	}
	gw := defaultGateway()
	savedGWNote = gw
	// keep proxy/bridge connections on the physical link (avoid tunnel loop)
	if gw != "" {
		for _, ip := range excludes {
			ip = strings.TrimSpace(ip)
			if ip == "" || strings.HasPrefix(ip, "127.") || strings.Contains(ip, ":") {
				continue // skip loopback and IPv6 (route syntax differs)
			}
			if _, err := runHidden("route", "add", ip, "mask", "255.255.255.255", gw, "metric", "1"); err == nil {
				addedHosts = append(addedHosts, ip)
			}
		}
	}
	// give the adapter an address + DNS
	_, _ = runHidden("netsh", "interface", "ip", "set", "address", "name="+tunAdapter, "static", tunAddr, tunMask)
	_, _ = runHidden("netsh", "interface", "ip", "set", "dns", "name="+tunAdapter, "static", "1.1.1.1")
	// split-default through the tunnel gateway
	_, _ = runHidden("route", "add", "0.0.0.0", "mask", "128.0.0.0", tunGW, "metric", "1")
	_, _ = runHidden("route", "add", "128.0.0.0", "mask", "128.0.0.0", tunGW, "metric", "1")
	routesUp = true
	msg := "System routing sent through the TUN adapter."
	if gw != "" {
		msg += " Proxy/bridge IPs kept on gateway " + gw + " to avoid loops."
	}
	msg += " (Administrator required.)"
	log(msg, "OK")
}

func tunRoutesDown() {
	routeMu.Lock()
	defer routeMu.Unlock()
	if !routesUp {
		return
	}
	_, _ = runHidden("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
	_, _ = runHidden("route", "delete", "128.0.0.0", "mask", "128.0.0.0")
	for _, ip := range addedHosts {
		_, _ = runHidden("route", "delete", ip)
	}
	addedHosts = nil
	routesUp = false
}
