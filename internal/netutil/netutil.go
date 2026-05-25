// Package netutil provides small network helpers used by the control panel:
// a TCP port reachability check and local LAN address enumeration (for the
// "LAN sharing" feature in the SNI Tunnel tab).
package netutil

import (
	"net"
	"strconv"
	"time"
)

// PortResult reports whether a TCP port accepted a connection.
type PortResult struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Latency int    `json:"latency"` // ms, -1 on failure
	Error   string `json:"error"`
}

// CheckPort dials host:port and reports reachability.
func CheckPort(host string, port int, timeout time.Duration) PortResult {
	r := PortResult{Host: host, Port: port, Latency: -1}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	_ = conn.Close()
	r.Open = true
	r.Latency = int(time.Since(start).Milliseconds())
	return r
}

// LANAddrs returns the machine's non-loopback IPv4 addresses, which a user can
// hand to other devices when LAN sharing is enabled.
func LANAddrs() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				out = append(out, v4.String())
			}
		}
	}
	return out
}
