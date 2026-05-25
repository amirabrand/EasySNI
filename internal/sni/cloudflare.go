package sni

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// DefaultCloudflareRanges mirrors CloudflareScanner.DEFAULT_RANGES.
var DefaultCloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
	"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
	"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

// ExpandCIDR enumerates up to maxIPs host addresses from a CIDR block.
func ExpandCIDR(cidr string, maxIPs int) []string {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil
	}
	p = p.Masked()
	var ips []string
	addr := p.Addr()
	for i := 0; i < maxIPs; i++ {
		addr = addr.Next()
		if !p.Contains(addr) {
			break
		}
		ips = append(ips, addr.String())
	}
	return ips
}

// ParseIPList accepts lines of single IPs or CIDR blocks (with '#' comments)
// and returns the expanded, de-duplicated list of IPs. Mirrors parse_ip_list.
func ParseIPList(text string) []string {
	var ips []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			ips = append(ips, ExpandCIDR(line, 256)...)
		} else if _, err := netip.ParseAddr(line); err == nil {
			ips = append(ips, line)
		}
	}
	return ips
}

// CFResult is one row of a Cloudflare IP scan.
type CFResult struct {
	IP      string `json:"ip"`
	OK      bool   `json:"ok"`
	Latency int    `json:"latency"` // ms, -1 on failure
	TLSOK   bool   `json:"tls_ok"`
	RelayOK bool   `json:"relay_ok"`
	Error   string `json:"error"`
}

// TestIP dials ip:port, performs a TLS handshake with the given SNI, and sends
// a HEAD request. Mirrors CloudflareScanner.test_ip.
func TestIP(ip string, port int, sniName string, timeout time.Duration) CFResult {
	if sniName == "" {
		sniName = "cloudflare.com"
	}
	res := CFResult{IP: ip, Latency: -1}
	start := time.Now()
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		res.Error = trunc(err.Error(), 40)
		return res
	}
	defer conn.Close()
	res.Latency = int(time.Since(start).Milliseconds())

	tc := tls.Client(conn, tlsConfig(sniName))
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if err := tc.Handshake(); err != nil {
		res.Error = trunc(err.Error(), 40)
		return res
	}
	res.TLSOK = true

	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sniName)
	if _, err := tc.Write([]byte(req)); err != nil {
		res.Error = trunc(err.Error(), 40)
		return res
	}
	buf := make([]byte, 512)
	n, _ := tc.Read(buf)
	res.RelayOK = n > 0
	res.OK = res.RelayOK
	return res
}
