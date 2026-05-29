package sni

import (
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"time"
)

// FrontResult is one row of a CDN-fronting edge scan. PingMs is the
// time-to-first-byte after the request is sent — the value used to rank edges.
type FrontResult struct {
	IP         string `json:"ip"`
	OK         bool   `json:"ok"`
	TCPms      int    `json:"tcp_ms"`
	TLSms      int    `json:"tls_ms"`
	PingMs     int    `json:"ping_ms"` // TTFB, -1 on failure
	HTTPStatus int    `json:"http_status"`
	Error      string `json:"error"`
}

func ms(t time.Time) int { return int(time.Since(t).Milliseconds()) }

// FrontTest dials a single edge IP, performs a TLS handshake presenting frontSNI
// (which may be empty for no SNI), then sends a HEAD request whose Host header is
// realHost — i.e. the exact domain-fronting path. It measures TCP connect, TLS
// handshake, and time-to-first-byte.
func FrontTest(ip string, port int, frontSNI, realHost string, timeout time.Duration) FrontResult {
	res := FrontResult{IP: ip, TCPms: -1, TLSms: -1, PingMs: -1}
	host := realHost
	if host == "" {
		host = frontSNI
	}
	if host == "" {
		host = ip
	}

	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		res.Error = trunc(err.Error(), 60)
		return res
	}
	defer conn.Close()
	res.TCPms = ms(t0)

	tc := tls.Client(conn, tlsConfig(frontSNI))
	_ = tc.SetDeadline(time.Now().Add(timeout))
	t1 := time.Now()
	if err := tc.Handshake(); err != nil {
		res.Error = trunc(err.Error(), 60)
		return res
	}
	res.TLSms = ms(t1)

	// TLS handshake completing against the front SNI proves this edge is
	// reachable and accepts our fronting setup. The HTTP probe below is just
	// best-effort: many CF-fronted services only respond on their WS/specific
	// path, so HEAD / can hang or return nothing — that's fine.
	res.OK = true
	res.PingMs = res.TLSms

	// Short, independent deadline for the HTTP probe so we don't wait the full
	// connection timeout on workers that ignore HEAD /.
	probeDeadline := 1500 * time.Millisecond
	if d := timeout / 3; d > probeDeadline {
		probeDeadline = d
	}
	_ = tc.SetDeadline(time.Now().Add(probeDeadline))
	req := "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
	t2 := time.Now()
	if _, err := tc.Write([]byte(req)); err != nil {
		return res
	}
	buf := make([]byte, 256)
	n, _ := tc.Read(buf)
	if n > 0 {
		res.PingMs = ms(t2)
		res.HTTPStatus = parseHTTPStatus(string(buf[:n]))
	}
	return res
}

// parseHTTPStatus pulls the numeric code out of an "HTTP/1.1 200 OK" status line.
func parseHTTPStatus(line string) int {
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) >= 2 {
		if code, err := strconv.Atoi(f[1]); err == nil {
			return code
		}
	}
	return 0
}
