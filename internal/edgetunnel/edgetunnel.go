// Package edgetunnel builds client share links for an edgetunnel
// (Cloudflare Workers/Pages VLESS-over-WebSocket) deployment, matching the
// cmliu/edgetunnel layout: VLESS, WS transport, TLS on Cloudflare HTTPS ports,
// early-data path, and an optional clean edge IP to dial while keeping the
// worker domain as SNI + Host.
package edgetunnel

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// CloudflareTLSPorts are the HTTPS ports Cloudflare terminates TLS on.
var CloudflareTLSPorts = []int{443, 2053, 2083, 2087, 2096, 8443}

// CloudflarePlainPorts are the HTTP ports (no TLS) Cloudflare serves on.
var CloudflarePlainPorts = []int{80, 8080, 8880, 2052, 2082, 2086, 2095}

// GenUUID returns a random RFC-4122 v4 UUID.
func GenUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Options configures config generation.
type Options struct {
	UUID    string // VLESS UUID (required)
	Host    string // worker/pages domain — used as SNI and WS Host (required)
	Address string // dial target; default = Host. Use a clean CF IP/domain here.
	Path    string // WS path; default "/?ed=2560"
	Name    string // base node name; default = Host
	Ports   []int  // ports to emit; default = CloudflareTLSPorts
}

// Build returns one VLESS share link per requested port.
func Build(opts Options) ([]string, error) {
	if strings.TrimSpace(opts.UUID) == "" {
		return nil, fmt.Errorf("UUID is required")
	}
	if strings.TrimSpace(opts.Host) == "" {
		return nil, fmt.Errorf("worker host (domain) is required")
	}
	addr := strings.TrimSpace(opts.Address)
	if addr == "" {
		addr = opts.Host
	}
	path := opts.Path
	if strings.TrimSpace(path) == "" {
		path = "/?ed=2560"
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = opts.Host
	}
	ports := opts.Ports
	if len(ports) == 0 {
		ports = CloudflareTLSPorts
	}

	plain := map[int]bool{}
	for _, p := range CloudflarePlainPorts {
		plain[p] = true
	}

	out := make([]string, 0, len(ports))
	for _, port := range ports {
		q := url.Values{}
		q.Set("encryption", "none")
		q.Set("type", "ws")
		q.Set("host", opts.Host)
		q.Set("path", path)
		if plain[port] {
			q.Set("security", "none")
		} else {
			q.Set("security", "tls")
			q.Set("sni", opts.Host)
			q.Set("fp", "randomized")
			q.Set("alpn", "http/1.1")
		}
		label := fmt.Sprintf("%s | %d | @EzAccess1", name, port)
		link := "vless://" + opts.UUID + "@" + net.JoinHostPort(addr, strconv.Itoa(port)) +
			"?" + q.Encode() + "#" + url.QueryEscape(label)
		out = append(out, link)
	}
	return out, nil
}
