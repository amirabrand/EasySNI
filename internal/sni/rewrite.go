package sni

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// RewriteHost returns the share URI with its server host swapped to newHost,
// keeping the original port. See RewriteHostPort for swapping both.
func RewriteHost(uri, newHost string) (string, error) {
	return RewriteHostPort(uri, newHost, 0)
}

// RewriteHostPort swaps the server host and (when newPort > 0) the port too.
// It preserves credentials, query/fragment, SNI/path/tag, and protocol.
// Supports vless://, trojan://, vmess:// (base64-JSON), and ss:// (SIP002 + legacy).
func RewriteHostPort(uri, newHost string, newPort int) (string, error) {
	newHost = strings.TrimSpace(newHost)
	if newHost == "" {
		return uri, errors.New("empty newHost")
	}
	// portOrKeep picks the new port if non-zero, otherwise the supplied original.
	portOrKeep := func(orig string) string {
		if newPort > 0 {
			return strconv.Itoa(newPort)
		}
		return orig
	}
	switch {
	case strings.HasPrefix(uri, "vless://"),
		strings.HasPrefix(uri, "trojan://"):
		u, err := url.Parse(uri)
		if err != nil {
			return uri, err
		}
		port := portOrKeep(u.Port())
		u.Host = newHost
		if port != "" {
			u.Host = net.JoinHostPort(newHost, port)
		}
		return u.String(), nil

	case strings.HasPrefix(uri, "vmess://"):
		payload := strings.TrimPrefix(uri, "vmess://")
		frag := ""
		if i := strings.Index(payload, "#"); i >= 0 {
			frag = payload[i:]
			payload = payload[:i]
		}
		decoded, ok := decodeB64Loose(payload)
		if !ok {
			return uri, errors.New("vmess: bad base64")
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(decoded), &m); err != nil {
			return uri, err
		}
		m["add"] = newHost
		if newPort > 0 {
			m["port"] = strconv.Itoa(newPort)
		}
		out, err := json.Marshal(m)
		if err != nil {
			return uri, err
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(out) + frag, nil

	case strings.HasPrefix(uri, "ss://"):
		if u, err := url.Parse(uri); err == nil && u.User != nil && u.Host != "" {
			port := portOrKeep(u.Port())
			u.Host = newHost
			if port != "" {
				u.Host = net.JoinHostPort(newHost, port)
			}
			return u.String(), nil
		}
		rest := strings.TrimPrefix(uri, "ss://")
		tag := ""
		if i := strings.Index(rest, "#"); i >= 0 {
			tag = rest[i:]
			rest = rest[:i]
		}
		decoded, ok := decodeB64Loose(rest)
		if !ok {
			return uri, errors.New("ss: bad base64")
		}
		at := strings.LastIndex(decoded, "@")
		if at < 0 {
			return uri, errors.New("ss: legacy format missing @")
		}
		methodPass := decoded[:at]
		hostport := decoded[at+1:]
		origPort := ""
		if _, p, err := net.SplitHostPort(hostport); err == nil {
			origPort = p
		}
		port := portOrKeep(origPort)
		newHP := newHost
		if port != "" {
			newHP = net.JoinHostPort(newHost, port)
		}
		re := methodPass + "@" + newHP
		return "ss://" + base64.StdEncoding.EncodeToString([]byte(re)) + tag, nil
	}
	return uri, errors.New("unsupported URI for host rewrite")
}

// PortOf returns the port from a parsed URI, defaulting to 443 when absent.
func PortOf(p ParsedURI) int {
	if p.Port > 0 {
		return p.Port
	}
	return 443
}

// OriginalName returns the display name embedded in a share URI — the URL
// fragment for vless/trojan/ss, or the "ps" JSON field for vmess. Returns ""
// when no name is present.
func OriginalName(uri string) string {
	switch {
	case strings.HasPrefix(uri, "vless://"),
		strings.HasPrefix(uri, "trojan://"),
		strings.HasPrefix(uri, "ss://"):
		if i := strings.Index(uri, "#"); i >= 0 {
			if dec, err := url.QueryUnescape(uri[i+1:]); err == nil {
				return dec
			}
			return uri[i+1:]
		}
	case strings.HasPrefix(uri, "vmess://"):
		payload := strings.TrimPrefix(uri, "vmess://")
		if i := strings.Index(payload, "#"); i >= 0 {
			payload = payload[:i]
		}
		if decoded, ok := decodeB64Loose(payload); ok {
			var m map[string]any
			if json.Unmarshal([]byte(decoded), &m) == nil {
				if s, ok := m["ps"].(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

// RewriteHostPortName combines RewriteHostPort with a custom display name.
// Empty newName keeps whatever the URI already had.
func RewriteHostPortName(uri, newHost string, newPort int, newName string) (string, error) {
	out, err := RewriteHostPort(uri, newHost, newPort)
	if err != nil || newName == "" {
		return out, err
	}
	switch {
	case strings.HasPrefix(out, "vless://"),
		strings.HasPrefix(out, "trojan://"),
		strings.HasPrefix(out, "ss://"):
		// Drop any existing fragment and append the new one (URL-encoded).
		if i := strings.Index(out, "#"); i >= 0 {
			out = out[:i]
		}
		return out + "#" + url.QueryEscape(newName), nil
	case strings.HasPrefix(out, "vmess://"):
		// vmess stores the name as JSON field "ps"; re-encode after edit.
		payload := strings.TrimPrefix(out, "vmess://")
		frag := ""
		if i := strings.Index(payload, "#"); i >= 0 {
			frag = payload[i:]
			payload = payload[:i]
		}
		decoded, ok := decodeB64Loose(payload)
		if !ok {
			return out, nil
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(decoded), &m); err != nil {
			return out, nil
		}
		m["ps"] = newName
		buf, err := json.Marshal(m)
		if err != nil {
			return out, nil
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(buf) + frag, nil
	}
	return out, nil
}

// _ keeps strconv used even when downstream callers drop it.
var _ = strconv.Itoa
