package sni

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestRewriteHostVless(t *testing.T) {
	in := "vless://11111111-2222-3333-4444-555555555555@old.example.com:443?security=tls&sni=front.com&type=ws&path=%2Fws#tag"
	got, err := RewriteHost(in, "104.16.0.99")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "@104.16.0.99:443") {
		t.Fatalf("host not swapped: %s", got)
	}
	if !strings.Contains(got, "sni=front.com") || !strings.Contains(got, "type=ws") {
		t.Fatalf("query lost: %s", got)
	}
	// fragment preserved
	if !strings.HasSuffix(got, "#tag") {
		t.Fatalf("fragment lost: %s", got)
	}
	// Re-parsing the rewritten URI must yield the new host.
	p := ParseURI(got)
	if !p.Valid || p.Host != "104.16.0.99" || p.Port != 443 {
		t.Fatalf("re-parse failed: %+v", p)
	}
}

func TestRewriteHostTrojan(t *testing.T) {
	in := "trojan://secret@trojan.example.com:443?sni=front.com&type=tcp"
	got, err := RewriteHost(in, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "@1.2.3.4:443") {
		t.Fatalf("host not swapped: %s", got)
	}
	p := ParseURI(got)
	if p.Password != "secret" || p.SNI != "front.com" {
		t.Fatalf("credentials/SNI lost: %+v", p)
	}
}

func TestRewriteHostVmess(t *testing.T) {
	original := map[string]any{
		"v": "2", "ps": "tag", "add": "old.host.com", "port": "443",
		"id": "11111111-2222-3333-4444-555555555555", "aid": "0",
		"net": "ws", "type": "none", "host": "front.com", "path": "/ws",
		"tls": "tls", "sni": "front.com",
	}
	js, _ := json.Marshal(original)
	in := "vmess://" + base64.StdEncoding.EncodeToString(js)
	got, err := RewriteHost(in, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	p := ParseURI(got)
	if !p.Valid {
		t.Fatalf("re-parse failed: %s", p.Error)
	}
	if p.Host != "9.9.9.9" {
		t.Fatalf("vmess host not swapped: %s", p.Host)
	}
	if p.SNI != "front.com" {
		t.Fatalf("SNI lost: %s", p.SNI)
	}
}

func TestRewriteHostShadowsocksSIP002(t *testing.T) {
	// ss://base64(method:pass)@host:port#tag
	cred := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:mypassword"))
	in := "ss://" + cred + "@old.ss.com:8388#tag"
	got, err := RewriteHost(in, "5.5.5.5")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "@5.5.5.5:8388") {
		t.Fatalf("ss host not swapped: %s", got)
	}
	p := ParseURI(got)
	if p.Host != "5.5.5.5" || p.Method != "aes-256-gcm" || p.Password != "mypassword" {
		t.Fatalf("ss re-parse lost data: %+v", p)
	}
}

func TestRewriteHostShadowsocksLegacy(t *testing.T) {
	// Legacy: ss://base64(method:pass@host:port)
	enc := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret@legacy.ss.com:8388"))
	in := "ss://" + enc + "#tag"
	got, err := RewriteHost(in, "7.7.7.7")
	if err != nil {
		t.Fatal(err)
	}
	p := ParseURI(got)
	if !p.Valid {
		t.Fatalf("re-parse failed: %s", p.Error)
	}
	if p.Host != "7.7.7.7" || p.Password != "secret" {
		t.Fatalf("legacy ss lost data: %+v", p)
	}
}

func TestRewriteHostUnsupported(t *testing.T) {
	_, err := RewriteHost("http://example.com", "1.1.1.1")
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

// TestRewriteHostRealWorldTrojan verifies a user-supplied trojan URI with full
// CDN query parameters (security=tls, sni, allowInsecure, type=ws, host, path)
// and a percent-encoded fragment survives the host swap intact.
func TestRewriteHostRealWorldTrojan(t *testing.T) {
	in := "trojan://lVFPgHdMRXSSLvWO@ua-globalcdn1.xeovo.org:443?security=tls&sni=ua-globalcdn1.xeovo.org&allowInsecure=1&type=ws&host=ua-globalcdn1.xeovo.org&path=%2Fcolcha#UA%20%2F%20Trojan%20%28WS%2BTLS%29"
	got, err := RewriteHost(in, "104.17.134.117")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "@104.17.134.117:443") {
		t.Fatalf("CF IP not in rewritten URI: %s", got)
	}
	for _, must := range []string{
		"security=tls", "sni=ua-globalcdn1.xeovo.org", "allowInsecure=1",
		"type=ws", "host=ua-globalcdn1.xeovo.org", "path=%2Fcolcha",
		"#UA%20%2F%20Trojan%20%28WS%2BTLS%29",
	} {
		if !strings.Contains(got, must) {
			t.Fatalf("missing %q in rewritten URI: %s", must, got)
		}
	}
	// And the rewriter's parser still understands the result.
	p := ParseURI(got)
	if !p.Valid || p.Host != "104.17.134.117" || p.Port != 443 ||
		p.SNI != "ua-globalcdn1.xeovo.org" || p.Password != "lVFPgHdMRXSSLvWO" {
		t.Fatalf("re-parse lost info: %+v", p)
	}
}

func TestOriginalName(t *testing.T) {
	cases := map[string]string{
		"trojan://x@h:443?sni=h#UA%20%2F%20Trojan%20%28WS%2BTLS%29": "UA / Trojan (WS+TLS)",
		"vless://uuid@h:443?sni=h#JP-tokyo":                         "JP-tokyo",
		"ss://YWVzOnB3@h:8388#Mumbai%20VPS":                         "Mumbai VPS",
		"vless://uuid@h:443?sni=h":                                  "", // no fragment
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"ps":"FRA-1","add":"h","port":"443","id":"u","aid":"0","net":"ws"}`)): "FRA-1",
	}
	for in, want := range cases {
		got := OriginalName(in)
		if got != want {
			t.Fatalf("OriginalName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRewriteHostPortName_Annotated(t *testing.T) {
	// Realistic CDN configs flow: host → IP, port → 2053, name → annotated.
	in := "trojan://lVFPgHdMRXSSLvWO@ua-globalcdn1.xeovo.org:443?security=tls&sni=ua-globalcdn1.xeovo.org&type=ws&host=ua-globalcdn1.xeovo.org&path=%2Fcolcha#UA%20%2F%20Trojan%20%28WS%2BTLS%29"
	annotated := "UA / Trojan (WS+TLS) | FRA | 12ms | @EzAccess1"
	out, err := RewriteHostPortName(in, "104.17.134.117", 2053, annotated)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "@104.17.134.117:2053") {
		t.Fatalf("expected host:port swap, got %s", out)
	}
	// SNI / path / host header preserved.
	for _, must := range []string{"sni=ua-globalcdn1.xeovo.org", "host=ua-globalcdn1.xeovo.org", "path=%2Fcolcha"} {
		if !strings.Contains(out, must) {
			t.Fatalf("query param lost: %s missing from %s", must, out)
		}
	}
	// Fragment is the annotated name (URL-encoded).
	want := "#" + url.QueryEscape(annotated)
	if !strings.HasSuffix(out, want) {
		t.Fatalf("annotated fragment missing; got tail %q want %q", out[strings.LastIndex(out, "#"):], want)
	}
	// Round-tripping OriginalName on the output recovers the annotated string.
	if got := OriginalName(out); got != annotated {
		t.Fatalf("OriginalName round-trip: got %q want %q", got, annotated)
	}
}

func TestRewriteHostPortName_VmessPsField(t *testing.T) {
	// vmess stores name in the JSON "ps" field — not in the URL fragment.
	in := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"old","add":"h","port":"443","id":"u","aid":"0","net":"ws","host":"h","path":"/ws","tls":"tls","sni":"h"}`))
	out, err := RewriteHostPortName(in, "9.9.9.9", 2053, "JP-tokyo | NRT | 18ms | @EzAccess1")
	if err != nil {
		t.Fatal(err)
	}
	if got := OriginalName(out); got != "JP-tokyo | NRT | 18ms | @EzAccess1" {
		t.Fatalf("vmess ps not updated: got %q", got)
	}
	p := ParseURI(out)
	if !p.Valid || p.Host != "9.9.9.9" || p.Port != 2053 {
		t.Fatalf("vmess host/port wrong: %+v", p)
	}
}
