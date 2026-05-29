package sni

import (
	"encoding/base64"
	"testing"
)

func TestParseTrojan(t *testing.T) {
	p := ParseURI("trojan://pass123@example.com:443?security=tls&sni=front.com&type=ws&path=/x#name")
	if !p.Valid || p.Protocol != "trojan" {
		t.Fatalf("not valid trojan: %+v", p)
	}
	if p.Host != "example.com" || p.Port != 443 || p.Password != "pass123" || p.SNI != "front.com" || p.Type != "ws" || !p.TLS {
		t.Fatalf("trojan fields wrong: %+v", p)
	}
	// security=none disables TLS
	if ParseURI("trojan://p@h.com:443?security=none").TLS {
		t.Fatal("security=none should disable TLS")
	}
}

func TestParseShadowsocksSIP002(t *testing.T) {
	ui := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secretpw"))
	p := ParseURI("ss://" + ui + "@1.2.3.4:8388#name")
	if !p.Valid || p.Protocol != "shadowsocks" {
		t.Fatalf("not valid ss: %+v", p)
	}
	if p.Method != "aes-256-gcm" || p.Password != "secretpw" || p.Host != "1.2.3.4" || p.Port != 8388 {
		t.Fatalf("ss SIP002 fields wrong: %+v", p)
	}
}

func TestParseShadowsocksLegacy(t *testing.T) {
	leg := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@5.6.7.8:443"))
	p := ParseURI("ss://" + leg + "#x")
	if !p.Valid || p.Method != "chacha20-ietf-poly1305" || p.Password != "pw" || p.Host != "5.6.7.8" || p.Port != 443 {
		t.Fatalf("ss legacy fields wrong: %+v", p)
	}
}

func TestParseShadowsocksRawUserinfo(t *testing.T) {
	// some links use url-safe base64 without padding
	ui := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw2"))
	p := ParseURI("ss://" + ui + "@host.net:1234")
	if !p.Valid || p.Method != "aes-128-gcm" || p.Password != "pw2" || p.Port != 1234 {
		t.Fatalf("ss raw userinfo wrong: %+v", p)
	}
}
