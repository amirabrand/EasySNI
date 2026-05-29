package xray

import (
	"encoding/json"
	"os"
	"testing"

	"ezsni/internal/sni"
)

func outboundFor(t *testing.T, uri string) map[string]any {
	t.Helper()
	p := sni.ParseURI(uri)
	if !p.Valid {
		t.Fatalf("parse %q failed: %s", uri, p.Error)
	}
	path, err := buildConfig(p, p.Host, p.Port, "127.0.0.1", 10800)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	defer os.Remove(path)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config not valid JSON: %v", err)
	}
	if len(cfg.Outbounds) != 1 {
		t.Fatalf("expected 1 outbound, got %d", len(cfg.Outbounds))
	}
	return cfg.Outbounds[0]
}

func TestBuildConfigTrojan(t *testing.T) {
	ob := outboundFor(t, "trojan://secretpass@example.com:443?sni=front.com&type=tcp")
	if ob["protocol"] != "trojan" {
		t.Fatalf("protocol = %v", ob["protocol"])
	}
	settings := ob["settings"].(map[string]any)
	servers := settings["servers"].([]any)
	srv := servers[0].(map[string]any)
	if srv["password"] != "secretpass" {
		t.Fatalf("password = %v", srv["password"])
	}
	if srv["address"] != "example.com" {
		t.Fatalf("address = %v", srv["address"])
	}
	if _, ok := ob["streamSettings"]; !ok {
		t.Fatal("trojan should carry streamSettings (TLS)")
	}
}

func TestBuildConfigShadowsocks(t *testing.T) {
	// SIP002: ss://base64(method:password)@host:port
	ob := outboundFor(t, "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#node")
	if ob["protocol"] != "shadowsocks" {
		t.Fatalf("protocol = %v", ob["protocol"])
	}
	settings := ob["settings"].(map[string]any)
	srv := settings["servers"].([]any)[0].(map[string]any)
	if srv["method"] != "aes-256-gcm" {
		t.Fatalf("method = %v", srv["method"])
	}
	if srv["password"] != "secret" {
		t.Fatalf("password = %v", srv["password"])
	}
	if srv["port"].(float64) != 8388 {
		t.Fatalf("port = %v", srv["port"])
	}
	// shadowsocks has its own crypto; no TLS streamSettings by default.
	if _, ok := ob["streamSettings"]; ok {
		t.Fatal("plain shadowsocks should not have streamSettings")
	}
}

func TestBuildConfigVless(t *testing.T) {
	ob := outboundFor(t, "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&sni=x.com&type=ws&path=/ws")
	if ob["protocol"] != "vless" {
		t.Fatalf("protocol = %v", ob["protocol"])
	}
	settings := ob["settings"].(map[string]any)
	vnext := settings["vnext"].([]any)[0].(map[string]any)
	user := vnext["users"].([]any)[0].(map[string]any)
	if user["encryption"] != "none" {
		t.Fatalf("vless user encryption = %v", user["encryption"])
	}
	stream := ob["streamSettings"].(map[string]any)
	if stream["network"] != "ws" {
		t.Fatalf("network = %v", stream["network"])
	}
}
