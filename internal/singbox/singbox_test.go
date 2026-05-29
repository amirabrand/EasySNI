package singbox

import (
	"encoding/json"
	"os"
	"testing"
)

func readCfg(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("config is not valid JSON: %v\n%s", err, b)
	}
	return m
}

func firstOutbound(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	obs, ok := cfg["outbounds"].([]any)
	if !ok || len(obs) == 0 {
		t.Fatal("no outbounds")
	}
	return obs[0].(map[string]any)
}

func TestBuildConfigTUN_Vless(t *testing.T) {
	uri := "vless://90cd4a77-141a-43c9-991b-08263cfe9c10@104.17.1.1:443?security=tls&sni=ex.workers.dev&type=ws&host=ex.workers.dev&path=%2F%3Fed%3D2560#node"
	path, err := BuildConfig(uri, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	cfg := readCfg(t, path)

	// TUN inbound present with auto_route.
	ins := cfg["inbounds"].([]any)
	in := ins[0].(map[string]any)
	if in["type"] != "tun" || in["auto_route"] != true {
		t.Fatalf("expected tun inbound with auto_route, got %+v", in)
	}

	ob := firstOutbound(t, cfg)
	if ob["type"] != "vless" || ob["uuid"] != "90cd4a77-141a-43c9-991b-08263cfe9c10" {
		t.Fatalf("vless outbound wrong: %+v", ob)
	}
	if ob["server"] != "104.17.1.1" {
		t.Fatalf("server wrong: %v", ob["server"])
	}
	tls, ok := ob["tls"].(map[string]any)
	if !ok || tls["server_name"] != "ex.workers.dev" || tls["enabled"] != true {
		t.Fatalf("tls block wrong: %+v", ob["tls"])
	}
	tr, ok := ob["transport"].(map[string]any)
	if !ok || tr["type"] != "ws" {
		t.Fatalf("ws transport missing: %+v", ob["transport"])
	}
	hdrs := tr["headers"].(map[string]any)
	if hdrs["Host"] != "ex.workers.dev" {
		t.Fatalf("ws Host header wrong: %+v", hdrs)
	}
}

func TestBuildConfigSOCKS_Trojan(t *testing.T) {
	uri := "trojan://secret@host.example:443?security=tls&sni=host.example&type=ws&path=%2Fpath#t"
	path, err := BuildConfig(uri, false, 2080)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	cfg := readCfg(t, path)
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["type"] != "socks" {
		t.Fatalf("expected socks inbound, got %v", in["type"])
	}
	if int(in["listen_port"].(float64)) != 2080 {
		t.Fatalf("socks port wrong: %v", in["listen_port"])
	}
	ob := firstOutbound(t, cfg)
	if ob["type"] != "trojan" || ob["password"] != "secret" {
		t.Fatalf("trojan outbound wrong: %+v", ob)
	}
}

func TestBuildConfigShadowsocks_NoTLS(t *testing.T) {
	// ss must not carry tls/transport blocks.
	uri := "ss://YWVzLTI1Ni1nY206cGFzcw@host.example:8388#s"
	path, err := BuildConfig(uri, false, 2080)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	cfg := readCfg(t, path)
	ob := firstOutbound(t, cfg)
	if ob["type"] != "shadowsocks" {
		t.Fatalf("expected shadowsocks, got %v", ob["type"])
	}
	if _, hasTLS := ob["tls"]; hasTLS {
		t.Fatal("shadowsocks outbound should not have a tls block")
	}
	if _, hasTr := ob["transport"]; hasTr {
		t.Fatal("shadowsocks outbound should not have a transport block")
	}
}

func TestBuildConfigInvalid(t *testing.T) {
	if _, err := BuildConfig("not-a-uri", true, 0); err == nil {
		t.Fatal("expected error for invalid URI")
	}
}
