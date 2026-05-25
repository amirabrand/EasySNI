package sni

import "testing"

func TestSafePort(t *testing.T) {
	cases := []struct {
		raw string
		def int
		out int
	}{
		{"443", 80, 443},
		{":8080", 80, 8080},
		{"", 443, 443},
		{"abc", 443, 443},
		{"99999", 443, 443}, // out of range
		{"0", 443, 443},
	}
	for _, c := range cases {
		if got := SafePort(c.raw, c.def); got != c.out {
			t.Errorf("SafePort(%q,%d)=%d want %d", c.raw, c.def, got, c.out)
		}
	}
}

func TestParseVLESS(t *testing.T) {
	uri := "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=tls&sni=cdn.example.com&path=/ray"
	p := ParseURI(uri)
	if !p.Valid {
		t.Fatalf("expected valid, err=%q", p.Error)
	}
	if p.Protocol != "vless" || p.Host != "example.com" || p.Port != 443 {
		t.Fatalf("bad parse: %+v", p)
	}
	if p.SNI != "cdn.example.com" || p.Type != "ws" || p.Path != "/ray" || !p.TLS {
		t.Fatalf("bad fields: %+v", p)
	}
	if p.UUID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("bad uuid: %q", p.UUID)
	}
}

func TestParseVLESSDefaults(t *testing.T) {
	p := ParseURI("vless://uuid@host.tld:2053")
	if !p.Valid || p.SNI != "host.tld" || p.Type != "tcp" || p.Path != "/" || p.TLS {
		t.Fatalf("defaults wrong: %+v", p)
	}
}

func TestParseUnknown(t *testing.T) {
	if p := ParseURI("ss://whatever"); p.Valid || p.Error == "" {
		t.Fatalf("expected unknown protocol error, got %+v", p)
	}
	if p := ParseURI("   "); p.Valid || p.Error != "Empty URI" {
		t.Fatalf("expected empty error, got %+v", p)
	}
}

func TestExpandCIDR(t *testing.T) {
	ips := ExpandCIDR("192.0.2.0/30", 256)
	// /30 has hosts .1 and .2 (4 addrs minus network/broadcast); our simple
	// enumerator walks Next() within the prefix and stops at the boundary.
	if len(ips) == 0 {
		t.Fatal("expected some IPs")
	}
	if ips[0] != "192.0.2.1" {
		t.Fatalf("first host = %s want 192.0.2.1", ips[0])
	}
	for _, ip := range ips {
		if ip == "192.0.2.0" {
			t.Fatal("should not include network address")
		}
	}
}

func TestParseIPList(t *testing.T) {
	in := "# comment\n1.1.1.1\n\n192.0.2.0/30\nnot-an-ip\n"
	ips := ParseIPList(in)
	if len(ips) < 2 || ips[0] != "1.1.1.1" {
		t.Fatalf("unexpected list: %v", ips)
	}
}
