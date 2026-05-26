package sni

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "edge"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestFrontTest(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{testCert(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
			}(c)
		}
	}()

	host, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)

	res := FrontTest(host, port, "front.example.com", "real.example.net", 3*time.Second)
	if !res.OK {
		t.Fatalf("expected OK, got error %q", res.Error)
	}
	if res.HTTPStatus != 204 {
		t.Fatalf("expected status 204, got %d", res.HTTPStatus)
	}
	if res.TCPms < 0 || res.TLSms < 0 || res.PingMs < 0 {
		t.Fatalf("timings should be set: %+v", res)
	}

	// A closed port should fail cleanly with ping = -1.
	bad := FrontTest("127.0.0.1", 1, "front.example.com", "", 500*time.Millisecond)
	if bad.OK || bad.PingMs != -1 {
		t.Fatalf("expected failure for closed port, got %+v", bad)
	}
}

func TestParseHTTPStatus(t *testing.T) {
	cases := map[string]int{
		"HTTP/1.1 200 OK\r\n":      200,
		"HTTP/2 403 Forbidden\r\n": 403,
		"HTTP/1.1 204 No Content":  204,
		"garbage":                  0,
		"HTTP/1.1 \r\n":            0,
	}
	for in, want := range cases {
		if got := parseHTTPStatus(in); got != want {
			t.Fatalf("parseHTTPStatus(%q) = %d, want %d", in, got, want)
		}
	}
}
