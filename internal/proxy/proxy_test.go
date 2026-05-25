package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"splus-suite/internal/desync"
)

// selfSigned makes a throwaway cert for the loopback TLS echo server.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"hcaptcha.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestFragmentedHandshakeEndToEnd proves that fragmenting the ClientHello (and
// attempting fake injection, which fails without privileges and is logged but
// non-fatal) still yields an intact TLS handshake and correct data echo.
func TestFragmentedHandshakeEndToEnd(t *testing.T) {
	cert := selfSigned(t)
	srv, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	_, sport, _ := net.SplitHostPort(srv.Addr().String())
	serverPort, _ := strconv.Atoi(sport)

	dc := desync.DefaultConfig()
	dc.EnableFragment = true
	dc.SNIChunk = 3
	dc.FragmentDelay = time.Millisecond
	dc.Mode = desync.ModeWrongChecksum // raw injection will fail gracefully here

	p := New(nil)
	if err := p.Start(Config{
		ListenHost: "127.0.0.1", ListenPort: 0, // 0 => ephemeral; resolved below
		ConnectIP: "127.0.0.1", ConnectPort: serverPort,
		FakeSNI: "www.google.com", Desync: dc,
	}, Passthrough); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	proxyAddr := p.ln.Addr().String()
	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		ServerName:         "hcaptcha.com",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("TLS handshake through fragmenting proxy failed: %v", err)
	}
	defer conn.Close()

	msg := []byte("ping-through-fragmented-clienthello")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("echo read failed: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q", buf)
	}
}
