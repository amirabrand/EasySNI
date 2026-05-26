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
	"strings"
	"sync"
	"testing"
	"time"

	"ezsni/internal/desync"
)

// TestCopyClientToUpstreamRewritesHost verifies CDN-fronting Host rewriting on
// an HTTP request, and that non-HTTP (TLS-looking) streams pass through.
func TestCopyClientToUpstreamRewritesHost(t *testing.T) {
	// HTTP request: Host must be rewritten.
	cIn, cOut := net.Pipe()
	dst := &syncBuf{}
	go copyClientToUpstream(dst, cIn, "real.example.net")
	req := "GET /path HTTP/1.1\r\nHost: front.cdn.com\r\nUser-Agent: x\r\n\r\nbody"
	go func() { _, _ = cOut.Write([]byte(req)); _ = cOut.Close() }()
	time.Sleep(150 * time.Millisecond)
	got := dst.String()
	if !strings.Contains(got, "Host: real.example.net\r\n") {
		t.Fatalf("Host not rewritten: %q", got)
	}
	if strings.Contains(got, "front.cdn.com") {
		t.Fatalf("original Host leaked: %q", got)
	}
	if !strings.Contains(got, "GET /path HTTP/1.1") || !strings.Contains(got, "body") {
		t.Fatalf("request mangled: %q", got)
	}

	// Non-HTTP (TLS record) must be relayed unchanged.
	c2In, c2Out := net.Pipe()
	dst2 := &syncBuf{}
	go copyClientToUpstream(dst2, c2In, "real.example.net")
	tlsBytes := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x02, 0x03}
	go func() { _, _ = c2Out.Write(tlsBytes); _ = c2Out.Close() }()
	time.Sleep(150 * time.Millisecond)
	if dst2.String() != string(tlsBytes) {
		t.Fatalf("TLS stream altered: %x", dst2.String())
	}
}

func TestPickSNIRotates(t *testing.T) {
	c := &Config{SNIList: []string{"a.com", "b.com", "c.com"}}
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		s := c.pickSNI()
		if s != "a.com" && s != "b.com" && s != "c.com" {
			t.Fatalf("unexpected SNI %q", s)
		}
		seen[s] = true
	}
	if len(seen) < 2 {
		t.Fatalf("rotation not happening, only saw %v", seen)
	}
	// Falls back to FakeSNI when the list is empty.
	c2 := &Config{FakeSNI: "only.com"}
	if c2.pickSNI() != "only.com" {
		t.Fatal("empty list should use FakeSNI")
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
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
