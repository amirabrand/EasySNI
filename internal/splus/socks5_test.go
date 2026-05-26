package splus

import (
	"net"
	"testing"
	"time"
)

// drive runs socks5Negotiate on one end of a pipe with the given greeting and
// returns the negotiation error plus whatever bytes the server wrote.
func drive(t *testing.T, greeting []byte, user, pass string, clientAuth []byte) (error, []byte) {
	t.Helper()
	srv, cli := net.Pipe()
	errc := make(chan error, 1)
	go func() { errc <- socks5Negotiate(srv, greeting, user, pass); srv.Close() }()

	out := make([]byte, 0, 16)
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 8)
		for {
			_ = cli.SetReadDeadline(time.Now().Add(time.Second))
			n, err := cli.Read(buf)
			if n > 0 {
				out = append(out, buf[:n]...)
			}
			// After we receive the method-select reply, send auth (if any).
			if clientAuth != nil && len(out) >= 2 {
				_, _ = cli.Write(clientAuth)
				clientAuth = nil
			}
			if err != nil {
				break
			}
		}
		close(done)
	}()

	err := <-errc
	_ = cli.Close()
	<-done
	return err, out
}

func TestSocks5NoAuth(t *testing.T) {
	// greeting: VER=5, NMETHODS=1, METHOD=0 (no-auth)
	err, out := drive(t, []byte{5, 1, 0}, "", "", nil)
	if err != nil {
		t.Fatalf("no-auth negotiate failed: %v", err)
	}
	if len(out) < 2 || out[0] != 5 || out[1] != 0 {
		t.Fatalf("expected method-select 05 00, got %x", out)
	}
}

func TestSocks5AuthSuccess(t *testing.T) {
	// client offers user/pass (0x02); then sends correct creds.
	auth := []byte{0x01, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'}
	err, out := drive(t, []byte{5, 1, 0x02}, "user", "pass", auth)
	if err != nil {
		t.Fatalf("auth should succeed: %v", err)
	}
	// expect 05 02 (method select) then 01 00 (auth success)
	if len(out) < 4 || out[0] != 5 || out[1] != 0x02 || out[2] != 0x01 || out[3] != 0x00 {
		t.Fatalf("unexpected auth bytes: %x", out)
	}
}

func TestSocks5AuthBadCreds(t *testing.T) {
	auth := []byte{0x01, 4, 'u', 's', 'e', 'r', 3, 'b', 'a', 'd'}
	err, out := drive(t, []byte{5, 1, 0x02}, "user", "pass", auth)
	if err == nil {
		t.Fatal("auth should fail with wrong password")
	}
	if len(out) < 4 || out[3] != 0x01 {
		t.Fatalf("expected auth failure byte 01, got %x", out)
	}
}

func TestSocks5AuthRequiredButNotOffered(t *testing.T) {
	// server requires auth, client only offers no-auth (0x00)
	err, out := drive(t, []byte{5, 1, 0x00}, "user", "pass", nil)
	if err == nil {
		t.Fatal("should reject when client lacks user/pass method")
	}
	if len(out) < 2 || out[1] != 0xff {
		t.Fatalf("expected no-acceptable-methods 05 ff, got %x", out)
	}
}
