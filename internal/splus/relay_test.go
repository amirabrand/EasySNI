package splus

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"splus-suite/internal/protocol"
)

// fakeTransport is an in-order, in-memory stand-in for the LiveKit transport.
// Send delivers to the peer's inbox; Connect starts the peer's delivery loop.
type fakeTransport struct {
	in    chan []byte
	peer  *fakeTransport
	onMsg func([]byte)
}

func newFakePair() (*fakeTransport, *fakeTransport) {
	a := &fakeTransport{in: make(chan []byte, 1024)}
	b := &fakeTransport{in: make(chan []byte, 1024)}
	a.peer, b.peer = b, a
	return a, b
}

func (f *fakeTransport) SetOnMessage(fn func([]byte)) { f.onMsg = fn }
func (f *fakeTransport) Send(data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	f.peer.in <- cp
	return nil
}
func (f *fakeTransport) Connect() error {
	go func() {
		for m := range f.in {
			if f.onMsg != nil {
				f.onMsg(m)
			}
		}
	}()
	return nil
}
func (f *fakeTransport) Close() error            { return nil }
func (f *fakeTransport) Stats() (uint64, uint64) { return 0, 0 }

// startEcho starts a TCP echo server and returns its address.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// socksConnect performs a SOCKS5 no-auth CONNECT to host:port and returns the
// established connection (ready for application data).
func socksConnect(t *testing.T, proxyAddr, host string, port int) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	// greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil || resp[0] != 5 || resp[1] != 0 {
		t.Fatalf("bad method selection: %v err=%v", resp, err)
	}
	// request: CONNECT domain host:port
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, []byte(host)...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("connect failed, reply=%v", reply)
	}
	return c
}

func TestTunnelEndToEnd(t *testing.T) {
	echoAddr := startEcho(t)
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)

	// Wire two relays over a fake transport pair.
	serverTr, clientTr := newFakePair()

	srv := NewServerRelay(serverTr, nil)
	serverTr.SetOnMessage(func(raw []byte) {
		if m, ok := protocol.Decode(raw); ok {
			srv.Handle(m)
		}
	})
	cli := NewClientRelay(clientTr, nil)
	clientTr.SetOnMessage(func(raw []byte) {
		if m, ok := protocol.Decode(raw); ok {
			cli.Handle(m)
		}
	})
	_ = serverTr.Connect()
	_ = clientTr.Connect()

	socks := NewSocksServer(cli, nil)
	if err := socks.Start("127.0.0.1", 0); err != nil {
		t.Fatal(err)
	}
	defer socks.Stop()

	conn := socksConnect(t, socks.Addr().String(), echoHost, echoPort)
	defer conn.Close()

	payload := []byte("hello-through-the-tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
}

func TestTunnelConnectFailure(t *testing.T) {
	serverTr, clientTr := newFakePair()
	srv := NewServerRelay(serverTr, nil)
	serverTr.SetOnMessage(func(raw []byte) {
		if m, ok := protocol.Decode(raw); ok {
			srv.Handle(m)
		}
	})
	cli := NewClientRelay(clientTr, nil)
	clientTr.SetOnMessage(func(raw []byte) {
		if m, ok := protocol.Decode(raw); ok {
			cli.Handle(m)
		}
	})
	_ = serverTr.Connect()
	_ = clientTr.Connect()

	socks := NewSocksServer(cli, nil)
	if err := socks.Start("127.0.0.1", 0); err != nil {
		t.Fatal(err)
	}
	defer socks.Stop()

	// Connect through SOCKS to a port that refuses connections.
	c, err := net.Dial("tcp", socks.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	req := []byte{5, 1, 0, 3, byte(len("127.0.0.1"))}
	req = append(req, []byte("127.0.0.1")...)
	req = binary.BigEndian.AppendUint16(req, 1) // port 1, refused
	c.Write(req)
	reply := make([]byte, 10)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("expected a SOCKS reply: %v", err)
	}
	if reply[1] == 0 {
		t.Fatalf("expected failure reply, got success: %v", reply)
	}
}
