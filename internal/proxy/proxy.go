// Package proxy ports the DualModeProxy from the original app.
//
//   - "transparent": the proxy terminates TLS to the upstream using a fake SNI,
//     then relays plaintext both ways (for ordinary HTTPS).
//   - "passthrough": the proxy relays raw TCP bytes untouched (for Xray/V2Ray
//     that bring their own TLS).
package proxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"splus-suite/internal/desync"
)

// Mode selects the relaying behaviour.
type Mode string

const (
	Transparent Mode = "transparent"
	Passthrough Mode = "passthrough"
)

// Config holds the listen/connect parameters.
type Config struct {
	ListenHost  string
	ListenPort  int
	ConnectIP   string
	ConnectPort int
	FakeSNI     string
	Desync      desync.Config // DPI-evasion: fragmentation + fake injection
}

// LogFunc receives human-readable status lines.
type LogFunc func(msg, level string)

// Proxy is a running dual-mode TCP proxy.
type Proxy struct {
	log     LogFunc
	ln      net.Listener
	cfg     Config
	mode    Mode
	conns   int64
	running atomic.Bool
	wg      sync.WaitGroup
}

// New creates a Proxy. log may be nil.
func New(log LogFunc) *Proxy {
	if log == nil {
		log = func(string, string) {}
	}
	return &Proxy{log: log}
}

// Start binds the listen socket and begins accepting in the background.
func (p *Proxy) Start(cfg Config, mode Mode) error {
	if p.running.Load() {
		return errors.New("already running")
	}
	addr := net.JoinHostPort(cfg.ListenHost, strconv.Itoa(cfg.ListenPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	p.ln = ln
	p.cfg = cfg
	p.mode = mode
	p.running.Store(true)

	modeName := "TRANSPARENT (terminates TLS)"
	if mode == Passthrough {
		modeName = "PASSTHROUGH (raw TCP for Xray)"
	}
	p.log("Proxy listening on "+addr, "ACCENT")
	p.log("Mode: "+modeName, "OK")
	p.log("Forwarding to "+net.JoinHostPort(cfg.ConnectIP, strconv.Itoa(cfg.ConnectPort)), "ACCENT")
	if mode == Transparent {
		p.log("Fake SNI: "+cfg.FakeSNI, "DIM")
	}
	if d := cfg.Desync; d.Active() {
		msg := "DPI evasion:"
		if d.EnableFragment {
			msg += " fragment(sni-chunk=" + strconv.Itoa(d.SNIChunk) + ", delay=" + d.FragmentDelay.String() + ")"
		}
		if d.Mode != desync.ModeNone {
			msg += " fake(" + string(d.Mode) + ", utls=" + d.UTLS + ", repeat=" + strconv.Itoa(d.FakeRepeat) + ")"
		}
		p.log(msg, "ACCENT")
	}

	p.wg.Add(1)
	go p.acceptLoop()
	return nil
}

// Stop closes the listener and waits for the accept loop to exit.
func (p *Proxy) Stop() {
	if !p.running.CompareAndSwap(true, false) {
		return
	}
	if p.ln != nil {
		_ = p.ln.Close()
	}
	p.wg.Wait()
	p.log("Proxy stopped", "WARN")
}

// Running reports whether the proxy is accepting connections.
func (p *Proxy) Running() bool { return p.running.Load() }

func (p *Proxy) acceptLoop() {
	defer p.wg.Done()
	for p.running.Load() {
		c, err := p.ln.Accept()
		if err != nil {
			if p.running.Load() {
				p.log("Accept error: "+err.Error(), "ERROR")
			}
			return
		}
		n := atomic.AddInt64(&p.conns, 1)
		p.log("Connection #"+strconv.FormatInt(n, 10)+" from "+c.RemoteAddr().String(), "DIM")
		go p.handle(c)
	}
}

func (p *Proxy) handle(client net.Conn) {
	defer client.Close()
	addr := net.JoinHostPort(p.cfg.ConnectIP, strconv.Itoa(p.cfg.ConnectPort))
	raw, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		p.log("Connection error: "+err.Error(), "ERROR")
		return
	}
	defer raw.Close()

	// Apply DPI evasion to the first (ClientHello) write toward the upstream.
	// In transparent mode this fragments the proxy's own TLS ClientHello; in
	// passthrough mode it fragments the client's relayed ClientHello.
	conn := desync.WrapConn(raw, p.cfg.Desync, p.cfg.FakeSNI, p.cfg.ConnectIP, p.cfg.ConnectPort, desync.LogFunc(p.log))

	var upstream net.Conn = conn
	if p.mode == Transparent {
		tc := tls.Client(conn, &tls.Config{
			ServerName:         p.cfg.FakeSNI,
			InsecureSkipVerify: true, //nolint:gosec // intentional for SNI spoofing
		})
		if err := tc.Handshake(); err != nil {
			p.log("TLS handshake error: "+err.Error(), "ERROR")
			return
		}
		p.log("TLS established with SNI="+p.cfg.FakeSNI, "DIM")
		upstream = tc
	}

	// Bidirectional copy; closing either side ends both.
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, client); done <- struct{}{} }()
	go func() { io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}
