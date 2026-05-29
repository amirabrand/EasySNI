// Package proxy ports the DualModeProxy from the original app.
//
//   - "transparent": the proxy terminates TLS to the upstream using a fake SNI,
//     then relays plaintext both ways (for ordinary HTTPS).
//   - "passthrough": the proxy relays raw TCP bytes untouched (for Xray/V2Ray
//     that bring their own TLS).
//   - "cdn_fronting": like transparent, but it also rewrites the HTTP Host
//     header to the real host while the TLS SNI stays the (allowed) front
//     domain — classic domain/CDN fronting.
package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ezsni/internal/desync"
)

// Mode selects the relaying behaviour.
type Mode string

const (
	Transparent Mode = "transparent"
	Passthrough Mode = "passthrough"
	CDNFront    Mode = "cdn_fronting"
)

// Config holds the listen/connect parameters.
type Config struct {
	ListenHost  string
	ListenPort  int
	ConnectIP   string
	ConnectPort int
	FakeSNI     string        // single fake SNI (used when SNIList is empty)
	SNIList     []string      // multiple SNIs; one is chosen at random per connection
	RealHost    string        // CDN fronting: Host header rewritten to this value
	Desync      desync.Config // DPI-evasion: fragmentation + fake injection
}

// pickSNI returns the SNI to use for a connection: a random entry from SNIList,
// or FakeSNI when the list is empty.
func (c *Config) pickSNI() string {
	if len(c.SNIList) == 1 {
		return c.SNIList[0]
	}
	if len(c.SNIList) > 1 {
		return c.SNIList[rand.Intn(len(c.SNIList))]
	}
	return c.FakeSNI
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
	switch mode {
	case Passthrough:
		modeName = "PASSTHROUGH (raw TCP for Xray)"
	case CDNFront:
		modeName = "CDN FRONTING (front SNI + Host rewrite)"
	}
	p.log("Proxy listening on "+addr, "ACCENT")
	p.log("Mode: "+modeName, "OK")
	p.log("Forwarding to "+net.JoinHostPort(cfg.ConnectIP, strconv.Itoa(cfg.ConnectPort)), "ACCENT")
	if mode == Transparent || mode == CDNFront {
		if len(cfg.SNIList) > 1 {
			p.log("Front SNIs ("+strconv.Itoa(len(cfg.SNIList))+", rotated): "+strings.Join(cfg.SNIList, ", "), "DIM")
		} else {
			p.log("Front SNI: "+cfg.pickSNI(), "DIM")
		}
	}
	if mode == CDNFront && cfg.RealHost != "" {
		p.log("Host header → "+cfg.RealHost, "DIM")
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

// ListenHostPort returns the address the proxy is currently bound to, so other
// features (e.g. the Mass URI tester) can route through it without the user
// re-typing the port. Returns ("",0) when not running.
func (p *Proxy) ListenHostPort() (string, int) {
	if !p.running.Load() {
		return "", 0
	}
	host := p.cfg.ListenHost
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return host, p.cfg.ListenPort
}

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

	sni := p.cfg.pickSNI()

	// Apply DPI evasion to the first (ClientHello) write toward the upstream.
	conn := desync.WrapConn(raw, p.cfg.Desync, sni, p.cfg.ConnectIP, p.cfg.ConnectPort, desync.LogFunc(p.log))

	var upstream net.Conn = conn
	if p.mode == Transparent || p.mode == CDNFront {
		tc := tls.Client(conn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true, //nolint:gosec // intentional for SNI spoofing
		})
		if err := tc.Handshake(); err != nil {
			p.log("TLS handshake error: "+err.Error(), "ERROR")
			return
		}
		p.log("TLS established with SNI="+sni, "DIM")
		upstream = tc
	}

	realHost := ""
	if p.mode == CDNFront {
		realHost = p.cfg.RealHost
	}

	// Bidirectional copy; closing either side ends both.
	done := make(chan struct{}, 2)
	go func() { copyClientToUpstream(upstream, client, realHost); done <- struct{}{} }()
	go func() { io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// copyClientToUpstream relays client→upstream, rewriting the HTTP Host header to
// realHost on the first request (for CDN fronting). Non-HTTP streams (e.g. inner
// TLS) pass through untouched.
func copyClientToUpstream(dst io.Writer, src net.Conn, realHost string) {
	if realHost == "" {
		_, _ = io.Copy(dst, src)
		return
	}
	br := bufio.NewReader(src)
	peek, _ := br.Peek(7)
	if !looksHTTP(peek) {
		_, _ = io.Copy(dst, br)
		return
	}
	var head bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			name := line
			if i := strings.IndexByte(line, ':'); i >= 0 {
				name = line[:i]
			}
			if strings.EqualFold(strings.TrimSpace(name), "Host") {
				head.WriteString("Host: " + realHost + "\r\n")
			} else {
				head.WriteString(line)
			}
		}
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	_, _ = dst.Write(head.Bytes())
	_, _ = io.Copy(dst, br)
}

// looksHTTP reports whether b begins with a common HTTP method token.
func looksHTTP(b []byte) bool {
	s := string(b)
	for _, m := range []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS", "PATCH ", "CONNECT", "TRACE "} {
		if strings.HasPrefix(s, m) {
			return true
		}
	}
	return false
}
