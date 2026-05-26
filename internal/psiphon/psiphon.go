// Package psiphon embeds the Psiphon circumvention tunnel. It is configured to
// reach the Psiphon network *through* an upstream proxy started by this project
// (the SNI-spoofing / CDN-fronting local proxy), and exposes local SOCKS5 and
// HTTP proxies that a device can route all of its traffic through.
//
// The real engine depends on github.com/Psiphon-Labs/psiphon-tunnel-core, which
// is large and not part of the default offline build. It sits behind the
// "psiphon" build tag (see psiphon_real.go); without it, Start returns
// ErrNoPsiphon with build instructions — mirroring how the SPlus LiveKit
// transport is gated.
package psiphon

import (
	"errors"
	"net"
	"strconv"
	"sync"
)

// ErrNoPsiphon is returned by the default build.
var ErrNoPsiphon = errors.New(
	"Psiphon is not compiled in — enable it with:\n" +
		"    go get github.com/Psiphon-Labs/psiphon-tunnel-core/ClientLibrary/clientlib@latest\n" +
		"    go build -tags psiphon")

// LogFunc receives status lines.
type LogFunc func(msg, level string)

// Options configures the embedded tunnel.
type Options struct {
	// UpstreamProxyURL is the proxy Psiphon dials through, e.g.
	// "socks5://127.0.0.1:1080" or "http://127.0.0.1:8080". Point it at a proxy
	// this app exposes so Psiphon's traffic is itself obfuscated.
	UpstreamProxyURL string
	LocalSocksPort   int // local SOCKS5 the device uses (default 1090)
	LocalHTTPPort    int // local HTTP proxy the device uses (default 8090)
	DataDir          string
}

// Controller supervises a single embedded Psiphon tunnel.
type Controller struct {
	mu       sync.Mutex
	running  bool
	socks    int
	httpp    int
	upstream string
	stop     func()
}

// New creates a Controller.
func New() *Controller { return &Controller{} }

// Running reports whether the tunnel is up.
func (c *Controller) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// Status returns a snapshot for the UI.
func (c *Controller) Status() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return map[string]any{"running": false}
	}
	return map[string]any{
		"running":  true,
		"socks":    net.JoinHostPort("127.0.0.1", strconv.Itoa(c.socks)),
		"http":     net.JoinHostPort("127.0.0.1", strconv.Itoa(c.httpp)),
		"upstream": c.upstream,
	}
}

// Start brings up the tunnel. Returns ErrNoPsiphon on the default build.
func (c *Controller) Start(opts Options, log LogFunc) error {
	if log == nil {
		log = func(string, string) {}
	}
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return errors.New("psiphon already running")
	}
	c.mu.Unlock()

	if opts.LocalSocksPort == 0 {
		opts.LocalSocksPort = 1090
	}
	if opts.LocalHTTPPort == 0 {
		opts.LocalHTTPPort = 8090
	}

	stop, socks, httpp, err := runPsiphon(opts, log)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.running, c.socks, c.httpp, c.upstream, c.stop = true, socks, httpp, opts.UpstreamProxyURL, stop
	c.mu.Unlock()
	log("Psiphon tunnel up — SOCKS5 "+strconv.Itoa(socks)+", HTTP "+strconv.Itoa(httpp), "OK")
	return nil
}

// Stop tears the tunnel down.
func (c *Controller) Stop() {
	c.mu.Lock()
	stop := c.stop
	c.running, c.stop = false, nil
	c.mu.Unlock()
	if stop != nil {
		stop()
	}
}
