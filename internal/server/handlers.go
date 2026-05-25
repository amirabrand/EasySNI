package server

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"splus-suite/internal/desync"
	"splus-suite/internal/netutil"
	"splus-suite/internal/proxy"
	"splus-suite/internal/sni"
	"splus-suite/internal/splus"
	"splus-suite/internal/windivert"
	"splus-suite/internal/xray"
)

// ---- URI parser -----------------------------------------------------------

func (s *Server) handleParseURI(body json.RawMessage) (any, error) {
	var req struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	res := sni.ParseURI(req.URI)
	if res.Valid {
		s.log("Parsed "+res.Protocol+" → "+res.Host+" (SNI "+res.SNI+")", "OK")
	} else {
		s.log("URI parse failed: "+res.Error, "ERROR")
	}
	return res, nil
}

// ---- single SNI scan ------------------------------------------------------

func (s *Server) handleSNIScan(body json.RawMessage) (any, error) {
	var req struct {
		Host    string `json:"host"`
		Port    int    `json:"port"`
		Timeout int    `json:"timeout"` // seconds
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if req.Host == "" {
		return nil, errors.New("host required")
	}
	if req.Port == 0 {
		req.Port = 443
	}
	s.log("Testing SNI "+req.Host+"…", "ACCENT")
	res := sni.CheckSNI(req.Host, req.Port, timeoutOf(req.Timeout, 5))
	if res.OK {
		s.log("✓ "+req.Host+" reachable ("+strconv.Itoa(res.Latency)+" ms)", "OK")
	} else {
		s.log("✗ "+req.Host+" failed: "+res.Error, "ERROR")
	}
	return res, nil
}

// ---- relay test -----------------------------------------------------------

func (s *Server) handleRelayTest(body json.RawMessage) (any, error) {
	var req struct {
		ConnectIP   string `json:"connect_ip"`
		ConnectPort int    `json:"connect_port"`
		FakeSNI     string `json:"fake_sni"`
		Timeout     int    `json:"timeout"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if req.ConnectIP == "" {
		return nil, errors.New("connect_ip required")
	}
	if req.ConnectPort == 0 {
		req.ConnectPort = 443
	}
	if req.FakeSNI == "" {
		req.FakeSNI = "www.google.com"
	}
	s.log("Relay test → "+req.ConnectIP+" (SNI "+req.FakeSNI+")", "ACCENT")
	res := sni.RelayTest(req.ConnectIP, req.ConnectPort, req.FakeSNI, timeoutOf(req.Timeout, 8))
	if res.OK {
		s.log("✓ relay ok (tcp "+strconv.Itoa(res.TCPMs)+" / tls "+strconv.Itoa(res.TLSMs)+" / relay "+strconv.Itoa(res.RelayMs)+" ms)", "OK")
	} else {
		s.log("✗ relay failed: "+res.Error, "ERROR")
	}
	return res, nil
}

// ---- mass SNI scan --------------------------------------------------------

func (s *Server) handleMassScan(body json.RawMessage) (any, error) {
	var req struct {
		ConnectIP   string `json:"connect_ip"`
		ConnectPort int    `json:"connect_port"`
		SNIs        string `json:"snis"` // newline-separated
		Timeout     int    `json:"timeout"`
		Workers     int    `json:"workers"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if req.ConnectIP == "" {
		return nil, errors.New("connect_ip required")
	}
	if req.ConnectPort == 0 {
		req.ConnectPort = 443
	}
	names := splitLines(req.SNIs)
	if len(names) == 0 {
		return nil, errors.New("no SNI hostnames provided")
	}
	timeout := timeoutOf(req.Timeout, 5)
	workers := clampWorkers(req.Workers)

	s.log("Mass SNI scan: "+strconv.Itoa(len(names))+" hostnames via "+req.ConnectIP+" ("+strconv.Itoa(workers)+" workers)", "ACCENT")

	results := make([]sni.MassResult, len(names))
	var ok int64
	runPool(len(names), workers, func(i int) {
		results[i] = sni.MassTest(req.ConnectIP, req.ConnectPort, names[i], timeout)
		if results[i].OK {
			atomic.AddInt64(&ok, 1)
			s.log("✓ "+names[i]+" ("+strconv.Itoa(results[i].TotalMs)+" ms)", "OK")
		}
	})
	s.log("Mass scan complete: "+strconv.FormatInt(ok, 10)+"/"+strconv.Itoa(len(names))+" reachable", "ACCENT")
	return map[string]any{"results": results, "ok": ok, "total": len(names)}, nil
}

// ---- Cloudflare IP scan ---------------------------------------------------

func (s *Server) handleCFScan(body json.RawMessage) (any, error) {
	var req struct {
		Ranges  string `json:"ranges"` // newline-separated CIDRs / IPs
		Port    int    `json:"port"`
		SNI     string `json:"sni"`
		Limit   int    `json:"limit"`
		Timeout int    `json:"timeout"`
		Workers int    `json:"workers"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	text := req.Ranges
	if len(splitLines(text)) == 0 {
		text = strings.Join(sni.DefaultCloudflareRanges, "\n")
	}
	ips := sni.ParseIPList(text)
	if len(ips) == 0 {
		return nil, errors.New("no IPs parsed from ranges")
	}
	if req.Limit > 0 && len(ips) > req.Limit {
		ips = ips[:req.Limit]
	}
	if req.Port == 0 {
		req.Port = 443
	}
	if req.SNI == "" {
		req.SNI = "cloudflare.com"
	}
	timeout := timeoutOf(req.Timeout, 3)
	workers := clampWorkers(req.Workers)

	s.log("Cloudflare scan: "+strconv.Itoa(len(ips))+" IPs on :"+strconv.Itoa(req.Port)+" (SNI "+req.SNI+")", "ACCENT")

	results := make([]sni.CFResult, len(ips))
	var ok int64
	runPool(len(ips), workers, func(i int) {
		results[i] = sni.TestIP(ips[i], req.Port, req.SNI, timeout)
		if results[i].OK {
			atomic.AddInt64(&ok, 1)
			s.log("✓ "+ips[i]+" ("+strconv.Itoa(results[i].Latency)+" ms)", "OK")
		}
	})
	s.log("Cloudflare scan complete: "+strconv.FormatInt(ok, 10)+"/"+strconv.Itoa(len(ips))+" working", "ACCENT")
	return map[string]any{"results": results, "ok": ok, "total": len(ips)}, nil
}

// ---- proxy control --------------------------------------------------------

func (s *Server) handleProxyStart(body json.RawMessage) (any, error) {
	var req struct {
		ListenHost  string `json:"listen_host"`
		ListenPort  int    `json:"listen_port"`
		ConnectIP   string `json:"connect_ip"`
		ConnectPort int    `json:"connect_port"`
		FakeSNI     string `json:"fake_sni"`
		Mode        string `json:"mode"`
		// DPI evasion
		BypassMode     string `json:"bypass_mode"`       // none | wrong_checksum | wrong_seq
		FakeRepeat     int    `json:"fake_repeat"`       // default 1
		FakeDelayMs    int    `json:"fake_delay_ms"`     // default 2
		AckTimeoutMs   int    `json:"ack_timeout_ms"`    // default 2000
		UTLS           string `json:"utls"`              // default firefox
		EnableFragment bool   `json:"enable_fragment"`   // default false
		FragDelayMs    int    `json:"fragment_delay_ms"` // default 500
		SNIChunk       *int   `json:"sni_chunk"`         // default 3; 0 = whole host
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if req.ConnectIP == "" {
		return nil, errors.New("connect_ip required")
	}
	if req.ListenHost == "" {
		req.ListenHost = "127.0.0.1"
	}
	if req.ListenPort == 0 {
		req.ListenPort = 10808
	}
	if req.ConnectPort == 0 {
		req.ConnectPort = 443
	}
	if req.FakeSNI == "" {
		req.FakeSNI = "www.google.com"
	}
	mode := proxy.Transparent
	if proxy.Mode(req.Mode) == proxy.Passthrough {
		mode = proxy.Passthrough
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proxy != nil && s.proxy.Running() {
		return nil, errors.New("proxy already running")
	}
	s.proxy = proxy.New(s.bus.Log)
	dc := s.desyncDefaults
	if req.UTLS != "" {
		if !desync.ValidPreset(req.UTLS) {
			return nil, errors.New("unknown -utls preset: " + req.UTLS)
		}
		dc.UTLS = req.UTLS
	}
	switch desync.BypassMode(req.BypassMode) {
	case desync.ModeWrongChecksum:
		dc.Mode = desync.ModeWrongChecksum
	case desync.ModeWrongSeq:
		dc.Mode = desync.ModeWrongSeq
	default:
		dc.Mode = desync.ModeNone
	}
	if req.FakeRepeat > 0 {
		dc.FakeRepeat = req.FakeRepeat
	}
	if req.FakeDelayMs > 0 {
		dc.FakeDelay = time.Duration(req.FakeDelayMs) * time.Millisecond
	}
	if req.AckTimeoutMs > 0 {
		dc.AckTimeout = time.Duration(req.AckTimeoutMs) * time.Millisecond
	}
	if req.FragDelayMs > 0 {
		dc.FragmentDelay = time.Duration(req.FragDelayMs) * time.Millisecond
	}
	if req.SNIChunk != nil {
		dc.SNIChunk = *req.SNIChunk
	}
	dc.EnableFragment = req.EnableFragment

	cfg := proxy.Config{
		ListenHost:  req.ListenHost,
		ListenPort:  req.ListenPort,
		ConnectIP:   req.ConnectIP,
		ConnectPort: req.ConnectPort,
		FakeSNI:     req.FakeSNI,
		Desync:      dc,
	}
	if err := s.proxy.Start(cfg, mode); err != nil {
		s.log("Proxy start failed: "+err.Error(), "ERROR")
		return nil, err
	}
	return map[string]any{"running": true}, nil
}

func (s *Server) handleProxyStop(json.RawMessage) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proxy == nil || !s.proxy.Running() {
		return map[string]any{"running": false}, nil
	}
	s.proxy.Stop()
	return map[string]any{"running": false}, nil
}

func (s *Server) handleProxyStatus(json.RawMessage) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	running := s.proxy != nil && s.proxy.Running()
	return map[string]any{"running": running}, nil
}

// ---- SPlus tunnel control -------------------------------------------------

func (s *Server) handleSplusStart(body json.RawMessage) (any, error) {
	var req struct {
		Role      string `json:"role"`
		Token     string `json:"token"`
		URL       string `json:"url"`
		SocksHost string `json:"socks_host"`
		SocksPort int    `json:"socks_port"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Token) == "" {
		return nil, errors.New("token required (extract from the SoroushPlus call)")
	}
	role := splus.RoleClient
	if splus.Role(req.Role) == splus.RoleServer {
		role = splus.RoleServer
	}
	opts := splus.Options{
		Role:      role,
		Token:     strings.TrimSpace(req.Token),
		URL:       strings.TrimSpace(req.URL),
		SocksHost: req.SocksHost,
		SocksPort: req.SocksPort,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tunnel != nil {
		return nil, errors.New("tunnel already running")
	}
	s.log("Starting SPlus tunnel ("+string(role)+")…", "ACCENT")
	t, err := splus.Start(opts, s.bus.Log)
	if err != nil {
		s.log("SPlus start failed: "+err.Error(), "ERROR")
		return nil, err
	}
	s.tunnel = t
	s.tunOpts = opts
	return map[string]any{"running": true, "role": string(role)}, nil
}

func (s *Server) handleSplusStop(json.RawMessage) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tunnel == nil {
		return map[string]any{"running": false}, nil
	}
	s.tunnel.Stop()
	s.tunnel = nil
	s.log("SPlus tunnel stopped", "WARN")
	return map[string]any{"running": false}, nil
}

func (s *Server) handleSplusStatus(json.RawMessage) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tunnel == nil {
		return map[string]any{"running": false}, nil
	}
	rx, tx := s.tunnel.Stats()
	return map[string]any{
		"running": true,
		"role":    string(s.tunOpts.Role),
		"rx":      rx,
		"tx":      tx,
	}, nil
}

// ---- xray test ------------------------------------------------------------

func (s *Server) handleXrayTest(body json.RawMessage) (any, error) {
	var req struct {
		URI       string `json:"uri"`
		ProxyHost string `json:"proxy_host"`
		ProxyPort int    `json:"proxy_port"`
		SocksPort int    `json:"socks_port"`
		TestURL   string `json:"test_url"`
		Timeout   int    `json:"timeout"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.URI) == "" {
		return nil, errors.New("uri required")
	}
	s.log("Xray test starting…", "ACCENT")
	res := xray.Test(xray.Options{
		URI:        req.URI,
		ProxyHost:  req.ProxyHost,
		ProxyPort:  req.ProxyPort,
		SocksPort:  req.SocksPort,
		TestURL:    req.TestURL,
		TimeoutSec: req.Timeout,
	}, s.bus.Log)
	if res.OK {
		s.log("✓ Xray test ok — HTTP "+strconv.Itoa(res.HTTPStatus)+" in "+strconv.Itoa(res.ResponseMs)+" ms", "OK")
	} else {
		s.log("✗ Xray test failed: "+res.Error, "ERROR")
	}
	return res, nil
}

// ---- WinDivert ------------------------------------------------------------

func (s *Server) handleWinDivertStatus(json.RawMessage) (any, error) {
	return windivert.Check(), nil
}

func (s *Server) handleWinDivertInstall(body json.RawMessage) (any, error) {
	var req struct {
		Path string `json:"path"`
	}
	_ = json.Unmarshal(body, &req)
	s.log("Installing WinDivert…", "ACCENT")
	r := windivert.Install(strings.TrimSpace(req.Path))
	if r.OK {
		s.log("✓ "+r.Message, "OK")
	} else {
		s.log("✗ "+r.Message, "ERROR")
	}
	return r, nil
}

func (s *Server) handleWinDivertUninstall(json.RawMessage) (any, error) {
	s.log("Removing WinDivert…", "WARN")
	r := windivert.Uninstall()
	if r.OK {
		s.log("✓ "+r.Message, "OK")
	} else {
		s.log("✗ "+r.Message, "ERROR")
	}
	return r, nil
}

// ---- port check & LAN info ------------------------------------------------

func (s *Server) handlePortCheck(body json.RawMessage) (any, error) {
	var req struct {
		Host    string `json:"host"`
		Port    int    `json:"port"`
		Timeout int    `json:"timeout"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if req.Host == "" {
		req.Host = "127.0.0.1"
	}
	if req.Port == 0 {
		return nil, errors.New("port required")
	}
	r := netutil.CheckPort(req.Host, req.Port, timeoutOf(req.Timeout, 4))
	if r.Open {
		s.log("✓ port "+req.Host+":"+strconv.Itoa(req.Port)+" open ("+strconv.Itoa(r.Latency)+" ms)", "OK")
	} else {
		s.log("✗ port "+req.Host+":"+strconv.Itoa(req.Port)+" closed", "WARN")
	}
	return r, nil
}

func (s *Server) handleLANInfo(json.RawMessage) (any, error) {
	return map[string]any{"addrs": netutil.LANAddrs()}, nil
}

// ---- small helpers --------------------------------------------------------

func timeoutOf(seconds, def int) time.Duration {
	if seconds <= 0 {
		seconds = def
	}
	return time.Duration(seconds) * time.Second
}

func clampWorkers(n int) int {
	if n <= 0 {
		return 50
	}
	if n > 200 {
		return 200
	}
	return n
}

// runPool runs fn(0..n-1) across at most `workers` goroutines and blocks until
// every index has completed.
func runPool(n, workers int, fn func(i int)) {
	if n == 0 {
		return
	}
	if workers > n {
		workers = n
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}
