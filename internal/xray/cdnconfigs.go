package xray

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ezsni/internal/sni"
)

// CDNConfigRow is one tested CF edge IP with timings, speeds, and the share
// URI rewritten to point at that IP.
type CDNConfigRow struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	OK         bool    `json:"ok"`
	PingMs     int     `json:"ping_ms"`     // TLS+TTFB from phase 1
	RelayMs    int     `json:"relay_ms"`    // SOCKS-fetch time from phase 2
	DownKbps   int     `json:"down_kbps"`   // download throughput via xray
	UpKbps     int     `json:"up_kbps"`     // upload throughput via xray
	HTTPStatus int     `json:"http_status"` // initial test fetch status
	Colo       string  `json:"colo"`        // Cloudflare datacenter code (e.g. "FRA")
	Score      float64 `json:"score"`       // ranking score: dl*0.75 + ul*0.25 − ping/50
	Status     string  `json:"status"`      // "GOOD" / "DL-only" / "UL-only" / "Below"
	URI        string  `json:"uri"`         // rewritten URI pointing at this IP:port
	Error      string  `json:"error"`
}

// CDNScanState is the live state of an in-progress CDN configs scan. The server
// polls Snapshot() to drive the UI's progress bar and top-N cards.
type CDNScanState struct {
	mu         sync.Mutex
	Phase      int // 0 idle, 1 ping, 2 speed, 3 finished
	PingTotal  int
	PingDone   int
	SpeedTotal int
	SpeedDone  int
	Rows       []CDNConfigRow // appended live as phase-2 finishes each IP:port
	Saved      []string
	Best       string
	Finished   bool
	Cancelled  bool
	Paused     bool
	Err        string
	StartedAt  time.Time
}

// Pause stalls workers before they pick up new units of work.
func (s *CDNScanState) Pause() {
	s.mu.Lock()
	s.Paused = true
	s.mu.Unlock()
}

// Resume releases stalled workers.
func (s *CDNScanState) Resume() {
	s.mu.Lock()
	s.Paused = false
	s.mu.Unlock()
}

// waitIfPaused blocks while Paused, returning early on ctx cancel. Polled sleep
// so context cancellation always wins.
func (s *CDNScanState) waitIfPaused(ctx context.Context) {
	for {
		s.mu.Lock()
		if !s.Paused {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// Snapshot returns a JSON-friendly copy with rows sorted reachable-first by
// score (desc). Safe to call from any goroutine.
func (s *CDNScanState) Snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]CDNConfigRow, len(s.Rows))
	copy(rows, s.Rows)
	sort.SliceStable(rows, func(a, b int) bool {
		if rows[a].OK != rows[b].OK {
			return rows[a].OK
		}
		return rows[a].Score > rows[b].Score
	})
	elapsed := 0
	if !s.StartedAt.IsZero() {
		elapsed = int(time.Since(s.StartedAt).Milliseconds())
	}
	return map[string]any{
		"phase":       s.Phase,
		"ping_total":  s.PingTotal,
		"ping_done":   s.PingDone,
		"speed_total": s.SpeedTotal,
		"speed_done":  s.SpeedDone,
		"rows":        rows,
		"saved":       s.Saved,
		"best":        s.Best,
		"finished":    s.Finished,
		"cancelled":   s.Cancelled,
		"paused":      s.Paused,
		"err":         s.Err,
		"elapsed_ms":  elapsed,
	}
}

func (s *CDNScanState) pingTick() {
	s.mu.Lock()
	s.PingDone++
	s.mu.Unlock()
}

func (s *CDNScanState) addRow(r CDNConfigRow) {
	s.mu.Lock()
	s.Rows = append(s.Rows, r)
	s.SpeedDone++
	s.mu.Unlock()
}

func (s *CDNScanState) setPhase(p int) {
	s.mu.Lock()
	s.Phase = p
	s.mu.Unlock()
}

func (s *CDNScanState) setTotals(pingTotal, speedTotal int) {
	s.mu.Lock()
	s.PingTotal, s.SpeedTotal = pingTotal, speedTotal
	s.mu.Unlock()
}

func (s *CDNScanState) finish(saved []string, best, errMsg string, cancelled bool) {
	s.mu.Lock()
	s.Saved, s.Best, s.Err = saved, best, errMsg
	s.Cancelled = cancelled
	s.Finished = true
	s.Phase = 3
	s.mu.Unlock()
}

// CDNConfigsOptions configures the two-phase mass CDN scan.
type CDNConfigsOptions struct {
	URI             string
	BinPath         string
	Ranges          string // newline IPs/CIDRs; default = sni.DefaultCloudflareRanges
	PerRangeLimit   int    // max IPs to take from each CIDR (0 = full range)
	MaxScanCap      int    // overall hard cap to protect memory (default 50000)
	Ports           []int  // ports to test on each IP (default [443]); CF supports 443/2053/2083/2087/2096/8443
	TopForSpeed     int    // phase-2 candidates by ping (default 20)
	FinalCount      int    // size of the savebox (default 50, clamped to TopForSpeed)
	DownloadBytes   int    // bytes to download per IP (default 2 MB)
	UploadBytes     int    // bytes to upload per IP (default 1 MB)
	PingTimeoutSec  int    // per-IP phase-1 timeout (default 4)
	SpeedTimeoutSec int    // per-IP phase-2 timeout (default 10)
	PingConcurrency int    // phase-1 workers (default 64)
	SpeedConc       int    // phase-2 workers (default 4)
	BasePort        int    // first SOCKS port for phase-2 xray (default 24000)
}

// TestCDNConfigs takes one xray share link, scans many Cloudflare edge IPs
// against the original SNI (phase 1: TLS ping), speed-tests the fastest ones
// through xray (phase 2: download + upload), and writes live progress + ranked
// rows into state so the UI can poll Snapshot(). It honours ctx for cooperative
// cancellation via the Stop button.
func TestCDNConfigs(ctx context.Context, state *CDNScanState, opts CDNConfigsOptions, log LogFunc) error {
	if log == nil {
		log = func(string, string) {}
	}

	cancelled := func() bool {
		select {
		case <-ctx.Done():
			return true
		default:
			return false
		}
	}

	bin := ResolveBin(opts.BinPath)
	if bin == "" {
		state.finish(nil, "", "xray binary not found — set its path or use Download", false)
		return errors.New("xray binary not found")
	}
	p := sni.ParseURI(opts.URI)
	if !p.Valid {
		state.finish(nil, "", "invalid URI: "+p.Error, false)
		return errors.New("invalid URI: " + p.Error)
	}

	if opts.PerRangeLimit < 0 {
		opts.PerRangeLimit = 0
	}
	if opts.PerRangeLimit == 0 {
		opts.PerRangeLimit = 200
	}
	if opts.MaxScanCap <= 0 {
		opts.MaxScanCap = 50000
	}
	if len(opts.Ports) == 0 {
		opts.Ports = []int{sni.PortOf(p)}
	}
	if opts.TopForSpeed <= 0 {
		opts.TopForSpeed = 20
	}
	if opts.FinalCount <= 0 {
		opts.FinalCount = 50
	}
	if opts.FinalCount > opts.TopForSpeed {
		opts.FinalCount = opts.TopForSpeed
	}
	if opts.DownloadBytes <= 0 {
		opts.DownloadBytes = 2_000_000
	}
	if opts.UploadBytes <= 0 {
		opts.UploadBytes = 1_000_000
	}
	if opts.PingTimeoutSec <= 0 {
		opts.PingTimeoutSec = 4
	}
	if opts.SpeedTimeoutSec <= 0 {
		opts.SpeedTimeoutSec = 10
	}
	if opts.PingConcurrency <= 0 {
		opts.PingConcurrency = 64
	}
	if opts.SpeedConc <= 0 {
		opts.SpeedConc = 4
	}
	if opts.BasePort <= 0 {
		opts.BasePort = 24000
	}

	// --- phase 1: expand ranges per-CIDR (PerRangeLimit) and ping-rank candidates ---
	rangeLines := splitNonEmpty(opts.Ranges)
	if len(rangeLines) == 0 {
		rangeLines = append([]string{}, sni.DefaultCloudflareRanges...)
	}
	// Expand each CIDR independently with the per-range cap; collect IPs.
	ips := make([]string, 0, opts.PerRangeLimit*len(rangeLines))
	for _, ln := range rangeLines {
		if !strings.Contains(ln, "/") {
			ips = append(ips, ln) // single IP
			continue
		}
		ips = append(ips, sni.ExpandCIDR(ln, opts.PerRangeLimit)...)
	}
	if len(ips) > opts.MaxScanCap {
		ips = ips[:opts.MaxScanCap] // safety cap to prevent memory blowup
	}
	if len(ips) == 0 {
		state.finish(nil, "", "no IPs parsed from ranges", false)
		return errors.New("no IPs parsed from ranges")
	}
	// Build (IP, port) targets — each IP is tried on every requested port.
	type target struct {
		IP   string
		Port int
	}
	targets := make([]target, 0, len(ips)*len(opts.Ports))
	for _, ip := range ips {
		for _, prt := range opts.Ports {
			targets = append(targets, target{IP: ip, Port: prt})
		}
	}
	frontSNI := p.SNI
	if frontSNI == "" {
		frontSNI = p.Host
	}
	state.setPhase(1)
	state.setTotals(len(targets), 0)
	portsStr := make([]string, len(opts.Ports))
	for i, pr := range opts.Ports {
		portsStr[i] = strconv.Itoa(pr)
	}
	log("CDN configs: phase 1 ping-scan "+strconv.Itoa(len(targets))+" targets (SNI "+frontSNI+", ports "+strings.Join(portsStr, ",")+")", "ACCENT")

	type pingRow struct {
		IP   string
		Port int
		Ms   int
		OK   bool
	}
	pingRows := make([]pingRow, len(targets))
	timeout1 := time.Duration(opts.PingTimeoutSec) * time.Second
	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.PingConcurrency)
	for i, tg := range targets {
		if cancelled() {
			break
		}
		state.waitIfPaused(ctx)
		if cancelled() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, tg target) {
			defer wg.Done()
			defer func() { <-sem }()
			if cancelled() {
				state.pingTick()
				return
			}
			r := sni.FrontTest(tg.IP, tg.Port, frontSNI, p.Host, timeout1)
			pingRows[i] = pingRow{IP: tg.IP, Port: tg.Port, Ms: r.PingMs, OK: r.OK}
			state.pingTick()
		}(i, tg)
	}
	wg.Wait()
	if cancelled() {
		state.finish(nil, "", "", true)
		log("CDN configs: cancelled during phase 1", "WARN")
		return nil
	}

	sort.SliceStable(pingRows, func(a, b int) bool {
		if pingRows[a].OK != pingRows[b].OK {
			return pingRows[a].OK
		}
		ma, mb := pingRows[a].Ms, pingRows[b].Ms
		if ma < 0 {
			ma = 1 << 30
		}
		if mb < 0 {
			mb = 1 << 30
		}
		return ma < mb
	})

	candidates := []pingRow{}
	for _, r := range pingRows {
		if r.OK {
			candidates = append(candidates, r)
		}
		if len(candidates) >= opts.TopForSpeed {
			break
		}
	}
	if len(candidates) == 0 {
		state.finish(nil, "", "phase 1: no edge IPs reachable", false)
		return errors.New("phase 1: no edge IPs reachable")
	}

	// --- phase 2: per-(IP,port) xray + speed test, streaming into state ---
	state.setPhase(2)
	state.setTotals(len(targets), len(candidates))
	log("phase 2: speed-test "+strconv.Itoa(len(candidates))+" top edges through xray", "ACCENT")

	var portSeq int64 = int64(opts.BasePort) - 1
	sem2 := make(chan struct{}, opts.SpeedConc)
	var wg2 sync.WaitGroup
	for _, c := range candidates {
		if cancelled() {
			break
		}
		state.waitIfPaused(ctx)
		if cancelled() {
			break
		}
		wg2.Add(1)
		sem2 <- struct{}{}
		go func(c pingRow) {
			defer wg2.Done()
			defer func() { <-sem2 }()
			if cancelled() {
				return
			}
			socksPort := int(atomic.AddInt64(&portSeq, 1))
			row := cdnSpeedOne(ctx, bin, p, c.IP, c.Port, socksPort, opts)
			row.PingMs = c.Ms
			classify(&row)
			// Build the annotated savebox URI: "OriginalName | LOC | ping ms | @EzAccess1".
			row.URI = annotateURI(opts.URI, row)
			state.addRow(row)
		}(c)
	}
	wg2.Wait()
	cancelledHere := cancelled()

	// --- finalize: build the savebox from top FinalCount working rows ---
	state.mu.Lock()
	rowsCopy := make([]CDNConfigRow, len(state.Rows))
	copy(rowsCopy, state.Rows)
	state.mu.Unlock()
	sort.SliceStable(rowsCopy, func(a, b int) bool {
		if rowsCopy[a].OK != rowsCopy[b].OK {
			return rowsCopy[a].OK
		}
		return rowsCopy[a].Score > rowsCopy[b].Score
	})
	saved := []string{}
	final := opts.FinalCount
	if final > len(rowsCopy) {
		final = len(rowsCopy)
	}
	for i := 0; i < final; i++ {
		if rowsCopy[i].OK && rowsCopy[i].URI != "" {
			saved = append(saved, rowsCopy[i].URI)
		}
	}
	best := ""
	if len(saved) > 0 {
		best = saved[0]
	}
	state.finish(saved, best, "", cancelledHere)
	ok := 0
	for _, r := range rowsCopy {
		if r.OK {
			ok++
		}
	}
	verb := "complete"
	if cancelledHere {
		verb = "stopped"
	}
	log("CDN configs "+verb+": "+strconv.Itoa(ok)+"/"+strconv.Itoa(len(rowsCopy))+" reachable; savebox has "+strconv.Itoa(len(saved))+" configs", "OK")
	return nil
}

// annotateURI builds the savebox share link for a tested edge: rewrites host
// and port, then renames it to "<original-name> | <COLO> | <ping>ms | @EzAccess1"
// so users can tell variants apart in their client.
func annotateURI(origURI string, r CDNConfigRow) string {
	orig := strings.TrimSpace(sni.OriginalName(origURI))
	if orig == "" {
		orig = "EzSNI"
	}
	parts := []string{orig}
	if r.Colo != "" {
		parts = append(parts, r.Colo)
	}
	if r.PingMs >= 0 {
		parts = append(parts, strconv.Itoa(r.PingMs)+"ms")
	}
	parts = append(parts, "@EzAccess1")
	name := strings.Join(parts, " | ")
	out, err := sni.RewriteHostPortName(origURI, r.IP, r.Port, name)
	if err != nil {
		return ""
	}
	return out
}

// classify fills the Score and Status fields after speeds are measured.
//
// Score = down*0.75 + up*0.25 − ping/50  (down/up in Mb/s).
// Status thresholds: ≥2 Mb/s download, ≥1 Mb/s upload are "good enough".
func classify(r *CDNConfigRow) {
	dl := float64(r.DownKbps) / 1000.0
	ul := float64(r.UpKbps) / 1000.0
	if r.PingMs < 0 {
		return
	}
	r.Score = dl*0.75 + ul*0.25 - float64(r.PingMs)/50.0
	const dlMin, ulMin = 2.0, 1.0
	switch {
	case dl >= dlMin && ul >= ulMin:
		r.Status = "GOOD"
	case dl >= dlMin:
		r.Status = "DL-only"
	case ul >= ulMin:
		r.Status = "UL-only"
	default:
		r.Status = "Below"
	}
}

func cdnSpeedOne(parent context.Context, bin string, p sni.ParsedURI, ip string, edgePort, socksPort int, opts CDNConfigsOptions) CDNConfigRow {
	row := CDNConfigRow{IP: ip, Port: edgePort, RelayMs: -1, DownKbps: -1, UpKbps: -1, PingMs: -1}
	// The final URI's display name is filled in once we have colo + ping.
	cfgPath, err := buildConfig(p, ip, edgePort, "127.0.0.1", socksPort)
	if err != nil {
		row.Error = "config: " + err.Error()
		return row
	}
	defer os.Remove(cfgPath)

	// Derive a per-IP context from the parent so Stop reliably kills xray
	// processes mid-scan via exec.CommandContext.
	ctx, cancel := context.WithTimeout(parent, time.Duration(opts.SpeedTimeoutSec+10)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-c", cfgPath)
	var out lockBuf
	cmd.Stdout, cmd.Stderr = &out, &out
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		row.Error = "start xray: " + err.Error()
		return row
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	defer func() { _ = cmd.Process.Kill() }()

	socksAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	ready := false
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-waitErr:
			row.Error = "xray exited: " + procDetail(e, out.String())
			return row
		default:
		}
		if c, e := net.DialTimeout("tcp", socksAddr, 250*time.Millisecond); e == nil {
			_ = c.Close()
			ready = true
			break
		}
		time.Sleep(120 * time.Millisecond)
	}
	if !ready {
		row.Error = "xray not ready: " + procDetail(nil, out.String())
		return row
	}

	spTimeout := time.Duration(opts.SpeedTimeoutSec) * time.Second
	t0 := time.Now()
	status, _, err := fetchThroughSocks("127.0.0.1", socksPort, "https://speed.cloudflare.com/", spTimeout)
	row.RelayMs = int(time.Since(t0).Milliseconds())
	row.HTTPStatus = status
	if err != nil {
		row.Error = "probe: " + truncateErr(err, 80)
		return row
	}
	// Detect which Cloudflare datacenter this edge routes to. Best-effort; an
	// empty colo doesn't fail the row.
	row.Colo = DetectColo("127.0.0.1", socksPort, 3*time.Second)
	down, derr := MeasureDownload("127.0.0.1", socksPort, opts.DownloadBytes, spTimeout)
	if derr != nil {
		row.Error = "download: " + truncateErr(derr, 80)
		return row
	}
	row.DownKbps = down
	up, uerr := MeasureUpload("127.0.0.1", socksPort, opts.UploadBytes, spTimeout)
	if uerr != nil {
		// Keep download result even when upload fails.
		row.UpKbps = 0
		row.OK = down > 0
		row.Error = "upload: " + truncateErr(uerr, 80)
		return row
	}
	row.UpKbps = up
	row.OK = down > 0
	return row
}

// splitNonEmpty is a tiny helper that splits text into non-empty, non-comment
// trimmed lines (mirrors the server-side splitLines).
func splitNonEmpty(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			line := s[start:i]
			// trim spaces
			a, b := 0, len(line)
			for a < b && (line[a] == ' ' || line[a] == '\t' || line[a] == '\r') {
				a++
			}
			for b > a && (line[b-1] == ' ' || line[b-1] == '\t' || line[b-1] == '\r') {
				b--
			}
			if b > a && line[a] != '#' {
				out = append(out, line[a:b])
			}
			start = i + 1
		}
	}
	return out
}
