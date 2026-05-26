package xray

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"ezsni/internal/sni"
)

// ---- mass URI connectivity test -------------------------------------------

// MassRow is one config's reachability result.
type MassRow struct {
	URI     string `json:"uri"`
	Name    string `json:"name"` // protocol@host:port
	OK      bool   `json:"ok"`
	PingMs  int    `json:"ping_ms"`  // TCP connect, -1 on failure
	RelayMs int    `json:"relay_ms"` // TLS handshake + first byte, -1 on failure
	Host    string `json:"host"`
	Port    int    `json:"port"`
	SNI     string `json:"sni"`
	Error   string `json:"error"`
}

// MassTest parses each URI and measures TCP connect (ping) plus TLS-handshake/
// relay delay against the config's own server. It does not need xray. Results
// are sorted reachable-first, then by lowest relay delay.
func MassTest(uris []string, timeout time.Duration) []MassRow {
	rows := make([]MassRow, len(uris))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for i, u := range uris {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, u string) {
			defer wg.Done()
			defer func() { <-sem }()
			rows[i] = massOne(u, timeout)
		}(i, u)
	}
	wg.Wait()
	sort.SliceStable(rows, func(a, b int) bool {
		if rows[a].OK != rows[b].OK {
			return rows[a].OK
		}
		ra, rb := rows[a].RelayMs, rows[b].RelayMs
		if ra < 0 {
			ra = 1 << 30
		}
		if rb < 0 {
			rb = 1 << 30
		}
		return ra < rb
	})
	return rows
}

func massOne(uri string, timeout time.Duration) MassRow {
	p := sni.ParseURI(uri)
	row := MassRow{URI: uri, PingMs: -1, RelayMs: -1}
	if !p.Valid {
		row.Error = "parse: " + p.Error
		return row
	}
	row.Host, row.Port, row.SNI = p.Host, p.Port, p.SNI
	row.Name = p.Protocol + "@" + p.Host + ":" + strconv.Itoa(p.Port)
	r := sni.RelayTest(p.Host, p.Port, p.SNI, timeout)
	row.PingMs = r.TCPMs
	if r.TCPMs >= 0 && r.TLSMs >= 0 {
		row.RelayMs = r.TLSMs + maxInt(r.RelayMs, 0)
	}
	row.OK = r.OK
	row.Error = r.Error
	return row
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ---- persistent on-device runner ------------------------------------------

// RunOptions configures a long-running xray instance the device can use.
type RunOptions struct {
	URI        string
	BinPath    string
	SocksPort  int    // local SOCKS inbound (default 10808)
	ListenHost string // 127.0.0.1, or 0.0.0.0 to share on the LAN
	ProxyHost  string // when !Direct, route the outbound through this local proxy
	ProxyPort  int
	Direct     bool // connect straight to the config server (default behaviour)
}

// Runner supervises a persistent xray process exposing a local SOCKS proxy.
type Runner struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	cfgPath string
	bin     string
	uri     string
	listen  string
	port    int
	log     LogFunc
}

// NewRunner creates a Runner. log may be nil.
func NewRunner(log LogFunc) *Runner {
	if log == nil {
		log = func(string, string) {}
	}
	return &Runner{log: log}
}

// Running reports whether xray is currently supervised.
func (r *Runner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cmd != nil
}

// Status returns a snapshot for the UI.
func (r *Runner) Status() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil {
		return map[string]any{"running": false}
	}
	return map[string]any{
		"running": true,
		"socks":   net.JoinHostPort(r.listen, strconv.Itoa(r.port)),
		"uri":     r.uri,
		"bin":     r.bin,
	}
}

// Start launches xray with a SOCKS inbound for device-wide use.
func (r *Runner) Start(opts RunOptions) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil {
		return errors.New("xray already running")
	}
	bin := ResolveBin(opts.BinPath)
	if bin == "" {
		return errors.New("xray binary not found — set its path or use Download")
	}
	p := sni.ParseURI(opts.URI)
	if !p.Valid {
		return errors.New("invalid URI: " + p.Error)
	}
	if opts.SocksPort == 0 {
		opts.SocksPort = 10808
	}
	if opts.ListenHost == "" {
		opts.ListenHost = "127.0.0.1"
	}
	outHost, outPort := p.Host, p.Port
	if !opts.Direct && opts.ProxyHost != "" {
		outHost, outPort = opts.ProxyHost, opts.ProxyPort
	}
	cfgPath, err := buildConfig(p, outHost, outPort, opts.ListenHost, opts.SocksPort)
	if err != nil {
		return err
	}

	cmd := exec.Command(bin, "-c", cfgPath)
	var out lockBuf
	cmd.Stdout, cmd.Stderr = &out, &out
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		_ = os.Remove(cfgPath)
		return errors.New("failed to start xray: " + err.Error())
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	// Wait until the SOCKS inbound accepts, or xray exits.
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(opts.SocksPort))
	ready := false
	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-waitErr:
			_ = os.Remove(cfgPath)
			return errors.New("xray exited before it was ready" + procDetail(e, out.String()))
		default:
		}
		if c, e := net.DialTimeout("tcp", addr, 300*time.Millisecond); e == nil {
			_ = c.Close()
			ready = true
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !ready {
		_ = cmd.Process.Kill()
		_ = os.Remove(cfgPath)
		return errors.New("xray did not open its SOCKS port" + procDetail(nil, out.String()))
	}

	r.cmd, r.cfgPath, r.bin = cmd, cfgPath, bin
	r.uri, r.listen, r.port = opts.URI, opts.ListenHost, opts.SocksPort
	r.log("xray running — SOCKS5 on "+net.JoinHostPort(opts.ListenHost, strconv.Itoa(opts.SocksPort)), "OK")
	return nil
}

// Stop terminates the supervised xray process.
func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil {
		return
	}
	_ = r.cmd.Process.Kill()
	_, _ = r.cmd.Process.Wait()
	if r.cfgPath != "" {
		_ = os.Remove(r.cfgPath)
	}
	r.cmd, r.cfgPath = nil, ""
	r.log("xray stopped", "WARN")
}

// ---- download from GitHub releases ----------------------------------------

func assetName() (string, error) {
	osName := map[string]string{"windows": "windows", "linux": "linux", "darwin": "macos"}[runtime.GOOS]
	if osName == "" {
		return "", errors.New("unsupported OS: " + runtime.GOOS)
	}
	arch := map[string]string{"amd64": "64", "386": "32", "arm64": "arm64-v8a"}[runtime.GOARCH]
	if arch == "" {
		return "", errors.New("unsupported arch: " + runtime.GOARCH)
	}
	return "Xray-" + osName + "-" + arch + ".zip", nil
}

// Download fetches the latest Xray-core release for this OS/arch from GitHub and
// extracts the binary into destDir. Returns the binary path.
func Download(destDir string, log LogFunc) (string, error) {
	if log == nil {
		log = func(string, string) {}
	}
	if destDir == "" {
		destDir, _ = os.Getwd()
	}
	want, err := assetName()
	if err != nil {
		return "", err
	}
	log("Querying latest Xray-core release…", "ACCENT")
	rel, err := http.Get("https://api.github.com/repos/XTLS/Xray-core/releases/latest")
	if err != nil {
		return "", err
	}
	defer rel.Body.Close()
	var meta struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(rel.Body).Decode(&meta); err != nil {
		return "", err
	}
	var url string
	for _, a := range meta.Assets {
		if a.Name == want {
			url = a.URL
			break
		}
	}
	if url == "" {
		return "", errors.New("no asset " + want + " in release " + meta.Tag)
	}
	log("Downloading "+want+" ("+meta.Tag+")…", "ACCENT")
	dl, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer dl.Body.Close()
	data, err := io.ReadAll(dl.Body)
	if err != nil {
		return "", err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	binName := "xray"
	if runtime.GOOS == "windows" {
		binName = "xray.exe"
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != binName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		defer rc.Close()
		dest := filepath.Join(destDir, binName)
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			return "", err
		}
		out.Close()
		log("✓ Xray installed at "+dest, "OK")
		return dest, nil
	}
	return "", errors.New(binName + " not found inside the release archive")
}
