// Package tor runs the Tor client as a subprocess with optional pluggable
// transports (obfs4, meek, snowflake, webtunnel) and exposes a local SOCKS
// port. It needs the `tor` binary and, for transports, the matching pluggable
// transport binary (obfs4proxy/lyrebird, snowflake-client, …) — both shipped in
// the Tor Expert Bundle. Routing to TUN is done by the tun2socks package.
package tor

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// LogFunc receives log lines.
type LogFunc func(msg, level string)

// Options configure a Tor run.
type Options struct {
	BinPath   string `json:"bin_path"`   // path to the tor binary ("" = auto)
	PTPath    string `json:"pt_path"`    // pluggable-transport binary ("" = auto)
	Transport string `json:"transport"`  // none|obfs4|meek_lite|snowflake|webtunnel
	Bridges   string `json:"bridges"`    // newline-separated bridge lines
	SocksPort int    `json:"socks_port"` // local SOCKS (default 9050)
	DataDir   string `json:"data_dir"`
}

func binNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"tor.exe"}
	}
	return []string{"tor"}
}

func ptNames(transport string) []string {
	exe := func(n string) string {
		if runtime.GOOS == "windows" {
			return n + ".exe"
		}
		return n
	}
	switch transport {
	case "snowflake":
		return []string{exe("snowflake-client"), exe("client")}
	case "conjure":
		return []string{exe("conjure-client"), exe("client")}
	case "webtunnel":
		// recent lyrebird provides webtunnel; fall back to a dedicated client
		return []string{exe("lyrebird"), exe("webtunnel-client"), exe("webtunnel"), exe("obfs4proxy")}
	default: // obfs4 / meek_lite are provided by lyrebird (formerly obfs4proxy)
		return []string{exe("lyrebird"), exe("obfs4proxy")}
	}
}

// Find locates the tor binary near the app, in a Tor/ or tor/ subdir, or PATH.
func Find() string { return findIn(binNames(), []string{".", "tor", "Tor", "Browser/TorBrowser/Tor"}) }

// FindPT locates a pluggable-transport binary for the transport.
func FindPT(transport string) string {
	return findIn(ptNames(transport), []string{".", "tor", "pluggable_transports", "PluggableTransports", "Browser/TorBrowser/Tor/PluggableTransports"})
}

func findIn(names, subdirs []string) string {
	var roots []string
	if exe, err := os.Executable(); err == nil {
		roots = append(roots, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		roots = append(roots, wd)
	}
	for _, r := range roots {
		for _, sd := range subdirs {
			for _, n := range names {
				p := filepath.Join(r, sd, n)
				if st, err := os.Stat(p); err == nil && !st.IsDir() {
					return p
				}
			}
		}
	}
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// findGeoIP locates geoip / geoip6 files shipped in the Tor bundle (next to the
// tor binary or in the tor/ folder), returning their paths if present.
func findGeoIP(binPath string) (string, string) {
	var dirs []string
	if binPath != "" {
		dirs = append(dirs, filepath.Dir(binPath))
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe), filepath.Join(filepath.Dir(exe), "tor"))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd, filepath.Join(wd, "tor"))
	}
	find := func(name string) string {
		for _, d := range dirs {
			p := filepath.Join(d, name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
		return ""
	}
	return find("geoip"), find("geoip6")
}

// BuildTorrc writes a torrc for the given options and returns its path.
func BuildTorrc(o Options, dataDir string) (string, error) {
	var b strings.Builder
	port := o.SocksPort
	if port == 0 {
		port = 9050
	}
	fmt.Fprintf(&b, "SocksPort 127.0.0.1:%d\n", port)
	fmt.Fprintf(&b, "DataDirectory %s\n", dataDir)
	b.WriteString("AvoidDiskWrites 1\n")
	// Point Tor at the GeoIP files if they shipped with the bundle.
	if g, g6 := findGeoIP(o.BinPath); g != "" {
		fmt.Fprintf(&b, "GeoIPFile %s\n", g)
		if g6 != "" {
			fmt.Fprintf(&b, "GeoIPv6File %s\n", g6)
		}
	}

	if o.Transport != "" && o.Transport != "none" {
		ptBin := o.PTPath
		if ptBin == "" {
			ptBin = FindPT(o.Transport)
		}
		if ptBin == "" {
			return "", errors.New("pluggable-transport binary for " + o.Transport + " not found — download Tor + dependencies or set its path")
		}
		b.WriteString("UseBridges 1\n")
		switch o.Transport {
		case "snowflake":
			fmt.Fprintf(&b, "ClientTransportPlugin snowflake exec %s\n", ptBin)
		case "webtunnel":
			fmt.Fprintf(&b, "ClientTransportPlugin webtunnel exec %s\n", ptBin)
		case "meek_lite":
			fmt.Fprintf(&b, "ClientTransportPlugin meek_lite exec %s\n", ptBin)
		case "conjure":
			fmt.Fprintf(&b, "ClientTransportPlugin conjure exec %s\n", ptBin)
		default: // obfs4
			fmt.Fprintf(&b, "ClientTransportPlugin obfs4 exec %s\n", ptBin)
		}
		n := 0
		for _, line := range strings.Split(o.Bridges, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !strings.HasPrefix(strings.ToLower(line), "bridge ") {
				line = "Bridge " + line
			}
			b.WriteString(line + "\n")
			n++
		}
		if n == 0 {
			return "", errors.New("transport " + o.Transport + " selected but no bridge lines were provided")
		}
	}

	path := filepath.Join(dataDir, "torrc")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// Runner supervises a tor process.
type Runner struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	running   bool
	bootstrap int
	socks     int
	log       LogFunc
}

// NewRunner builds a runner.
func NewRunner(log LogFunc) *Runner {
	if log == nil {
		log = func(string, string) {}
	}
	return &Runner{log: log}
}

// Start launches tor with the given options.
func (r *Runner) Start(o Options) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		r.stopLocked()
	}
	bin := o.BinPath
	if bin == "" {
		bin = Find()
	}
	if bin == "" {
		return errors.New("tor binary not found — install the Tor Expert Bundle or set its path")
	}
	if o.SocksPort == 0 {
		o.SocksPort = 9050
	}
	dataDir := o.DataDir
	if dataDir == "" {
		base, _ := os.UserConfigDir()
		if base == "" {
			base, _ = os.Getwd()
		}
		dataDir = filepath.Join(base, "V2RayEz", "tor")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	torrc, err := BuildTorrc(o, dataDir)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "-f", torrc)
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	r.cmd = cmd
	r.running = true
	r.bootstrap = 0
	r.socks = o.SocksPort
	tlabel := o.Transport
	if tlabel == "" {
		tlabel = "none"
	}
	r.log("Tor starting (transport "+tlabel+", SOCKS 127.0.0.1:"+itoa(o.SocksPort)+")…", "OK")
	go r.scan(stdout)
	go func() {
		_ = cmd.Wait()
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
		r.log("Tor process exited", "DIM")
	}()
	return nil
}

func (r *Runner) scan(rc interface{ Read([]byte) (int, error) }) {
	sc := bufio.NewScanner(rc)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "Bootstrapped "); i >= 0 {
			rest := line[i+len("Bootstrapped "):]
			pct := 0
			fmt.Sscanf(rest, "%d", &pct)
			r.mu.Lock()
			r.bootstrap = pct
			r.mu.Unlock()
			r.log("Tor: bootstrapped "+itoa(pct)+"%", "ACCENT")
		} else if strings.Contains(line, "[warn]") || strings.Contains(line, "[err]") {
			r.log("[tor] "+strings.TrimSpace(line), "WARN")
		}
	}
}

func (r *Runner) stopLocked() {
	if r.cmd != nil && r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
	}
	r.cmd = nil
	r.running = false
	r.bootstrap = 0
}

// Stop terminates tor.
func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		r.log("Tor stopped", "DIM")
	}
	r.stopLocked()
}

// Running reports whether tor is up.
func (r *Runner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

// Status returns a UI snapshot.
func (r *Runner) Status() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]any{
		"running": r.running, "bootstrap": r.bootstrap, "socks": r.socks,
		"has_tor": Find() != "",
	}
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
