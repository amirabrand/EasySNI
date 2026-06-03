// Package singbox detects, downloads, and runs sing-box (SagerNet/sing-box).
// Its headline use here is real TUN mode: sing-box brings up a system TUN
// device with auto_route, so all OS traffic is routed through the selected
// share-link outbound — a genuine system-wide VPN, not just a local SOCKS port.
// Running TUN requires administrator/root privileges on the user's machine.
package singbox

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"ezsni/internal/ghdl"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"ezsni/internal/sni"
)

// LogFunc receives progress/log lines.
type LogFunc func(msg, level string)

// binName is the platform binary filename.
func binName() string {
	if runtime.GOOS == "windows" {
		return "sing-box.exe"
	}
	return "sing-box"
}

// Find locates a sing-box binary on PATH or next to the running executable.
func Find() string {
	if p, err := exec.LookPath(binName()); err == nil {
		return p
	}
	var roots []string
	if exe, err := os.Executable(); err == nil {
		roots = append(roots, filepath.Dir(exe))
	}
	if cwd, err := os.Getwd(); err == nil {
		roots = append(roots, cwd)
	}
	for _, r := range roots {
		for _, sub := range []string{"", "singbox"} {
			cand := filepath.Join(r, sub, binName())
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				return cand
			}
		}
	}
	return ""
}

// ResolveBin returns explicit if set and present, else Find().
func ResolveBin(explicit string) string {
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		if st, err := os.Stat(explicit); err == nil && !st.IsDir() {
			return explicit
		}
	}
	return Find()
}

// assetSuffix returns the sing-box release asset suffix for this OS/arch and
// whether it is a zip (Windows) versus tar.gz.
func assetSuffix() (osArch string, isZip bool) {
	goos := runtime.GOOS
	arch := runtime.GOARCH // amd64, arm64, 386, arm
	switch arch {
	case "amd64":
		arch = "amd64"
	case "arm64":
		arch = "arm64"
	case "386":
		arch = "386"
	}
	return goos + "-" + arch, goos == "windows"
}

// Download fetches the latest sing-box release for this platform and installs
// the binary into destDir. Returns the installed path.
func Download(destDir string, log LogFunc) (string, error) {
	if log == nil {
		log = func(string, string) {}
	}
	if destDir == "" {
		destDir, _ = os.Getwd()
	}
	osArch, isZip := assetSuffix()
	log("Resolving latest sing-box release…", "ACCENT")
	tag, err := ghdl.LatestTag("SagerNet/sing-box")
	if err != nil {
		return "", err
	}
	ver := strings.TrimPrefix(tag, "v")
	wantExt := ".tar.gz"
	if isZip {
		wantExt = ".zip"
	}
	name := "sing-box-" + ver + "-" + osArch + wantExt
	url := ghdl.AssetURL("SagerNet/sing-box", tag, name)
	log("Downloading "+name+" ("+tag+")…", "ACCENT")
	data, err := ghdl.Download(url)
	if err != nil {
		return "", err
	}
	var paths []string
	if isZip {
		paths, err = ghdl.ExtractZip(data, destDir)
	} else {
		paths, err = ghdl.ExtractTarGz(data, destDir)
	}
	if err != nil {
		return "", err
	}
	bin := ghdl.PickBinary(paths, binName(), "sing-box")
	if bin == "" {
		return "", errors.New(binName() + " not found inside the release archive")
	}
	log("✓ sing-box extracted to "+destDir, "OK")
	return bin, nil
}

func extractZip(data []byte, dest string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	win := runtime.GOOS == "windows"
	var pick *zip.File
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if filepath.Base(f.Name) == binName() {
			pick = f
			break
		}
	}
	if pick == nil { // fallback: largest regular file (the sing-box binary)
		var maxSize uint64
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			if win && !strings.HasSuffix(strings.ToLower(f.Name), ".exe") {
				continue
			}
			if f.UncompressedSize64 >= maxSize {
				maxSize = f.UncompressedSize64
				pick = f
			}
		}
	}
	if pick == nil {
		return errors.New(binName() + " not found inside the release archive")
	}
	rc, err := pick.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	return writeBin(rc, dest)
}

func extractTarGz(data []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) == binName() && hdr.Typeflag == tar.TypeReg {
			return writeBin(tr, dest)
		}
	}
	return errors.New(binName() + " not found inside the release archive")
}

func writeBin(r io.Reader, dest string) error {
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, r)
	return err
}

// outboundFromURI maps a parsed share link to a sing-box outbound object.
func outboundFromURI(p sni.ParsedURI) (map[string]any, error) {
	if !p.Valid {
		return nil, errors.New("invalid URI")
	}
	ob := map[string]any{"tag": "proxy", "server": p.Host, "server_port": p.Port}

	// TLS settings (with uTLS Chrome fingerprint for better DPI resistance).
	if p.TLS {
		ob["tls"] = map[string]any{
			"enabled":     true,
			"server_name": p.SNI,
			"insecure":    true,
			"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
		}
	}
	// WebSocket transport.
	if p.Type == "ws" {
		path := p.Path
		if path == "" {
			path = "/"
		}
		ob["transport"] = map[string]any{
			"type":    "ws",
			"path":    path,
			"headers": map[string]any{"Host": p.SNI},
		}
	}

	switch p.Protocol {
	case "trojan":
		ob["type"] = "trojan"
		ob["password"] = p.Password
	case "shadowsocks":
		ob["type"] = "shadowsocks"
		ob["method"] = p.Method
		ob["password"] = p.Password
		delete(ob, "tls")
		delete(ob, "transport")
	case "vmess":
		ob["type"] = "vmess"
		ob["uuid"] = p.UUID
		ob["security"] = "auto"
		ob["alter_id"] = 0
	default: // vless
		ob["type"] = "vless"
		ob["uuid"] = p.UUID
	}
	return ob, nil
}

// BuildConfig writes a sing-box JSON config to a temp file. When tun is true it
// uses a system TUN inbound (auto_route → all traffic). Otherwise it exposes a
// local SOCKS inbound on socksPort.
func BuildConfig(uri string, tun bool, socksPort int) (string, error) {
	p := sni.ParseURI(uri)
	ob, err := outboundFromURI(p)
	if err != nil {
		return "", err
	}
	var inbound map[string]any
	route := map[string]any{"auto_detect_interface": true, "final": "proxy"}
	if tun {
		inbound = map[string]any{
			"type":           "tun",
			"tag":            "tun-in",
			"interface_name": "v2rayez-tun",
			"address":        []any{"172.19.0.1/30"},
			"auto_route":     true,
			"strict_route":   true,
			"stack":          "system",
			"sniff":          true,
		}
	} else {
		inbound = map[string]any{
			"type":        "socks",
			"tag":         "socks-in",
			"listen":      "127.0.0.1",
			"listen_port": socksPort,
			"sniff":       true,
		}
	}
	cfg := map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []any{inbound},
		"outbounds": []any{ob, map[string]any{"type": "direct", "tag": "direct"}},
		"route":     route,
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "singbox_*.json")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// Runner supervises a persistent sing-box process.
type Runner struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	cfgPath  string
	running  bool
	tun      bool
	socks    int
	uri      string
	startErr string
	log      LogFunc
}

// NewRunner creates a runner that emits logs via log.
func NewRunner(log LogFunc) *Runner {
	if log == nil {
		log = func(string, string) {}
	}
	return &Runner{log: log}
}

// Start launches sing-box for uri. tun selects system TUN mode; otherwise a
// local SOCKS proxy on socksPort. An already-running instance is stopped first.
func (r *Runner) Start(bin, uri string, tun bool, socksPort int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopLocked()

	bin = ResolveBin(bin)
	if bin == "" {
		return errors.New("sing-box binary not found — click Download or set its path")
	}
	cfgPath, err := BuildConfig(uri, tun, socksPort)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "run", "-c", cfgPath)
	if err := cmd.Start(); err != nil {
		os.Remove(cfgPath)
		return err
	}
	r.cmd = cmd
	r.cfgPath = cfgPath
	r.running = true
	r.tun = tun
	r.socks = socksPort
	r.uri = uri
	r.startErr = ""
	mode := "SOCKS 127.0.0.1:" + strconv.Itoa(socksPort)
	if tun {
		mode = "system-wide TUN (v2rayez-tun)"
	}
	r.log("sing-box started — "+mode, "OK")
	go func(c *exec.Cmd, path string) {
		err := c.Wait()
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.cmd == c {
			r.running = false
			r.cmd = nil
			os.Remove(path)
			if err != nil {
				r.startErr = err.Error()
				r.log("sing-box exited: "+err.Error(), "ERROR")
			}
		}
	}(cmd, cfgPath)
	return nil
}

func (r *Runner) stopLocked() {
	if r.cmd != nil && r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
	}
	if r.cfgPath != "" {
		os.Remove(r.cfgPath)
		r.cfgPath = ""
	}
	r.cmd = nil
	r.running = false
}

// Stop terminates sing-box.
func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		r.log("sing-box stopped", "DIM")
	}
	r.stopLocked()
}

// Running reports whether sing-box is up.
func (r *Runner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

// Status returns a snapshot for the UI.
func (r *Runner) Status() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]any{
		"running": r.running,
		"tun":     r.tun,
		"socks":   r.socks,
		"uri":     r.uri,
		"error":   r.startErr,
	}
}
