// Command ezsni launches the local web control panel — EzSNI, a DPI-bypass
// tunnel toolkit. It binds to a loopback address and serves a single-page UI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"ezsni/internal/desync"
	"ezsni/internal/server"
	"ezsni/internal/winctl"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:8765", "address to listen on (default exposes the panel on the LAN)")
	open := flag.Bool("open", true, "open the UI on start (native app window if a Chromium browser is found, else default browser)")
	window := flag.Bool("window", true, "prefer a chromeless native-style window (Chrome/Edge --app) over a browser tab")
	minimize := flag.Bool("minimize", true, "minimize the console window after the UI opens (Windows only)")

	// DPI-evasion defaults (overridable per-start from the UI).
	fakeRepeat := flag.Int("fake-repeat", 1, "number of fake ClientHello injections")
	fakeDelay := flag.Duration("fake-delay", 2*time.Millisecond, "delay after fake injection before forwarding real traffic")
	ackTimeout := flag.Duration("ack-timeout", 2*time.Second, "max wait for the server response after fake injection")
	utlsPreset := flag.String("utls", "firefox", "TLS fingerprint preset; use none for the legacy fixed ClientHello template; run with -h to list all presets")
	enableFrag := flag.Bool("enable-fragment", false, "split the real ClientHello after fake injection")
	fragDelay := flag.Duration("fragment-delay", 500*time.Millisecond, "delay between split real ClientHello writes")
	sniChunk := flag.Int("sni-chunk", 3, "SNI bytes per write when -enable-fragment is set; 0 means the whole hostname; for hcaptcha.com, 3 writes hca, ptc, ha., com")
	bypassMode := flag.String("mode", "none", "bypass mode: none, wrong_checksum, or wrong_seq")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n-utls presets: %s\n", strings.Join(desync.Presets(), ", "))
		fmt.Fprintf(os.Stderr, "-mode values:  none, wrong_checksum, wrong_seq\n")
	}
	flag.Parse()

	if !desync.ValidPreset(*utlsPreset) {
		fmt.Fprintf(os.Stderr, "unknown -utls preset %q; valid: %s\n", *utlsPreset, strings.Join(desync.Presets(), ", "))
		os.Exit(2)
	}
	mode := desync.BypassMode(*bypassMode)
	if mode != desync.ModeNone && mode != desync.ModeWrongChecksum && mode != desync.ModeWrongSeq {
		fmt.Fprintf(os.Stderr, "unknown -mode %q; valid: none, wrong_checksum, wrong_seq\n", *bypassMode)
		os.Exit(2)
	}

	srv := server.New()
	srv.SetDesyncDefaults(desync.Config{
		FakeRepeat:     *fakeRepeat,
		FakeDelay:      *fakeDelay,
		AckTimeout:     *ackTimeout,
		UTLS:           *utlsPreset,
		EnableFragment: *enableFrag,
		FragmentDelay:  *fragDelay,
		SNIChunk:       *sniChunk,
		Mode:           mode,
	})
	bus := srv.Bus()

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot bind %s: %v\n", *addr, err)
		os.Exit(1)
	}

	// When binding on all interfaces, browsers can't fetch http://0.0.0.0/ —
	// open the loopback form and list every LAN address in the banner.
	_, port, _ := net.SplitHostPort(*addr)
	openURL := "http://localhost:" + port + "/"
	banner(bus, openURL, port)

	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(1)
		}
	}()

	if *open {
		if *window {
			go openAppWindow(openURL)
		} else {
			go openBrowser(openURL)
		}
		if *minimize {
			go func() { time.Sleep(1200 * time.Millisecond); winctl.MinimizeConsole() }()
		}
	}

	// Wait for Ctrl-C / SIGTERM, then shut down gracefully.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	bus.Log("shutting down…", "WARN")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}

func banner(bus interface{ Log(string, string) }, url, port string) {
	bus.Log("V2RayEz — DPI Bypass & CDN Toolkit · by MacanDev · @EzAccess1", "ACCENT")
	bus.Log("Control panel: "+url, "OK")
	lanURLs := lanAddresses(port)
	for _, u := range lanURLs {
		bus.Log("LAN access:    "+u, "DIM")
	}
	bus.Log("SNI proxy, scanners, URI parser, and SPlus LiveKit tunnel ready.", "DIM")
	bus.Log("Note: the SPlus tunnel needs a LiveKit build — see README (go build -tags livekit).", "DIM")
	fmt.Println()
	fmt.Println("  ┌──────────────────────────────────────────────────────┐")
	fmt.Println("  │   V2RayEz  ·  DPI Bypass & CDN Toolkit  ·  MacanDev     │")
	fmt.Println("  ├──────────────────────────────────────────────────────┤")
	fmt.Printf("  │   Open: %-46s│\n", url)
	for _, u := range lanURLs {
		fmt.Printf("  │   LAN:  %-46s│\n", u)
	}
	fmt.Println("  │   Press Ctrl-C to stop.                                │")
	fmt.Println("  └──────────────────────────────────────────────────────┘")
	fmt.Println()
}

// lanAddresses returns every non-loopback IPv4 the host advertises, formatted
// as URLs, so the user can reach the panel from phones/other devices.
func lanAddresses(port string) []string {
	out := []string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}
			out = append(out, "http://"+ipNet.IP.String()+":"+port+"/")
		}
	}
	return out
}

func openBrowser(url string) {
	time.Sleep(300 * time.Millisecond)
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd, args = "open", []string{url}
	default:
		cmd, args = "xdg-open", []string{url}
	}
	_ = exec.Command(cmd, args...).Start()
}

// openAppWindow launches a Chromium-based browser (Chrome/Edge/Brave/Chromium)
// in --app mode, giving a chromeless, native-feeling window dedicated to the
// panel. Falls back to the default browser when no Chromium browser is found.
// No CGO and no extra dependencies — it just drives an installed browser.
func openAppWindow(url string) {
	time.Sleep(300 * time.Millisecond)
	bin := findChromium()
	if bin == "" {
		openBrowser(url)
		return
	}
	profile := filepath.Join(os.TempDir(), "v2rayez-window")
	args := []string{
		"--app=" + url,
		"--user-data-dir=" + profile,
		"--no-first-run",
		"--no-default-browser-check",
		"--window-size=1180,820",
	}
	if err := exec.Command(bin, args...).Start(); err != nil {
		openBrowser(url)
	}
}

// findChromium returns the path to an installed Chromium-family browser, or "".
func findChromium() string {
	// PATH lookups first (Linux/macOS, and Windows when on PATH).
	names := []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser", "microsoft-edge", "microsoft-edge-stable", "msedge", "chrome"}
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	// Well-known absolute locations per OS.
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		pf := os.Getenv("ProgramFiles")
		pfx86 := os.Getenv("ProgramFiles(x86)")
		local := os.Getenv("LocalAppData")
		candidates = []string{
			filepath.Join(pf, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(pfx86, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(local, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(pfx86, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(pf, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
			filepath.Join(pfx86, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
		}
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	default:
		candidates = []string{
			"/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
			"/usr/bin/microsoft-edge", "/usr/bin/brave-browser", "/snap/bin/chromium",
		}
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}
