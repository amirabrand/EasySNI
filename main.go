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
	"runtime"
	"strings"
	"syscall"
	"time"

	"ezsni/internal/desync"
	"ezsni/internal/server"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8765", "address to listen on")
	open := flag.Bool("open", true, "open the UI in the default browser on start")

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

	url := "http://" + *addr + "/"
	banner(bus, url)

	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(1)
		}
	}()

	if *open {
		go openBrowser(url)
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

func banner(bus interface{ Log(string, string) }, url string) {
	bus.Log("EzSNI — DPI Bypass Suite · by MacanDev", "ACCENT")
	bus.Log("Control panel: "+url, "OK")
	bus.Log("SNI proxy, scanners, URI parser, and SPlus LiveKit tunnel ready.", "DIM")
	bus.Log("Note: the SPlus tunnel needs a LiveKit build — see README (go build -tags livekit).", "DIM")
	fmt.Println()
	fmt.Println("  ┌──────────────────────────────────────────────┐")
	fmt.Println("  │   EzSNI  ·  DPI Bypass Suite  ·  by MacanDev   │")
	fmt.Println("  ├──────────────────────────────────────────────┤")
	fmt.Printf("  │   Open: %-38s│\n", url)
	fmt.Println("  │   Press Ctrl-C to stop.                        │")
	fmt.Println("  └──────────────────────────────────────────────┘")
	fmt.Println()
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
