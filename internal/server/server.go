// Package server exposes the suite over a local web UI: an embedded single-page
// control panel, a Server-Sent-Events log stream, and JSON endpoints backing
// each tab (proxy control, SNI/relay/mass scans, Cloudflare scan, URI parsing,
// and the SPlus tunnel).
package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"ezsni/internal/desync"
	"ezsni/internal/logbus"
	"ezsni/internal/proxy"
	"ezsni/internal/psiphon"
	"ezsni/internal/splus"
	"ezsni/internal/xray"
)

//go:embed web/index.html
var webFS embed.FS

// Server holds the shared application state.
type Server struct {
	bus *logbus.Bus

	mu             sync.Mutex
	proxy          *proxy.Proxy
	tunnel         *splus.Tunnel
	tunOpts        splus.Options
	desyncDefaults desync.Config
	xrayRunner     *xray.Runner
	psi            *psiphon.Controller
}

// New returns a Server with a fresh log bus.
func New() *Server {
	s := &Server{bus: logbus.New(), desyncDefaults: desync.DefaultConfig()}
	s.xrayRunner = xray.NewRunner(s.bus.Log)
	s.psi = psiphon.New()
	return s
}

// SetDesyncDefaults sets the baseline DPI-evasion config (from CLI flags) used
// for the proxy when the UI request leaves fields unset.
func (s *Server) SetDesyncDefaults(d desync.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.desyncDefaults = d
}

func (s *Server) log(msg, level string) { s.bus.Log(msg, level) }

// Handler builds the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/uri/parse", s.jsonPOST(s.handleParseURI))
	mux.HandleFunc("/api/sni/scan", s.jsonPOST(s.handleSNIScan))
	mux.HandleFunc("/api/sni/relay-test", s.jsonPOST(s.handleRelayTest))
	mux.HandleFunc("/api/sni/mass-scan", s.jsonPOST(s.handleMassScan))
	mux.HandleFunc("/api/cf/scan", s.jsonPOST(s.handleCFScan))
	mux.HandleFunc("/api/proxy/start", s.jsonPOST(s.handleProxyStart))
	mux.HandleFunc("/api/proxy/stop", s.jsonPOST(s.handleProxyStop))
	mux.HandleFunc("/api/proxy/status", s.jsonPOST(s.handleProxyStatus))
	mux.HandleFunc("/api/splus/start", s.jsonPOST(s.handleSplusStart))
	mux.HandleFunc("/api/splus/stop", s.jsonPOST(s.handleSplusStop))
	mux.HandleFunc("/api/splus/status", s.jsonPOST(s.handleSplusStatus))
	mux.HandleFunc("/api/xray/test", s.jsonPOST(s.handleXrayTest))
	mux.HandleFunc("/api/xray/mass", s.jsonPOST(s.handleXrayMass))
	mux.HandleFunc("/api/xray/find", s.jsonPOST(s.handleXrayFind))
	mux.HandleFunc("/api/xray/download", s.jsonPOST(s.handleXrayDownload))
	mux.HandleFunc("/api/xray/start", s.jsonPOST(s.handleXrayStart))
	mux.HandleFunc("/api/xray/stop", s.jsonPOST(s.handleXrayStop))
	mux.HandleFunc("/api/xray/status", s.jsonPOST(s.handleXrayStatus))
	mux.HandleFunc("/api/windivert/status", s.jsonPOST(s.handleWinDivertStatus))
	mux.HandleFunc("/api/windivert/install", s.jsonPOST(s.handleWinDivertInstall))
	mux.HandleFunc("/api/windivert/uninstall", s.jsonPOST(s.handleWinDivertUninstall))
	mux.HandleFunc("/api/port/check", s.jsonPOST(s.handlePortCheck))
	mux.HandleFunc("/api/lan/info", s.jsonPOST(s.handleLANInfo))
	mux.HandleFunc("/api/cdn/scan", s.jsonPOST(s.handleCDNScan))
	mux.HandleFunc("/api/psiphon/start", s.jsonPOST(s.handlePsiphonStart))
	mux.HandleFunc("/api/psiphon/stop", s.jsonPOST(s.handlePsiphonStop))
	mux.HandleFunc("/api/psiphon/status", s.jsonPOST(s.handlePsiphonStatus))
	return mux
}

// Bus exposes the log bus so main can print a welcome banner.
func (s *Server) Bus() *logbus.Bus { return s.bus }

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "ui missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// handleEvents streams log entries to the browser via SSE.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, backlog, cancel := s.bus.Subscribe()
	defer cancel()
	for _, e := range backlog {
		writeSSE(w, e)
	}
	flusher.Flush()

	ctx := r.Context()
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			writeSSE(w, e)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, e logbus.Entry) {
	b, _ := json.Marshal(e)
	fmt.Fprintf(w, "data: %s\n\n", b)
}

// jsonPOST wraps a handler that decodes JSON and returns a value to encode.
func (s *Server) jsonPOST(fn func(body json.RawMessage) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var raw json.RawMessage
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
				writeJSON(w, map[string]any{"error": "bad json: " + err.Error()})
				return
			}
		}
		out, err := fn(raw)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, out)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
