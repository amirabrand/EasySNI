//go:build psiphon

package psiphon

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/ClientLibrary/clientlib"
)

// runPsiphon starts a real Psiphon tunnel configured to dial out through the
// given upstream proxy and to expose local SOCKS5/HTTP proxies.
//
// NOTE: compiled only with -tags psiphon (pulls in psiphon-tunnel-core and its
// dependencies). It follows the clientlib API; verify against the SDK version
// you pin, as Psiphon config keys evolve. You must supply your own Psiphon
// config/sponsor values via the PSIPHON_CONFIG env var or embed them here.
func runPsiphon(opts Options, log LogFunc) (func(), int, int, error) {
	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir, _ = os.MkdirTemp("", "psiphon")
	}

	// Base config. A real deployment needs valid PropagationChannelId /
	// SponsorId values from Psiphon; load them from PSIPHON_CONFIG if present.
	cfg := map[string]any{
		"LocalSocksProxyPort":    opts.LocalSocksPort,
		"LocalHttpProxyPort":     opts.LocalHTTPPort,
		"UpstreamProxyUrl":       opts.UpstreamProxyURL,
		"EmitDiagnosticNotices":  true,
		"DisableLocalSocksProxy": false,
		"DisableLocalHTTPProxy":  false,
	}
	if raw := os.Getenv("PSIPHON_CONFIG"); raw != "" {
		var extra map[string]any
		if err := json.Unmarshal([]byte(raw), &extra); err == nil {
			for k, v := range extra {
				cfg[k] = v
			}
		}
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, 0, 0, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	params := clientlib.Parameters{DataRootDirectory: &dataDir}

	tunnel, err := clientlib.StartTunnel(ctx, cfgJSON, "", params, nil,
		func(notice clientlib.NoticeEvent) {
			if notice.Type == "Tunnels" {
				log("Psiphon: "+notice.Type, "DIM")
			}
		})
	if err != nil {
		cancel()
		return nil, 0, 0, err
	}

	stop := func() {
		tunnel.Stop()
		cancel()
		_ = time.AfterFunc(0, func() {})
	}
	return stop, tunnel.SOCKSProxyPort, tunnel.HTTPProxyPort, nil
}
