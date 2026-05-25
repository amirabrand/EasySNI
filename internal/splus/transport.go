// Package splus ports SPlusTunnel: a SOCKS5-over-LiveKit tunnel. A server (on
// free internet) and a client (restricted) join the same LiveKit room and relay
// TCP streams over the WebRTC data channel using package protocol.
package splus

import "errors"

// DefaultLKURL is SoroushPlus's LiveKit signalling endpoint (settings.LK_URL).
const DefaultLKURL = "wss://k.splus.ir:8446"

// SOCKS5 listen defaults (settings.SOCKS5_HOST / SOCKS5_PORT).
const (
	DefaultSocksHost = "0.0.0.0"
	DefaultSocksPort = 1080
)

// ChunkSize is the read size for relayed streams (settings.CHUNK_SIZE).
const ChunkSize = 4000

// LogFunc receives status lines.
type LogFunc func(msg, level string)

// Sender publishes an encoded frame onto the tunnel.
type Sender interface {
	Send(data []byte) error
}

// Transport is the LiveKit room abstraction. Build with -tags livekit to get a
// real implementation; otherwise NewTransport returns an explanatory error.
type Transport interface {
	Sender
	SetOnMessage(func([]byte))
	Connect() error
	Close() error
	Stats() (rx, tx uint64)
}

// newTransport is wired up by transport_livekit.go (build tag "livekit").
var newTransport func(url, token string, log LogFunc) (Transport, error)

// ErrNoLiveKit explains how to enable the real transport.
var ErrNoLiveKit = errors.New(
	"LiveKit transport not compiled in — enable it with:\n" +
		"    go get github.com/livekit/server-sdk-go/v2@latest\n" +
		"    go build -tags livekit",
)

// NewTransport constructs a Transport for the given LiveKit URL and token.
func NewTransport(url, token string, log LogFunc) (Transport, error) {
	if newTransport == nil {
		return nil, ErrNoLiveKit
	}
	return newTransport(url, token, log)
}
