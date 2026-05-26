package splus

import "ezsni/internal/protocol"

// Role selects which end of the tunnel to run.
type Role string

const (
	RoleServer Role = "server"
	RoleClient Role = "client"
)

// Options configures a tunnel.
type Options struct {
	Role      Role
	Token     string // LiveKit access_token from the SoroushPlus call
	URL       string // LiveKit URL; defaults to DefaultLKURL
	SocksHost string // client only; defaults to DefaultSocksHost
	SocksPort int    // client only; defaults to DefaultSocksPort
	SocksUser string // client only; optional SOCKS5 username (LAN auth)
	SocksPass string // client only; optional SOCKS5 password
}

// Tunnel is a running server or client instance.
type Tunnel struct {
	role  Role
	tr    Transport
	socks *SocksServer
	srv   *ServerRelay
	cli   *ClientRelay
}

// Start builds the transport, wires up the relay, connects, and (for a client)
// opens the local SOCKS5 listener.
func Start(opts Options, log LogFunc) (*Tunnel, error) {
	if log == nil {
		log = func(string, string) {}
	}
	url := opts.URL
	if url == "" {
		url = DefaultLKURL
	}

	tr, err := NewTransport(url, opts.Token, log)
	if err != nil {
		return nil, err
	}

	t := &Tunnel{role: opts.Role, tr: tr}

	switch opts.Role {
	case RoleServer:
		t.srv = NewServerRelay(tr, log)
		tr.SetOnMessage(func(raw []byte) {
			if m, ok := protocol.Decode(raw); ok {
				t.srv.Handle(m)
			}
		})
	default: // client
		t.cli = NewClientRelay(tr, log)
		tr.SetOnMessage(func(raw []byte) {
			if m, ok := protocol.Decode(raw); ok {
				t.cli.Handle(m)
			}
		})
	}

	if err := tr.Connect(); err != nil {
		_ = tr.Close()
		return nil, err
	}

	if opts.Role == RoleClient {
		host := opts.SocksHost
		if host == "" {
			host = DefaultSocksHost
		}
		port := opts.SocksPort
		if port == 0 {
			port = DefaultSocksPort
		}
		t.socks = NewSocksServer(t.cli, log)
		t.socks.SetAuth(opts.SocksUser, opts.SocksPass)
		if err := t.socks.Start(host, port); err != nil {
			_ = tr.Close()
			return nil, err
		}
	}

	log("tunnel started in "+string(opts.Role)+" mode", "OK")
	return t, nil
}

// Stats returns bytes received/transmitted over the data channel.
func (t *Tunnel) Stats() (rx, tx uint64) {
	if t.tr == nil {
		return 0, 0
	}
	return t.tr.Stats()
}

// Stop tears everything down.
func (t *Tunnel) Stop() {
	if t.socks != nil {
		t.socks.Stop()
	}
	if t.cli != nil {
		t.cli.CloseAll()
	}
	if t.srv != nil {
		t.srv.CloseAll()
	}
	if t.tr != nil {
		_ = t.tr.Close()
	}
}
