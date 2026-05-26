package splus

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
)

// socks5Negotiate completes SOCKS5 method selection on c, given the client's
// initial greeting bytes. If user is non-empty it requires RFC 1929
// username/password auth; otherwise it selects no-auth.
func socks5Negotiate(c net.Conn, greeting []byte, user, pass string) error {
	if len(greeting) < 2 {
		return errors.New("short greeting")
	}
	methods := greeting[2:]
	has := func(m byte) bool {
		for _, x := range methods {
			if x == m {
				return true
			}
		}
		return false
	}

	if user == "" {
		// No auth required.
		_, err := c.Write([]byte{5, 0})
		return err
	}

	// Require username/password (method 0x02).
	if !has(0x02) {
		_, _ = c.Write([]byte{5, 0xff}) // no acceptable methods
		return errors.New("client offered no username/password method")
	}
	if _, err := c.Write([]byte{5, 0x02}); err != nil {
		return err
	}
	// Sub-negotiation: VER(1) ULEN UNAME PLEN PASSWD
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if head[0] != 0x01 {
		return errors.New("bad auth version")
	}
	uname := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, uname); err != nil {
		return err
	}
	pl := make([]byte, 1)
	if _, err := io.ReadFull(c, pl); err != nil {
		return err
	}
	passwd := make([]byte, int(pl[0]))
	if _, err := io.ReadFull(c, passwd); err != nil {
		return err
	}
	if string(uname) == user && string(passwd) == pass {
		_, err := c.Write([]byte{0x01, 0x00}) // success
		return err
	}
	_, _ = c.Write([]byte{0x01, 0x01}) // failure
	return errors.New("invalid credentials")
}

// SocksServer accepts SOCKS5 connections and hands each off to a ClientRelay.
// Port of socks5.py Socks5Server.
type SocksServer struct {
	relay   *ClientRelay
	log     LogFunc
	ln      net.Listener
	running atomic.Bool
	user    string
	pass    string
}

func NewSocksServer(relay *ClientRelay, log LogFunc) *SocksServer {
	if log == nil {
		log = func(string, string) {}
	}
	return &SocksServer{relay: relay, log: log}
}

// SetAuth enables RFC 1929 username/password authentication. When user is
// empty, the server accepts unauthenticated clients (the default).
func (s *SocksServer) SetAuth(user, pass string) {
	s.user, s.pass = user, pass
}

func (s *SocksServer) Start(host string, port int) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	s.ln = ln
	s.running.Store(true)
	s.log("SOCKS5 listening on "+net.JoinHostPort(host, strconv.Itoa(port)), "ACCENT")
	go s.acceptLoop()
	return nil
}

// Addr returns the bound listener address, or nil before Start.
func (s *SocksServer) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

func (s *SocksServer) Stop() {
	if s.running.CompareAndSwap(true, false) && s.ln != nil {
		_ = s.ln.Close()
	}
}

func (s *SocksServer) acceptLoop() {
	for s.running.Load() {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *SocksServer) handle(c net.Conn) {
	buf := make([]byte, 512)

	// Greeting: VER NMETHODS METHODS...
	n, err := c.Read(buf)
	if err != nil || n < 1 || buf[0] != 5 {
		_ = c.Close()
		return
	}
	if err := socks5Negotiate(c, buf[:n], s.user, s.pass); err != nil {
		s.log("SOCKS5 auth rejected: "+err.Error(), "WARN")
		_ = c.Close()
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	n, err = c.Read(buf)
	if err != nil || n < 4 || buf[0] != 5 || buf[1] != 1 {
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0}) // command not supported
		_ = c.Close()
		return
	}

	var (
		host string
		port uint16
	)
	switch buf[3] {
	case 1: // IPv4
		if n < 10 {
			_ = c.Close()
			return
		}
		host = net.IP(buf[4:8]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case 3: // domain name
		hl := int(buf[4])
		if n < 5+hl+2 {
			_ = c.Close()
			return
		}
		host = string(buf[5 : 5+hl])
		port = binary.BigEndian.Uint16(buf[5+hl : 7+hl])
	case 4: // IPv6 — unsupported, matches original
		_, _ = c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		_ = c.Close()
		return
	default:
		_, _ = c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		_ = c.Close()
		return
	}

	// The relay now owns the connection; it writes the SOCKS reply on ack.
	s.relay.NewSession(host, port, c)
}
