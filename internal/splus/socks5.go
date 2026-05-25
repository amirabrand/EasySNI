package splus

import (
	"encoding/binary"
	"net"
	"strconv"
	"sync/atomic"
)

// SocksServer accepts SOCKS5 connections and hands each off to a ClientRelay.
// Port of socks5.py Socks5Server.
type SocksServer struct {
	relay   *ClientRelay
	log     LogFunc
	ln      net.Listener
	running atomic.Bool
}

func NewSocksServer(relay *ClientRelay, log LogFunc) *SocksServer {
	if log == nil {
		log = func(string, string) {}
	}
	return &SocksServer{relay: relay, log: log}
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
	// Reply: no authentication required.
	if _, err := c.Write([]byte{5, 0}); err != nil {
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
