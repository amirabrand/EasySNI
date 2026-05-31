package mitmdf

import (
	"bufio"
	"errors"
	"net"
	"sync/atomic"
)

// newBufReader wraps a connection so peeked/buffered bytes aren't lost.
func newBufReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

// peekConn lets an http.Server read through a bufio.Reader that may already hold
// buffered bytes (so the first request peeked in handle() isn't lost).
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// oneConnListener is a net.Listener that yields a single pre-accepted
// connection to http.Server.Serve, then returns an error so Serve exits (the
// connection keeps being served on its own goroutine, with keep-alive).
type oneConnListener struct {
	conn net.Conn
	addr net.Addr
	used int32
}

var errListenerDone = errors.New("v2rayez-mitmdf: one-shot listener done")

func (l *oneConnListener) Accept() (net.Conn, error) {
	if atomic.CompareAndSwapInt32(&l.used, 0, 1) {
		return l.conn, nil
	}
	return nil, errListenerDone
}

func (l *oneConnListener) Close() error { return nil }

func (l *oneConnListener) Addr() net.Addr {
	if l.addr != nil {
		return l.addr
	}
	return dummyAddr("v2rayez-mitmdf")
}

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }
