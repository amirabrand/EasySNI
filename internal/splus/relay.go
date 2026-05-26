package splus

import (
	"net"
	"strconv"
	"sync"
	"time"

	"ezsni/internal/protocol"
)

// ---------------------------------------------------------------------------
// Server side: accepts Connect frames, dials the real destination, and pumps
// bytes back as Data frames. Port of relay.py ServerRelay.
// ---------------------------------------------------------------------------

type ServerRelay struct {
	tx   Sender
	log  LogFunc
	mu   sync.Mutex
	sess map[string]net.Conn
}

func NewServerRelay(tx Sender, log LogFunc) *ServerRelay {
	if log == nil {
		log = func(string, string) {}
	}
	return &ServerRelay{tx: tx, log: log, sess: make(map[string]net.Conn)}
}

func (r *ServerRelay) Handle(m protocol.Msg) {
	switch m.T {
	case protocol.KindConnect:
		go r.connect(m.SID, m.Host, m.Port)
	case protocol.KindData:
		r.mu.Lock()
		c := r.sess[m.SID]
		r.mu.Unlock()
		if c != nil {
			_, _ = c.Write(m.Data)
		}
	case protocol.KindClose:
		r.mu.Lock()
		c := r.sess[m.SID]
		delete(r.sess, m.SID)
		r.mu.Unlock()
		if c != nil {
			_ = c.Close()
		}
	}
}

func (r *ServerRelay) connect(sid, host string, port uint16) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		r.log("relay "+sid[:8]+" -> "+addr+" FAIL: "+err.Error(), "WARN")
		_ = r.tx.Send(protocol.Encode(protocol.Msg{T: protocol.KindAck, SID: sid, OK: false}))
		return
	}
	r.mu.Lock()
	r.sess[sid] = c
	r.mu.Unlock()
	r.log("relay "+sid[:8]+" -> "+addr+" OK", "OK")
	_ = r.tx.Send(protocol.Encode(protocol.Msg{T: protocol.KindAck, SID: sid, OK: true}))
	go r.relayLoop(sid, c)
}

func (r *ServerRelay) relayLoop(sid string, c net.Conn) {
	buf := make([]byte, ChunkSize)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			_ = r.tx.Send(protocol.Encode(protocol.Msg{T: protocol.KindData, SID: sid, Data: buf[:n]}))
		}
		if err != nil {
			break
		}
	}
	r.mu.Lock()
	delete(r.sess, sid)
	r.mu.Unlock()
	_ = r.tx.Send(protocol.Encode(protocol.Msg{T: protocol.KindClose, SID: sid}))
}

// CloseAll tears down any live upstream connections.
func (r *ServerRelay) CloseAll() {
	r.mu.Lock()
	for _, c := range r.sess {
		_ = c.Close()
	}
	r.sess = make(map[string]net.Conn)
	r.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Client side: each accepted SOCKS5 connection becomes a session. Bytes from
// the local app are buffered until the server acks the Connect, then streamed
// as Data frames. Port of relay.py ClientRelay.
// ---------------------------------------------------------------------------

type clientSession struct {
	conn      net.Conn
	mu        sync.Mutex
	connected bool
	queue     [][]byte
}

type ClientRelay struct {
	tx   Sender
	log  LogFunc
	mu   sync.Mutex
	sess map[string]*clientSession
}

func NewClientRelay(tx Sender, log LogFunc) *ClientRelay {
	if log == nil {
		log = func(string, string) {}
	}
	return &ClientRelay{tx: tx, log: log, sess: make(map[string]*clientSession)}
}

// SOCKS5 reply frames (success / general failure).
var (
	socksReplyOK   = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	socksReplyFail = []byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}
)

// NewSession registers a SOCKS5 connection and asks the server to connect.
func (r *ClientRelay) NewSession(host string, port uint16, conn net.Conn) {
	sid := protocol.MakeSID()
	s := &clientSession{conn: conn}
	r.mu.Lock()
	r.sess[sid] = s
	r.mu.Unlock()
	_ = r.tx.Send(protocol.Encode(protocol.Msg{T: protocol.KindConnect, SID: sid, Host: host, Port: port}))
	go r.readLoop(sid, s)
}

func (r *ClientRelay) Handle(m protocol.Msg) {
	switch m.T {
	case protocol.KindAck:
		r.mu.Lock()
		s := r.sess[m.SID]
		r.mu.Unlock()
		if s == nil {
			return
		}
		if m.OK {
			s.mu.Lock()
			s.connected = true
			_, _ = s.conn.Write(socksReplyOK)
			q := s.queue
			s.queue = nil
			s.mu.Unlock()
			for _, chunk := range q {
				_ = r.tx.Send(protocol.Encode(protocol.Msg{T: protocol.KindData, SID: m.SID, Data: chunk}))
			}
		} else {
			_, _ = s.conn.Write(socksReplyFail)
			_ = s.conn.Close()
			r.mu.Lock()
			delete(r.sess, m.SID)
			r.mu.Unlock()
		}
	case protocol.KindData:
		r.mu.Lock()
		s := r.sess[m.SID]
		r.mu.Unlock()
		if s != nil {
			_, _ = s.conn.Write(m.Data)
		}
	case protocol.KindClose:
		r.mu.Lock()
		s := r.sess[m.SID]
		delete(r.sess, m.SID)
		r.mu.Unlock()
		if s != nil {
			_ = s.conn.Close()
		}
	}
}

func (r *ClientRelay) readLoop(sid string, s *clientSession) {
	buf := make([]byte, ChunkSize)
	for {
		r.mu.Lock()
		_, alive := r.sess[sid]
		r.mu.Unlock()
		if !alive {
			break
		}
		n, err := s.conn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			s.mu.Lock()
			connected := s.connected
			if !connected {
				s.queue = append(s.queue, chunk)
			}
			s.mu.Unlock()
			if connected {
				_ = r.tx.Send(protocol.Encode(protocol.Msg{T: protocol.KindData, SID: sid, Data: chunk}))
			}
		}
		if err != nil {
			break
		}
	}
	r.mu.Lock()
	delete(r.sess, sid)
	r.mu.Unlock()
	_ = r.tx.Send(protocol.Encode(protocol.Msg{T: protocol.KindClose, SID: sid}))
}

// CloseAll closes all live SOCKS5 connections.
func (r *ClientRelay) CloseAll() {
	r.mu.Lock()
	for _, s := range r.sess {
		_ = s.conn.Close()
	}
	r.sess = make(map[string]*clientSession)
	r.mu.Unlock()
}
