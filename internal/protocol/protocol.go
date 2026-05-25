// Package protocol implements the tiny binary framing used to multiplex many
// TCP streams over a single LiveKit data channel. It is a faithful port of
// SPlusTunnel's protocol.py.
//
// Wire format (big-endian):
//
//	C <sid:6> <port:u16> <hostlen:u8> <host...>   -> open a stream to host:port
//	A <sid:6> <ok:u8>                             -> connect ack (1=ok, 0=fail)
//	D <sid:6> <data...>                           -> payload bytes for a stream
//	X <sid:6>                                     -> close a stream
//
// The session id (SID) travels as 6 raw bytes on the wire but is represented
// in Go as a 12-char lowercase hex string for convenient use as a map key.
package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
)

// Frame kinds.
const (
	KindConnect byte = 'C'
	KindAck     byte = 'A'
	KindData    byte = 'D'
	KindClose   byte = 'X'
)

// Msg is a decoded protocol frame.
type Msg struct {
	T    byte   // frame kind: KindConnect/KindAck/KindData/KindClose
	SID  string // 12-char hex session id
	Host string // KindConnect only
	Port uint16 // KindConnect only
	OK   bool   // KindAck only
	Data []byte // KindData only
}

// MakeSID returns a fresh random 12-char hex session id (6 random bytes).
func MakeSID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Encode serialises a Msg to wire bytes. It returns nil for an unknown kind
// or a malformed SID.
func Encode(m Msg) []byte {
	sid, err := hex.DecodeString(m.SID)
	if err != nil || len(sid) != 6 {
		return nil
	}
	switch m.T {
	case KindConnect:
		host := []byte(m.Host)
		if len(host) > 255 {
			host = host[:255]
		}
		out := make([]byte, 0, 1+6+2+1+len(host))
		out = append(out, KindConnect)
		out = append(out, sid...)
		out = binary.BigEndian.AppendUint16(out, m.Port)
		out = append(out, byte(len(host)))
		out = append(out, host...)
		return out
	case KindAck:
		ok := byte(0)
		if m.OK {
			ok = 1
		}
		out := make([]byte, 0, 1+6+1)
		out = append(out, KindAck)
		out = append(out, sid...)
		out = append(out, ok)
		return out
	case KindData:
		out := make([]byte, 0, 1+6+len(m.Data))
		out = append(out, KindData)
		out = append(out, sid...)
		out = append(out, m.Data...)
		return out
	case KindClose:
		out := make([]byte, 0, 1+6)
		out = append(out, KindClose)
		out = append(out, sid...)
		return out
	}
	return nil
}

// Decode parses a wire frame. ok is false if the buffer is too short or the
// kind is unrecognised.
func Decode(buf []byte) (m Msg, ok bool) {
	if len(buf) < 7 {
		return Msg{}, false
	}
	t := buf[0]
	sid := hex.EncodeToString(buf[1:7])
	rest := buf[7:]
	switch t {
	case KindConnect:
		if len(rest) < 3 {
			return Msg{}, false
		}
		port := binary.BigEndian.Uint16(rest[0:2])
		hl := int(rest[2])
		if len(rest) < 3+hl {
			return Msg{}, false
		}
		return Msg{T: KindConnect, SID: sid, Host: string(rest[3 : 3+hl]), Port: port}, true
	case KindAck:
		return Msg{T: KindAck, SID: sid, OK: len(rest) > 0 && rest[0] != 0}, true
	case KindData:
		// copy so callers may retain the slice past the read buffer's lifetime
		data := make([]byte, len(rest))
		copy(data, rest)
		return Msg{T: KindData, SID: sid, Data: data}, true
	case KindClose:
		return Msg{T: KindClose, SID: sid}, true
	}
	return Msg{}, false
}
