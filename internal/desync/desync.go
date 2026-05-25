// Package desync implements userspace DPI-evasion for the proxy: fake
// ClientHello injection and SNI-aware TLS record fragmentation, plus a
// connection wrapper that applies both to the first (ClientHello) write so it
// works transparently with io.Copy in either proxy mode.
//
// Two layers exist:
//
//   - Fragmentation (-enable-fragment / -sni-chunk / -fragment-delay) is pure
//     userspace over net.Conn and works everywhere. It splits the real
//     ClientHello across several TCP writes, breaking the SNI so DPI that does
//     not reassemble cannot match it. This is the reliable path.
//
//   - Fake injection with a bypass mode (-mode wrong_checksum | wrong_seq, with
//     -fake-repeat / -fake-delay / -ack-timeout) crafts a benign fake
//     ClientHello as a raw TCP segment whose checksum or sequence is
//     deliberately wrong, so the real server drops it but a DPI middlebox is
//     desynchronised. Sending raw segments needs elevated privileges (Linux
//     root via raw sockets; Windows needs WinDivert), so it is best-effort and
//     guarded per-OS — if injection is unavailable the proxy logs it and still
//     applies fragmentation.
package desync

import (
	"encoding/binary"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"time"
)

// BypassMode selects how the fake segment is corrupted so the real server
// rejects it while the DPI still inspects it.
type BypassMode string

const (
	ModeNone          BypassMode = "none"
	ModeWrongChecksum BypassMode = "wrong_checksum"
	ModeWrongSeq      BypassMode = "wrong_seq"
)

// LogFunc receives status lines.
type LogFunc func(msg, level string)

// Config carries every tunable from the CLI flags / UI.
type Config struct {
	FakeRepeat     int           // number of fake ClientHello injections
	FakeDelay      time.Duration // delay after fake injection before real traffic
	AckTimeout     time.Duration // max wait for server response after injection
	UTLS           string        // fingerprint preset for the fake hello; "none" = legacy template
	EnableFragment bool          // split the real ClientHello
	FragmentDelay  time.Duration // delay between split writes
	SNIChunk       int           // SNI bytes per write (0 = whole hostname)
	Mode           BypassMode    // none | wrong_checksum | wrong_seq
}

// DefaultConfig returns the documented defaults.
func DefaultConfig() Config {
	return Config{
		FakeRepeat:     1,
		FakeDelay:      2 * time.Millisecond,
		AckTimeout:     2 * time.Second,
		UTLS:           "firefox",
		EnableFragment: false,
		FragmentDelay:  500 * time.Millisecond,
		SNIChunk:       3,
		Mode:           ModeNone,
	}
}

// Active reports whether any DPI-evasion behaviour is requested.
func (c Config) Active() bool { return c.EnableFragment || c.Mode != ModeNone }

// Presets lists the uTLS fingerprint presets accepted by -utls.
func Presets() []string {
	return []string{"none", "firefox", "chrome", "safari", "ios", "android", "edge", "360", "qq", "randomized", "random"}
}

// ValidPreset reports whether name is a known preset.
func ValidPreset(name string) bool {
	for _, p := range Presets() {
		if p == name {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------ TLS parse

func isClientHello(b []byte) bool {
	// record: type=22 (handshake), version 0x03xx; handshake type=1 (ClientHello)
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}

// FindSNI locates the server_name host inside a TLS ClientHello record and
// returns its absolute [start,end) byte offsets and the host string.
func FindSNI(rec []byte) (start, end int, host string, ok bool) {
	if !isClientHello(rec) {
		return 0, 0, "", false
	}
	// Skip record header (5) + handshake header (4).
	p := 5 + 4
	if p+2+32 > len(rec) {
		return 0, 0, "", false
	}
	p += 2 + 32 // client_version + random
	if p >= len(rec) {
		return 0, 0, "", false
	}
	sid := int(rec[p])
	p += 1 + sid // session_id
	if p+2 > len(rec) {
		return 0, 0, "", false
	}
	cs := int(binary.BigEndian.Uint16(rec[p:]))
	p += 2 + cs // cipher_suites
	if p >= len(rec) {
		return 0, 0, "", false
	}
	comp := int(rec[p])
	p += 1 + comp // compression_methods
	if p+2 > len(rec) {
		return 0, 0, "", false
	}
	extTotal := int(binary.BigEndian.Uint16(rec[p:]))
	p += 2
	extEnd := p + extTotal
	if extEnd > len(rec) {
		extEnd = len(rec)
	}
	for p+4 <= extEnd {
		etype := binary.BigEndian.Uint16(rec[p:])
		elen := int(binary.BigEndian.Uint16(rec[p+2:]))
		body := p + 4
		if body+elen > len(rec) {
			return 0, 0, "", false
		}
		if etype == 0x0000 { // server_name
			q := body
			if q+2 > len(rec) {
				return 0, 0, "", false
			}
			q += 2 // server_name_list length
			if q+3 > len(rec) {
				return 0, 0, "", false
			}
			// name_type(1) + name_length(2)
			nlen := int(binary.BigEndian.Uint16(rec[q+1:]))
			ns := q + 3
			ne := ns + nlen
			if ne > len(rec) {
				return 0, 0, "", false
			}
			return ns, ne, string(rec[ns:ne]), true
		}
		p = body + elen
	}
	return 0, 0, "", false
}

// ------------------------------------------------------------ fragmentation

// FragmentWrites splits a ClientHello record into the ordered TCP-write chunks
// described by the flags: everything up to the SNI in one write, then the SNI
// in sniChunk-byte pieces (0 = whole host), then the remainder. The TLS record
// itself is unchanged; only the byte boundaries between writes differ. If no
// SNI is found it splits once near the middle.
func FragmentWrites(rec []byte, sniChunk int) [][]byte {
	s, e, _, ok := FindSNI(rec)
	if !ok {
		if len(rec) < 2 {
			return [][]byte{rec}
		}
		mid := len(rec) / 2
		return [][]byte{rec[:mid], rec[mid:]}
	}
	// Boundary set: start of SNI, every sniChunk inside it, end of SNI.
	bounds := map[int]struct{}{s: {}, e: {}}
	if sniChunk > 0 {
		for i := s + sniChunk; i < e; i += sniChunk {
			bounds[i] = struct{}{}
		}
	}
	cuts := []int{0, len(rec)}
	for b := range bounds {
		if b > 0 && b < len(rec) {
			cuts = append(cuts, b)
		}
	}
	sort.Ints(cuts)
	var out [][]byte
	for i := 0; i+1 < len(cuts); i++ {
		if cuts[i+1] > cuts[i] {
			out = append(out, rec[cuts[i]:cuts[i+1]])
		}
	}
	if len(out) == 0 {
		out = [][]byte{rec}
	}
	return out
}

// ------------------------------------------------------ fake ClientHello

// FakeClientHello builds a syntactically valid ClientHello record carrying the
// given (benign) SNI. The preset tweaks the cipher-suite list so the fake hello
// roughly resembles the named client; "none" uses a fixed legacy template.
//
// These are approximations of real fingerprints — byte-perfect uTLS mimicry
// needs the refraction-networking/utls library (see README for the optional
// build path). They are valid enough for a DPI to parse and act on.
func FakeClientHello(preset, sni string) []byte {
	if sni == "" {
		sni = "www.google.com"
	}
	ciphers := presetCiphers(preset)

	var body []byte
	body = append(body, 0x03, 0x03) // client_version TLS 1.2
	rnd := make([]byte, 32)         // random
	_, _ = rand.Read(rnd)
	body = append(body, rnd...)
	sid := make([]byte, 32) // session_id
	_, _ = rand.Read(sid)
	body = append(body, 32)
	body = append(body, sid...)
	// cipher_suites
	cs := make([]byte, 2)
	binary.BigEndian.PutUint16(cs, uint16(len(ciphers)))
	body = append(body, cs...)
	body = append(body, ciphers...)
	// compression
	body = append(body, 0x01, 0x00)
	// extensions
	ext := buildExtensions(sni, preset)
	el := make([]byte, 2)
	binary.BigEndian.PutUint16(el, uint16(len(ext)))
	body = append(body, el...)
	body = append(body, ext...)

	// handshake header
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	// record header
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func presetCiphers(preset string) []byte {
	// A small, real cipher-suite set; ordering differs slightly per preset.
	common := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	switch preset {
	case "chrome", "edge", "android":
		common = append([]uint16{0x1301, 0x1303, 0x1302}, common[3:]...)
	case "safari", "ios":
		common = append([]uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b}, common[5:]...)
	case "none":
		common = []uint16{0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009c, 0x009d, 0x002f, 0x0035}
	}
	out := make([]byte, 0, len(common)*2)
	b := make([]byte, 2)
	for _, c := range common {
		binary.BigEndian.PutUint16(b, c)
		out = append(out, b...)
	}
	return out
}

func ext(typ uint16, data []byte) []byte {
	h := make([]byte, 4)
	binary.BigEndian.PutUint16(h, typ)
	binary.BigEndian.PutUint16(h[2:], uint16(len(data)))
	return append(h, data...)
}

func buildExtensions(sni, preset string) []byte {
	var out []byte
	// server_name (0)
	name := []byte(sni)
	sn := make([]byte, 0, len(name)+5)
	entry := append([]byte{0x00}, byte(len(name)>>8), byte(len(name)))
	entry = append(entry, name...)
	listLen := make([]byte, 2)
	binary.BigEndian.PutUint16(listLen, uint16(len(entry)))
	sn = append(sn, listLen...)
	sn = append(sn, entry...)
	out = append(out, ext(0x0000, sn)...)
	// supported_groups (10): x25519, secp256r1, secp384r1
	out = append(out, ext(0x000a, []byte{0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18})...)
	// ec_point_formats (11)
	out = append(out, ext(0x000b, []byte{0x01, 0x00})...)
	// signature_algorithms (13)
	out = append(out, ext(0x000d, []byte{0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x02, 0x01})...)
	// supported_versions (43): TLS 1.3, 1.2
	out = append(out, ext(0x002b, []byte{0x04, 0x03, 0x04, 0x03, 0x03})...)
	// ALPN (16): h2, http/1.1 — chrome/firefox-ish
	if preset != "none" {
		alpn := []byte{0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
		out = append(out, ext(0x0010, alpn)...)
	}
	return out
}

// ------------------------------------------------------ raw fake segment

// BuildFakeSegment crafts a raw IPv4+TCP PSH/ACK segment carrying payload, then
// corrupts it per mode so the destination drops it while a DPI still parses it.
// Exposed (and unit-tested) so the checksum/sequence behaviour is verifiable
// independently of the privileged send path.
func BuildFakeSegment(src, dst net.IP, srcPort, dstPort int, seq, ack uint32, payload []byte, mode BypassMode) []byte {
	src4, dst4 := src.To4(), dst.To4()
	if src4 == nil || dst4 == nil {
		return nil
	}
	if mode == ModeWrongSeq {
		seq -= 100000 // shove it out of the receive window
	}

	tcpLen := 20 + len(payload)
	totalLen := 20 + tcpLen

	ip := make([]byte, 20)
	ip[0] = 0x45 // v4, IHL=5
	binary.BigEndian.PutUint16(ip[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:], uint16(rand.Intn(65535))) // id
	ip[8] = 64                                                   // TTL
	ip[9] = 6                                                    // TCP
	copy(ip[12:16], src4)
	copy(ip[16:20], dst4)
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip))

	tcp := make([]byte, tcpLen)
	binary.BigEndian.PutUint16(tcp[0:], uint16(srcPort))
	binary.BigEndian.PutUint16(tcp[2:], uint16(dstPort))
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = 0x50                // data offset 5
	tcp[13] = 0x18                // PSH|ACK
	tcp[14], tcp[15] = 0xff, 0xff // window
	copy(tcp[20:], payload)

	csum := tcpChecksum(src4, dst4, tcp)
	if mode == ModeWrongChecksum {
		csum = ^csum // deliberately invalid
		if csum == 0 {
			csum = 0xdead
		}
	}
	binary.BigEndian.PutUint16(tcp[16:], csum)

	return append(ip, tcp...)
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		if i == 10 { // skip checksum field
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst, tcp []byte) uint16 {
	var sum uint32
	// pseudo-header
	sum += uint32(binary.BigEndian.Uint16(src[0:]))
	sum += uint32(binary.BigEndian.Uint16(src[2:]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:]))
	sum += uint32(6) // protocol
	sum += uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		if i == 16 { // skip checksum field
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(tcp[i:]))
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ------------------------------------------------------------ conn wrapper

// WrapConn returns c wrapped so the first ClientHello write is fake-injected
// (best effort) and/or fragmented per cfg. If cfg requests nothing, c is
// returned unchanged. fakeSNI is the benign name used in the fake hello;
// serverIP/serverPort identify the upstream for raw injection.
func WrapConn(c net.Conn, cfg Config, fakeSNI, serverIP string, serverPort int, log LogFunc) net.Conn {
	if !cfg.Active() {
		return c
	}
	if log == nil {
		log = func(string, string) {}
	}
	return &wrapConn{Conn: c, cfg: cfg, fakeSNI: fakeSNI, serverIP: serverIP, serverPort: serverPort, log: log}
}

type wrapConn struct {
	net.Conn
	cfg        Config
	fakeSNI    string
	serverIP   string
	serverPort int
	log        LogFunc
	did        bool
}

func (w *wrapConn) Write(b []byte) (int, error) {
	if w.did || !isClientHello(b) {
		return w.Conn.Write(b)
	}
	w.did = true

	if w.cfg.Mode != ModeNone {
		w.injectFakes()
		if w.cfg.FakeDelay > 0 {
			time.Sleep(w.cfg.FakeDelay)
		}
	}

	if !w.cfg.EnableFragment {
		return w.Conn.Write(b)
	}
	chunks := FragmentWrites(b, w.cfg.SNIChunk)
	w.log("Fragmenting ClientHello into "+strconv.Itoa(len(chunks))+" writes", "DIM")
	total := 0
	for i, ch := range chunks {
		n, err := w.Conn.Write(ch)
		total += n
		if err != nil {
			return total, err
		}
		if i+1 < len(chunks) && w.cfg.FragmentDelay > 0 {
			time.Sleep(w.cfg.FragmentDelay)
		}
	}
	return total, nil
}

// injectFakes builds fake ClientHello segments and attempts to send them via
// the privileged raw path. Failures are logged but never fatal — fragmentation
// remains the reliable bypass.
func (w *wrapConn) injectFakes() {
	la, ok := w.Conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	dstIP := net.ParseIP(w.serverIP)
	if dstIP == nil {
		if ips, err := net.LookupIP(w.serverIP); err == nil && len(ips) > 0 {
			dstIP = ips[0]
		}
	}
	if dstIP == nil || dstIP.To4() == nil {
		w.log("Fake injection skipped (need an IPv4 upstream)", "DIM")
		return
	}
	hello := FakeClientHello(w.cfg.UTLS, w.fakeSNI)
	seq := rand.Uint32()
	n := w.cfg.FakeRepeat
	if n < 1 {
		n = 1
	}
	var lastErr error
	for i := 0; i < n; i++ {
		seg := BuildFakeSegment(la.IP, dstIP, la.Port, w.serverPort, seq, 0, hello, w.cfg.Mode)
		if err := sendRaw(dstIP, seg); err != nil {
			lastErr = err
			break
		}
	}
	if lastErr != nil {
		w.log("Fake injection unavailable ("+lastErr.Error()+") — applying fragmentation only", "WARN")
	} else {
		w.log("Injected "+strconv.Itoa(n)+"x fake ClientHello ["+string(w.cfg.Mode)+", "+w.cfg.UTLS+"]", "ACCENT")
	}
}
