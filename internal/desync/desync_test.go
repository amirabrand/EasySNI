package desync

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestFindSNIRoundTrip(t *testing.T) {
	for _, host := range []string{"hcaptcha.com", "www.google.com", "challenges.cloudflare.com"} {
		hello := FakeClientHello("firefox", host)
		if !isClientHello(hello) {
			t.Fatalf("generated hello for %q is not a ClientHello", host)
		}
		s, e, got, ok := FindSNI(hello)
		if !ok {
			t.Fatalf("SNI not found in generated hello for %q", host)
		}
		if got != host {
			t.Fatalf("SNI mismatch: got %q want %q", got, host)
		}
		if string(hello[s:e]) != host {
			t.Fatalf("offsets wrong: %q", hello[s:e])
		}
	}
}

func TestFragmentSNIChunks(t *testing.T) {
	// hcaptcha.com with sniChunk=3 should break the SNI into hca|ptc|ha.|com,
	// matching the documented behaviour.
	hello := FakeClientHello("none", "hcaptcha.com")
	chunks := FragmentWrites(hello, 3)
	if len(chunks) < 5 {
		t.Fatalf("expected several chunks, got %d", len(chunks))
	}
	// Reassembly must equal the original record exactly.
	var joined []byte
	for _, c := range chunks {
		joined = append(joined, c...)
	}
	if !bytes.Equal(joined, hello) {
		t.Fatal("fragmented chunks do not reassemble to the original ClientHello")
	}
	// The SNI bytes must appear split at 3-byte boundaries across writes.
	s, _, _, _ := FindSNI(hello)
	pos := 0
	var sniPieces []string
	for _, c := range chunks {
		if pos+len(c) > s && pos < s+len("hcaptcha.com") {
			lo := s - pos
			if lo < 0 {
				lo = 0
			}
			hi := len(c)
			if pos+hi > s+len("hcaptcha.com") {
				hi = s + len("hcaptcha.com") - pos
			}
			if lo < hi {
				sniPieces = append(sniPieces, string(c[lo:hi]))
			}
		}
		pos += len(c)
	}
	got := sniPieces
	want := []string{"hca", "ptc", "ha.", "com"}
	if len(got) != len(want) {
		t.Fatalf("SNI split pieces = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SNI split pieces = %v, want %v", got, want)
		}
	}
}

func TestFragmentWholeSNI(t *testing.T) {
	hello := FakeClientHello("none", "example.org")
	chunks := FragmentWrites(hello, 0) // 0 => whole hostname in one write
	var joined []byte
	for _, c := range chunks {
		joined = append(joined, c...)
	}
	if !bytes.Equal(joined, hello) {
		t.Fatal("reassembly mismatch")
	}
}

func TestBuildFakeSegmentChecksum(t *testing.T) {
	src := net.ParseIP("192.168.1.10")
	dst := net.ParseIP("104.16.0.1")
	payload := []byte("hello")

	good := BuildFakeSegment(src, dst, 50000, 443, 1000, 0, payload, ModeNone)
	if good == nil {
		t.Fatal("nil segment")
	}
	// Verify the TCP checksum of the "none" segment is correct.
	tcp := good[20:]
	stored := binary.BigEndian.Uint16(tcp[16:])
	binary.BigEndian.PutUint16(tcp[16:], 0)
	if want := tcpChecksum(src.To4(), dst.To4(), tcp); want != stored {
		t.Fatalf("none mode checksum invalid: stored %x want %x", stored, want)
	}
	binary.BigEndian.PutUint16(tcp[16:], stored)

	// wrong_checksum must NOT verify.
	bad := BuildFakeSegment(src, dst, 50000, 443, 1000, 0, payload, ModeWrongChecksum)
	btcp := bad[20:]
	bs := binary.BigEndian.Uint16(btcp[16:])
	binary.BigEndian.PutUint16(btcp[16:], 0)
	if want := tcpChecksum(src.To4(), dst.To4(), btcp); want == bs {
		t.Fatal("wrong_checksum produced a valid checksum")
	}

	// wrong_seq must shift the sequence number out of window.
	wseq := BuildFakeSegment(src, dst, 50000, 443, 1000, 0, payload, ModeWrongSeq)
	if got := binary.BigEndian.Uint32(wseq[20+4:]); got == 1000 {
		t.Fatal("wrong_seq did not change the sequence number")
	}
}
