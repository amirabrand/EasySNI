package protocol

import (
	"bytes"
	"testing"
)

func TestSIDRoundTrip(t *testing.T) {
	sid := MakeSID()
	if len(sid) != 12 {
		t.Fatalf("sid len = %d, want 12", len(sid))
	}
}

func TestConnectRoundTrip(t *testing.T) {
	in := Msg{T: KindConnect, SID: "0123456789ab", Host: "example.com", Port: 443}
	raw := Encode(in)
	if raw == nil {
		t.Fatal("encode returned nil")
	}
	if raw[0] != KindConnect {
		t.Fatalf("kind byte = %q", raw[0])
	}
	out, ok := Decode(raw)
	if !ok {
		t.Fatal("decode failed")
	}
	if out.Host != in.Host || out.Port != in.Port || out.SID != in.SID {
		t.Fatalf("got %+v want %+v", out, in)
	}
}

func TestAckRoundTrip(t *testing.T) {
	for _, want := range []bool{true, false} {
		raw := Encode(Msg{T: KindAck, SID: "aabbccddeeff", OK: want})
		out, ok := Decode(raw)
		if !ok || out.T != KindAck || out.OK != want {
			t.Fatalf("ack ok=%v -> %+v ok=%v", want, out, ok)
		}
	}
}

func TestDataRoundTrip(t *testing.T) {
	payload := []byte("the quick brown fox \x00\x01\x02")
	raw := Encode(Msg{T: KindData, SID: "001122334455", Data: payload})
	out, ok := Decode(raw)
	if !ok || !bytes.Equal(out.Data, payload) {
		t.Fatalf("data mismatch: %v", out.Data)
	}
}

func TestCloseRoundTrip(t *testing.T) {
	raw := Encode(Msg{T: KindClose, SID: "ffffffffffff"})
	out, ok := Decode(raw)
	if !ok || out.T != KindClose || out.SID != "ffffffffffff" {
		t.Fatalf("close -> %+v ok=%v", out, ok)
	}
}

func TestDecodeShort(t *testing.T) {
	if _, ok := Decode([]byte{'D', 1, 2, 3}); ok {
		t.Fatal("expected short buffer to fail")
	}
}

func TestDataDecodeCopies(t *testing.T) {
	raw := Encode(Msg{T: KindData, SID: "000000000000", Data: []byte("hi")})
	out, _ := Decode(raw)
	raw[7] = 'X' // mutate the source buffer after decode
	if string(out.Data) != "hi" {
		t.Fatalf("decode did not copy payload: %q", out.Data)
	}
}
