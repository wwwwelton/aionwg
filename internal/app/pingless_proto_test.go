package app

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestPinglessProtoRoundtrip(t *testing.T) {
	keys := NewPinglessSessionKeys("secret-test-psk")
	clientCipher, err := keys.Session(12345, false)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	relayCipher, err := keys.Session(12345, true)
	if err != nil {
		t.Fatalf("relay session: %v", err)
	}

	peer := netip.MustParseAddrPort("1.2.3.4:27015")
	payload := []byte("hello openlag relay")

	// 1. Data packet from client to relay
	out := make([]byte, HeaderLen, 2048)
	data := &DataBody{
		Flow:    10,
		Seq:     1,
		Peer:    peer,
		Payload: payload,
	}
	sealed, err := clientCipher.SealData(data, out)
	if err != nil {
		t.Fatalf("seal data: %v", err)
	}

	hdr, kind, body, err := relayCipher.Open(sealed)
	if err != nil {
		t.Fatalf("relay open: %v", err)
	}
	if hdr.Session != 12345 || kind != KindData {
		t.Fatalf("unexpected header: %+v, kind: %v", hdr, kind)
	}
	if len(body) < DataFixedLen+7 {
		t.Fatalf("body too short: %d", len(body))
	}
	gotFlow := uint32(body[0]) | uint32(body[1])<<8 | uint32(body[2])<<16 | uint32(body[3])<<24
	gotSeq := uint64(body[4]) | uint64(body[5])<<8 | uint64(body[6])<<16 | uint64(body[7])<<24 |
		uint64(body[8])<<32 | uint64(body[9])<<40 | uint64(body[10])<<48 | uint64(body[11])<<56
	gotPeer, used, err := DecodeAddr(body[12:])
	if err != nil {
		t.Fatalf("decode addr: %v", err)
	}
	gotPayload := body[12+used:]

	if gotFlow != 10 || gotSeq != 1 || gotPeer != peer || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("mismatch: flow=%d seq=%d peer=%s payload=%s", gotFlow, gotSeq, gotPeer, string(gotPayload))
	}

	// 2. Pong packet from relay to client
	pong := PingBody{
		Path:   2,
		Probe:  99,
		SentUS: 100500,
	}
	pongOut := make([]byte, HeaderLen, 128)
	sealedPong, err := relayCipher.SealPong(pong, pongOut)
	if err != nil {
		t.Fatalf("seal pong: %v", err)
	}

	hdrP, kindP, bodyP, err := clientCipher.Open(sealedPong)
	if err != nil {
		t.Fatalf("client open pong: %v", err)
	}
	if kindP != KindPong || hdrP.Session != 12345 {
		t.Fatalf("unexpected pong: %+v, kind: %v", hdrP, kindP)
	}
	gotPong, err := DecodePingBody(bodyP)
	if err != nil {
		t.Fatalf("decode ping body: %v", err)
	}
	if gotPong != pong {
		t.Fatalf("pong mismatch: %+v vs %+v", gotPong, pong)
	}
}

func TestPinglessSeqWindow(t *testing.T) {
	var w PinglessSeqWindow
	if !w.Accept(1) {
		t.Fatal("expected seq 1 accepted")
	}
	if w.Accept(1) {
		t.Fatal("expected duplicate seq 1 rejected")
	}
	if !w.Accept(3) {
		t.Fatal("expected seq 3 accepted")
	}
	if !w.Accept(2) {
		t.Fatal("expected out of order seq 2 accepted")
	}
	if w.Accept(2) {
		t.Fatal("expected duplicate seq 2 rejected")
	}
	if !w.Accept(5000) {
		t.Fatal("expected forward jump seq 5000 accepted")
	}
	if w.Accept(3) {
		t.Fatal("expected old seq 3 rejected")
	}
}
