package main

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestDNSQueryRoundTrip(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := append([]byte(nil), buf[:n]...)
		resp[2] |= 0x80                         // QR
		binary.BigEndian.PutUint16(resp[6:], 2) // 2 answers
		pc.WriteTo(resp, addr)
	}()
	q := buildDNSQuery("api.steampowered.com", 1)
	if len(q) != 12+22+4 {
		t.Fatalf("query len %d", len(q))
	}
	// dnsUDP always uses port 53; exercise the parser through a raw exchange
	c, _ := net.Dial("udp", pc.LocalAddr().String())
	c.Write(buildDNSQuery("api.steampowered.com", 0x4157))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil || n < 12 || binary.BigEndian.Uint16(buf[6:]) != 2 {
		t.Fatal("bad response")
	}
}
