package app

import (
	"encoding/binary"
	"net/netip"
)

// BuildInboundUDPPacket constructs a full IPv4/IPv6 + UDP packet.
// src: remote server address (game server)
// dst: local client address (game process socket)
func BuildInboundUDPPacket(src, dst netip.AddrPort, payload []byte) ([]byte, pktInfo) {
	v6 := src.Addr().Is6()
	ipHdrLen := 20
	if v6 {
		ipHdrLen = 40
	}
	udpLen := 8 + len(payload)
	totalLen := ipHdrLen + udpLen

	buf := make([]byte, totalLen)
	var p pktInfo
	p.v6 = v6
	p.proto = protoUDP
	p.ipHdr = ipHdrLen
	p.l4 = ipHdrLen
	p.src = src.Addr()
	p.dst = dst.Addr()
	p.srcPort = src.Port()
	p.dstPort = dst.Port()

	if !v6 {
		buf[0] = 0x45 // Version 4, IHL 5
		buf[1] = 0    // DSCP / ECN
		binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
		binary.BigEndian.PutUint16(buf[4:6], 0)      // Identification
		binary.BigEndian.PutUint16(buf[6:8], 0x4000) // DF flag
		buf[8] = 64                                  // TTL
		buf[9] = protoUDP                            // Protocol
		buf[10], buf[11] = 0, 0                      // Checksum placeholder
		src4 := src.Addr().As4()
		copy(buf[12:16], src4[:])
		dst4 := dst.Addr().As4()
		copy(buf[16:20], dst4[:])
	} else {
		buf[0] = 0x60 // Version 6
		buf[1], buf[2], buf[3] = 0, 0, 0
		binary.BigEndian.PutUint16(buf[4:6], uint16(udpLen))
		buf[6] = protoUDP // Next header
		buf[7] = 64       // Hop limit
		src6 := src.Addr().As16()
		copy(buf[8:24], src6[:])
		dst6 := dst.Addr().As16()
		copy(buf[24:40], dst6[:])
	}

	udp := buf[ipHdrLen:]
	binary.BigEndian.PutUint16(udp[0:2], src.Port())
	binary.BigEndian.PutUint16(udp[2:4], dst.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	udp[6], udp[7] = 0, 0 // Checksum placeholder
	copy(udp[8:], payload)

	fixChecksums(buf, &p)
	return buf, p
}
