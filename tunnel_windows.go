//go:build windows

package main

// The split-tunnel engine:
//
//   AION 2 ──► Windows TCP/IP ──► WinDivert (outbound, all TCP/UDP)
//                                    │ port owned by AION?  no ──► reinject unchanged
//                                    │ yes: SNAT src → tunnel IP
//                                    ▼
//                     splitTun.Read ──► wireguard-go ──► UDP to the VPN server
//
//   VPN server ──► wireguard-go ──► splitTun.Write ──► DNAT dst → original local IP
//                                    ──► WinDivert inject as inbound on the original NIC
//
// No virtual adapter and no route changes: everything else keeps using the
// normal connection.

import (
	"bufio"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// ---------------------------------------------------------------- engine

type natEntry struct {
	local    netip.Addr
	remote   netip.Addr
	dnsOrig  netip.Addr // valid when a DNS query was redirected to the tunnel DNS
	game     bool       // flow belongs to the game (mirror, game ping, game stats)
	class    uint8
	ifIdx    uint32
	subIfIdx uint32
	last     time.Time
}

// natKey separates IPv4/IPv6 sockets that share a port number.
func natKey(proto uint8, v6 bool, port uint16) portKey {
	if v6 {
		proto |= 0x80
	}
	return portKey{proto, port}
}

// EngineOptions are the user settings the engine needs.
type EngineOptions struct {
	Processes    []string
	PingTarget   string
	Mirror       bool
	UDPDuplicate bool // send game UDP extra copies via Windows direct route
	UDPOriginals int  // A of A:B ratio
	UDPCopies    int  // B of A:B ratio
	UDPForce     bool // also copy game UDP outside AllowedIPs; never DNS/LAN/full tunnel
	UDPNewestOut bool // opt-in latest-first ordering of primary game UDP sends
	UDPNewestIn  bool // opt-in latest-first ordering of primary game UDP arrivals
	FullTunnel   bool
	NoDNS        bool     // full tunnel: do NOT redirect DNS into the tunnel
	WFP          bool     // tunnel only WFPApps; replaces the port and full-tunnel modes
	WFPApps      []string // executables the user picked for WFP mode
	ConfigPath   string   // imported profile receiving learned WFP destinations
	ConfigPaths  []string
}

// Diag are counters for the diagnostics panel.
type Diag struct {
	Captured, Injected uint64 // packets into / out of the tunnel
	InNoNAT            uint64 // packets from the tunnel with no matching flow
	InjectErr          uint64
	TunDrop            uint64 // tunnel queue full
	Segmented          uint64 // oversized (LSO) TCP packets split
	ICMPErr            uint64 // ICMP errors relayed back to apps
	DNSQ, DNSA         uint64 // DNS queries redirected / answers received
	TableDumps         uint64
	V6Blocked          uint64 // IPv6 packets blocked (config without IPv6)
}

// PingResult holds the latest measurement for one target.
type PingResult struct {
	Target string
	RTT    time.Duration // 0 = no reply
	OK     bool
	Loss   float64 // 0..1 over the last 20 probes
	Err    uint32  // Windows IP_STATUS / GetLastError of the last failed direct ICMP (0 = none)
}

type Stats struct {
	Up, Down         uint64 // all bytes through the tunnel (inner)
	GameUp, GameDown uint64 // game-only bytes
	WGRx, WGTx       uint64 // WireGuard wire bytes
	Handshake        time.Time
	Flows            int
	GameFlows        int
	Procs            []ProcInfo
	PingEndpoint     PingResult // direct ICMP to VPN server (outside the tunnel)
	PingTunnel       PingResult // ICMP through the tunnel to the gateway
	PingGame         PingResult // ICMP through the tunnel to the game server
	MirrorOn         bool
	UDPDupOn         bool   // worker enabled; active only in split-tunnel mode
	UDPOriginals     int    // A of the A:B ratio
	UDPCopies        int    // B of the A:B ratio
	UDPForce         bool   // duplicate game UDP outside AllowedIPs
	UDPNewestOut     bool   // latest-first primary game UDP send
	UDPNewestIn      bool   // latest-first primary game UDP arrival
	UDPSendDropped   uint64 // oldest outbound UDP packets evicted from LIFO queue
	UDPRecvDropped   uint64 // oldest inbound UDP packets evicted from LIFO queue
	UDPDupAccepted   uint64 // copies queued
	UDPDupSent       uint64 // copies reinjected to Windows
	UDPDupDropped    uint64 // copies dropped rather than slowing the original
	UDPDupErrors     uint64 // secondary path errors
	MirrorFlows      []string
	MeterAdapter     string
	MeterOK          bool
	FullTunnel       bool
	DNS              string // DNS used for the full tunnel ("" = none in config)
	IPv6Direct       bool   // full tunnel but config has no IPv6 address
	WFPOn            bool   // WFP mode: only the selected apps are tunnelled
	WFPSocket        bool   // SOCKET layer open (false = system-table fallback only)
	DNSTunnel        bool   // DNS redirect active
	Diag             Diag
	Endpoint         string
	TunnelAddr       string
}

type outboundUDPJob struct {
	packet   []byte // original routed packet, already SNAT'd for WireGuard
	copyUDP  []byte // optional original (pre-SNAT) for direct secondary copying
	copyAddr divertAddress
}

type Engine struct {
	conf         *WGConf
	routes       *wfpRoutes
	endpoints    []netip.AddrPort
	dev          *device.Device
	tun          *splitTun
	h            divertHandle
	owner        *ownerTracker
	mirror       *mirror
	shugoMu      sync.Mutex
	shugo        *shugoCompat // Shugo.gg relay view; exists only while [m] is on
	udpDup       *udpDuplicator[divertAddress]
	udpForce     atomic.Bool
	latestOut    atomic.Bool
	latestIn     atomic.Bool
	outboundQ    *latestQueue[outboundUDPJob]
	inboundQ     *latestQueue[[]byte]
	meterMu      sync.Mutex
	meter        *meterAdapter // Wintun copy for Npcap-based DPS meters
	meterErr     string
	meterOpening bool                          // protected by meterMu; never initialize Wintun on the TUI goroutine
	meterOpener  func() (*meterAdapter, error) // injectable for regression tests
	addr4        netip.Addr
	addr6        netip.Addr
	maxMSS4      uint16
	maxMSS6      uint16
	logf         func(string, ...any)

	natMu sync.Mutex
	nat   map[portKey]*natEntry

	up, down                                   atomic.Uint64
	gameUp, gameDown                           atomic.Uint64
	full                                       atomic.Bool
	noDNS                                      atomic.Bool
	wfpOn                                      atomic.Bool // WFP mode: only the selected apps are tunnelled
	wfp                                        *wfpMonitor // nil when the SOCKET layer could not be opened
	cCaptured, cInjected, cInNoNAT, cInjectErr atomic.Uint64
	cSegmented, cICMPErr, cDNSQ, cDNSA         atomic.Uint64
	cV6Block                                   atomic.Uint64
	ownUDP                                     atomic.Uint32 // our own WireGuard socket port (never captured)

	closing atomic.Bool
	wg      sync.WaitGroup
	stop    chan struct{}

	pingMu   sync.Mutex
	pingSeq  uint16
	pending  map[uint32]time.Time // id<<16|seq -> sent
	pings    map[uint16]*pingState
	gwTarget netip.Addr
}

type pingState struct {
	target  netip.Addr
	last    time.Duration
	ok      bool
	err     uint32
	history []bool
}

func (s *pingState) result() PingResult {
	r := PingResult{RTT: s.last, OK: s.ok, Err: s.err}
	if s.target.IsValid() {
		r.Target = s.target.String()
	}
	if len(s.history) > 0 {
		lost := 0
		for _, ok := range s.history {
			if !ok {
				lost++
			}
		}
		r.Loss = float64(lost) / float64(len(s.history))
	}
	return r
}

func (s *pingState) record(ok bool, rtt time.Duration) {
	s.ok = ok
	if ok {
		s.last = rtt
	}
	s.history = append(s.history, ok)
	if len(s.history) > 20 {
		s.history = s.history[1:]
	}
}

const (
	pingIDGateway = 0xA102
	pingIDGame    = 0xA103
)

func StartEngine(conf *WGConf, opt EngineOptions, logf func(string, ...any)) (*Engine, error) {
	e := &Engine{
		conf:    conf,
		logf:    logf,
		nat:     map[portKey]*natEntry{},
		stop:    make(chan struct{}),
		pending: map[uint32]time.Time{},
		pings: map[uint16]*pingState{
			pingIDGateway: {},
			pingIDGame:    {},
			0:             {}, // endpoint (direct)
		},
	}
	var ok4, ok6 bool
	e.addr4, ok4 = conf.Addr(false)
	e.addr6, ok6 = conf.Addr(true)
	if !ok4 && !ok6 {
		return nil, fmt.Errorf("config sem endereço")
	}
	e.maxMSS4 = uint16(conf.MTU - 40)
	e.maxMSS6 = uint16(conf.MTU - 60)

	for _, p := range conf.Peers {
		ep, err := ResolveEndpoint(p.Endpoint)
		if err != nil {
			return nil, err
		}
		e.endpoints = append(e.endpoints, ep)
	}
	e.pings[0].target = e.endpoints[0].Addr()
	e.gwTarget = e.pickGateway(opt.PingTarget)
	e.pings[pingIDGateway].target = e.gwTarget

	// The VPN server's own UDP packets are excluded from capture (only a
	// speed-up: they come from our own process and would pass through anyway).
	filter := captureFilter(e.endpoints)
	h, err := divertOpen(filter, divertLayerNetwork, 0, 0)
	if err != nil && filter != baseCaptureFilter {
		logf("aviso: %v — usando filtro simples", err)
		h, err = divertOpen(baseCaptureFilter, divertLayerNetwork, 0, 0)
	}
	if err != nil {
		return nil, err
	}
	e.h = h
	h.setParam(0, 16384)    // queue length
	h.setParam(1, 2000)     // queue time ms
	h.setParam(2, 33554432) // queue size bytes

	e.owner = newOwnerTracker(opt.Processes)
	e.mirror = newMirror(opt.Mirror, logf)
	e.mirror.trace = e.logDisk
	e.udpDup = newUDPDuplicator[divertAddress](udpDupQueueSize, opt.UDPDuplicate)
	e.udpDup.setRatio(opt.UDPOriginals, opt.UDPCopies)
	e.udpForce.Store(opt.UDPForce)
	e.latestOut.Store(opt.UDPNewestOut)
	e.latestIn.Store(opt.UDPNewestIn)
	e.outboundQ = newLatestQueue[outboundUDPJob](128)
	e.outboundQ.onDrop = func(job outboundUDPJob) {
		putPktBuf(job.packet)
		putPktBuf(job.copyUDP)
	}
	e.inboundQ = newLatestQueue[[]byte](128)
	e.inboundQ.onDrop = putPktBuf
	e.meterOpener = openMeterAdapter
	e.full.Store(opt.FullTunnel)
	e.noDNS.Store(opt.NoDNS)
	// The SOCKET layer cannot see sockets opened before its handle, so the
	// monitor starts with the engine (not when WFP is toggled on): by the time
	// the user enables WFP it already knows the apps' sockets. It degrades to the
	// system table if the SOCKET layer cannot open; it never blocks the tunnel.
	table := newWFPTable()
	table.SetApps(opt.WFPApps)
	e.wfp = startWFPMonitor(table, logf)
	e.wfpOn.Store(opt.WFP)
	e.tun = newSplitTun(conf.MTU)
	e.tun.onInbound = e.handleInbound

	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { logf("wg: "+f, a...) },
	}
	e.dev = device.NewDevice(e.tun, conn.NewDefaultBind(), logger)
	if err := e.dev.IpcSet(conf.UAPI(e.endpoints)); err != nil {
		e.Close()
		return nil, fmt.Errorf("configurando WireGuard: %w", err)
	}
	e.routes = &wfpRoutes{conf: conf, path: opt.ConfigPath, paths: opt.ConfigPaths, apply: e.dev.IpcSet}
	if err := e.dev.Up(); err != nil {
		e.Close()
		return nil, err
	}
	if uapi, err := e.dev.IpcGet(); err == nil {
		for _, l := range strings.Split(uapi, "\n") {
			if v, ok := strings.CutPrefix(l, "listen_port="); ok {
				n, _ := strconv.Atoi(v)
				e.ownUDP.Store(uint32(n))
			}
		}
	}

	for i := 0; i < 4; i++ {
		e.wg.Add(1)
		go e.divertLoop()
	}
	go e.housekeeping()
	go e.pingLoop()
	e.wg.Add(3)
	go e.runUDPDuplicateWorker()
	go func() {
		defer e.wg.Done()
		e.outboundQ.run(e.stop, func(job outboundUDPJob) {
			if !e.closing.Load() {
				e.tun.inject(job.packet)
				if len(job.copyUDP) > 0 && e.udpDup != nil {
					e.udpDup.offer(job.copyUDP, job.copyAddr)
				}
				putPktBuf(job.copyUDP)
			} else {
				putPktBuf(job.packet)
				putPktBuf(job.copyUDP)
			}
		})
	}()
	go func() {
		defer e.wg.Done()
		e.inboundQ.run(e.stop, func(pkt []byte) {
			if !e.closing.Load() {
				e.processInbound(pkt)
			}
			putPktBuf(pkt)
		})
	}()
	if opt.Mirror {
		e.setShugo(true)
		e.requestMeter()
	}
	logf("túnel ativo · endpoint %s · filtro WinDivert aberto", e.endpoints[0])
	return e, nil
}

func (e *Engine) pickGateway(user string) netip.Addr {
	if a, err := netip.ParseAddr(strings.TrimSpace(user)); err == nil {
		return a
	}
	for _, p := range e.conf.Addresses {
		if p.Addr().Is4() && p.Bits() < 31 {
			gw := p.Masked().Addr().Next()
			if gw != p.Addr() && e.conf.Allowed(gw) {
				return gw
			}
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8"} {
		a := netip.MustParseAddr(s)
		if e.addr4.IsValid() && e.conf.Allowed(a) {
			return a
		}
	}
	return netip.Addr{}
}

func (e *Engine) tunAddr(v6 bool) (netip.Addr, bool) {
	if v6 {
		return e.addr6, e.addr6.IsValid()
	}
	return e.addr4, e.addr4.IsValid()
}

func (e *Engine) divertLoop() {
	defer e.wg.Done()
	buf := make([]byte, 65535)
	var addr divertAddress
	for {
		n, err := e.h.recv(buf, &addr)
		if err != nil {
			if e.closing.Load() {
				return
			}
			continue
		}
		pkt := buf[:n]
		if e.capture(pkt, &addr) {
			continue
		}
		e.h.send(pkt, &addr)
	}
}

// classify decides which class of traffic a local port carries and whether the
// system-wide full tunnel applies. The precedence rule lives in resolveClass.
func (e *Engine) classify(proto uint8, port uint16) (class uint8, full bool) {
	on := e.wfp != nil && e.wfpOn.Load()
	return resolveClass(on,
		func() uint8 { return e.owner.Class(proto, port) },
		e.full.Load(),
		func() uint8 {
			return e.wfp.table.Decide(proto, port, time.Now(), func() uint8 {
				return e.wfp.systemClass(proto, port)
			})
		})
}

// capture diverts the packet into the tunnel if it belongs to a listed
// process (or to anything, in full-tunnel mode).
func (e *Engine) capture(pkt []byte, addr *divertAddress) bool {
	p, ok := parsePacket(pkt)
	if !ok || (p.proto != protoTCP && p.proto != protoUDP) {
		return false
	}
	// never capture our own WireGuard traffic (would loop)
	if p.proto == protoUDP {
		if uint32(p.srcPort) == e.ownUDP.Load() {
			return false
		}
		for _, ep := range e.endpoints {
			if p.dstPort == ep.Port() && p.dst == ep.Addr() {
				return false
			}
		}
	}
	class, full := e.classify(p.proto, p.srcPort)
	if class == classNone && !full {
		return false
	}
	src, ok := e.tunAddr(p.v6)
	if !ok {
		// Config without IPv6: block IPv6 for tunnelled traffic instead of
		// letting it leak (the shop would reach the server from a second IP).
		// A TCP reset makes apps fall back to IPv4 at once.
		if p.v6 && !e.conf.Bypass(p.dst) {
			if r := buildTCPResetV6(pkt, &p); r != nil && p.tcpSYN {
				e.injectInbound(r, true, addr.IfIdx, addr.SubIfIdx)
			}
			e.cV6Block.Add(1)
			return true
		}
		return false
	}
	isGame := class == classGame
	dst := p.dst
	var dnsOrig netip.Addr
	if full && p.dstPort == 53 && !e.noDNS.Load() {
		if d, ok := e.conf.DNSFor(p.v6); ok && d != p.dst {
			dnsOrig, dst = p.dst, d // no DNS leaks: resolve through the tunnel
		}
	}
	if full && !dnsOrig.IsValid() && class != classSelf && e.conf.Bypass(dst) {
		return false // LAN, multicast… stays on the local network
	}
	allowed := e.conf.Allowed(dst)
	if !allowed && e.wfp != nil && e.wfpOn.Load() && class != classNone && class != classSelf && !e.conf.Bypass(dst) && dst.IsGlobalUnicast() {
		if err := e.routes.ensure(dst); err != nil {
			e.logf("WFP: não foi possível adicionar destino %s: %v", dst, err)
			return true
		}
		allowed = true
	}
	if !allowed {
		// Force UDP only extends direct secondary duplication to game UDP
		// destinations excluded by AllowedIPs. The original Windows route
		// remains untouched. Do not duplicate LAN, DNS or VPN endpoints.
		if e.udpDup != nil && e.udpForce.Load() &&
			shouldDuplicateGameUDP(isGame, full, p.proto, p.dstPort) &&
			!e.conf.Bypass(dst) && dst.IsGlobalUnicast() {
			e.udpDup.offer(pkt[:pktLen(pkt, &p)], *addr)
		}
		return false
	}
	if isGame {
		e.mirror.packet(true, pkt, &p)
		if e.mirror.enabled.Load() {
			e.meterWrite(pkt[:pktLen(pkt, &p)])
		}
	}
	out := clonePktBuf(pkt[:pktLen(pkt, &p)])

	k := natKey(p.proto, p.v6, p.srcPort)
	e.natMu.Lock()
	ne := e.nat[k]
	if ne == nil {
		ne = &natEntry{}
		e.nat[k] = ne
	}
	ne.local, ne.remote, ne.dnsOrig, ne.game, ne.class = p.src, p.dst, dnsOrig, isGame, class
	ne.ifIdx, ne.subIfIdx = addr.IfIdx, addr.SubIfIdx
	ne.last = time.Now()
	e.natMu.Unlock()

	setSrc(out, &p, src)
	if dnsOrig.IsValid() {
		setDst(out, &p, dst)
		e.cDNSQ.Add(1)
	}
	if p.v6 {
		clampMSS(out, &p, e.maxMSS6)
	} else {
		clampMSS(out, &p, e.maxMSS4)
	}
	fixChecksums(out, &p)
	pkts := [][]byte{out}
	if segs := segmentTCP(out, &p, e.conf.MTU); segs != nil {
		putPktBuf(out)
		pkts = segs
		e.cSegmented.Add(1)
	}
	eligibleCopy := e.udpDup != nil && shouldDuplicateGameUDP(isGame, full, p.proto, p.dstPort)
	for _, q := range pkts {
		e.up.Add(uint64(len(q)))
		if isGame {
			e.gameUp.Add(uint64(len(q)))
		}
		e.cCaptured.Add(1)
		if isGame && p.proto == protoUDP && e.latestOut.Load() && e.outboundQ != nil {
			job := outboundUDPJob{packet: q}
			if eligibleCopy {
				// Keep the source buffer alive for the asynchronous worker.
				job.copyUDP = clonePktBuf(pkt[:pktLen(pkt, &p)])
				job.copyAddr = *addr
			}
			e.outboundQ.offer(job)
		} else {
			e.tun.inject(q)
			if eligibleCopy {
				// Original has been submitted to the VPN before the copy.
				e.udpDup.offer(pkt[:pktLen(pkt, &p)], *addr)
			}
		}
	}
	return true
}

func (e *Engine) injectInbound(out []byte, v6 bool, ifIdx, subIfIdx uint32) bool {
	var addr divertAddress
	addr.IfIdx, addr.SubIfIdx = ifIdx, subIfIdx
	addr.SetOutbound(false)
	addr.SetIPv6(v6)
	if err := e.h.send(out, &addr); err != nil {
		e.cInjectErr.Add(1)
		return false
	}
	e.cInjected.Add(1)
	return true
}

// handleInbound receives decrypted packets from the VPN server. Latest-first
// processing is opt-in, only for NAT-matched game UDP datagrams. The buffer
// belongs to wireguard-go and must be copied before asynchronous processing.
func (e *Engine) handleInbound(pkt []byte) {
	if e.latestIn.Load() && e.inboundQ != nil {
		if p, ok := parsePacket(pkt); ok && p.proto == protoUDP && p.srcPort != 53 {
			e.natMu.Lock()
			ne := e.nat[natKey(p.proto, p.v6, p.dstPort)]
			game := ne != nil && ne.game && ne.local.Is6() == p.v6
			e.natMu.Unlock()
			if game {
				e.inboundQ.offer(clonePktBuf(pkt[:pktLen(pkt, &p)]))
				return
			}
		}
	}
	e.processInbound(pkt)
}

func (e *Engine) processInbound(pkt []byte) {
	p, ok := parsePacket(pkt)
	if !ok {
		return
	}
	if p.proto == protoICMP || p.proto == protoICMPv6 {
		if id, seq, ok := parseICMPEchoReply(pkt, &p); ok {
			e.pingReply(id, seq)
			return
		}
		e.relayICMPError(pkt, &p)
		return
	}
	e.natMu.Lock()
	ne := e.nat[natKey(p.proto, p.v6, p.dstPort)]
	var local, dnsOrig netip.Addr
	var ifIdx, subIfIdx uint32
	var game bool
	if ne != nil {
		local, dnsOrig, game = ne.local, ne.dnsOrig, ne.game
		ifIdx, subIfIdx = ne.ifIdx, ne.subIfIdx
		ne.last = time.Now()
	}
	e.natMu.Unlock()
	if ne == nil || local.Is6() != p.v6 {
		e.cInNoNAT.Add(1)
		return
	}
	if game {
		e.mirror.packet(false, pkt, &p)
	}
	n := pktLen(pkt, &p)
	out := pkt[:n]
	setDst(out, &p, local)
	if dnsOrig.IsValid() && p.srcPort == 53 {
		setSrc(out, &p, dnsOrig) // answer appears to come from the DNS the app asked
		e.cDNSA.Add(1)
	}
	if p.v6 {
		clampMSS(out, &p, e.maxMSS6)
	} else {
		clampMSS(out, &p, e.maxMSS4)
	}
	fixChecksums(out, &p)
	if game && e.mirror.enabled.Load() {
		e.meterWrite(out)
	}
	if e.injectInbound(out, p.v6, ifIdx, subIfIdx) {
		e.down.Add(uint64(n))
		if game {
			e.gameDown.Add(uint64(n))
		}
	}
}

// relayICMPError hands "fragmentation needed", "unreachable"… back to the
// app that sent the original packet, so Windows can adapt (Path MTU etc.).
func (e *Engine) relayICMPError(pkt []byte, p *pktInfo) {
	off, inner, ok := parseICMPError(pkt, p)
	if !ok {
		return
	}
	e.natMu.Lock()
	ne := e.nat[natKey(inner.proto, inner.v6, inner.srcPort)]
	var local netip.Addr
	var ifIdx, subIfIdx uint32
	if ne != nil {
		local, ifIdx, subIfIdx = ne.local, ne.ifIdx, ne.subIfIdx
	}
	e.natMu.Unlock()
	if ne == nil || local.Is6() != p.v6 {
		return
	}
	out := pkt[:pktLen(pkt, p)]
	rewriteICMPError(out, p, off, &inner, local)
	if e.injectInbound(out, p.v6, ifIdx, subIfIdx) {
		e.cICMPErr.Add(1)
	}
}

func (e *Engine) housekeeping() {
	tk := time.NewTicker(30 * time.Second)
	defer tk.Stop()
	// The health snapshot goes to the file log so a drop can be read afterwards.
	// It reuses this goroutine so Close() has nothing extra to wait for.
	hk := time.NewTicker(5 * time.Second)
	defer hk.Stop()
	var prev healthSample
	for {
		select {
		case <-e.stop:
			return
		case <-hk.C:
			if err := e.routes.flush(); err != nil {
				e.logf("WFP: gravando destinos no perfil: %v", err)
			}
			cur := e.healthSample()
			if line := formatHealth(cur, prev); line != "" {
				e.logDisk("%s", line)
			}
			prev = cur
		case <-tk.C:
			cut := time.Now().Add(-5 * time.Minute)
			e.natMu.Lock()
			for k, v := range e.nat {
				if v.last.Before(cut) {
					delete(e.nat, k)
				}
			}
			e.natMu.Unlock()
		}
	}
}

// healthSample reads the numbers the periodic snapshot records.
func (e *Engine) healthSample() healthSample {
	s := e.Stats()
	h := healthSample{
		HandshakeAgeSec: -1,
		CapturedPkts:    s.Diag.Captured, InjectedPkts: s.Diag.Injected,
		InjectErr: s.Diag.InjectErr, NoNAT: s.Diag.InNoNAT, QueueFull: s.Diag.TunDrop,
		Flows: s.Flows, MirrorOn: s.MirrorOn, MirrorFlows: len(s.MirrorFlows),
		PingTunnelMs: int(s.PingTunnel.RTT.Milliseconds()), PingLossPct: int(s.PingTunnel.Loss * 100),
	}
	if !s.Handshake.IsZero() {
		h.HandshakeAgeSec = int64(time.Since(s.Handshake).Seconds())
	}
	e.meterMu.Lock()
	if e.meter != nil {
		h.MeterPackets, h.MeterRingFull = e.meter.written.Load(), e.meter.full.Load()
	}
	e.meterMu.Unlock()
	return h
}

// logDisk writes a line to the file log only (not the screen). It is for
// periodic and high-volume diagnostics that would flood the TUI log panel.
func (e *Engine) logDisk(f string, a ...any) { diskLog.Printf(f, a...) }

// ---------------------------------------------------------------- ping

// gameServer returns the remote address with the most recently active TCP flow.
func (e *Engine) gameServer() netip.Addr {
	e.natMu.Lock()
	defer e.natMu.Unlock()
	var best netip.Addr
	var bt time.Time
	for k, v := range e.nat {
		if time.Since(v.last) > 30*time.Second {
			continue
		}
		if v.game && k.proto == protoTCP && v.last.After(bt) && v.remote.Is4() == e.addr4.IsValid() {
			best, bt = v.remote, v.last
		}
	}
	return best
}

func (e *Engine) pingLoop() {
	icmp, _ := newIcmpPinger()
	if icmp != nil {
		defer icmp.close()
	}
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
		}
		// 1) direct to the VPN server (outside the tunnel)
		if icmp != nil && e.endpoints[0].Addr().Is4() {
			go func(t netip.Addr) {
				rtt, code := icmp.ping(t, 900*time.Millisecond)
				e.pingMu.Lock()
				e.pings[0].err = code
				e.pings[0].record(code == 0, rtt)
				e.pingMu.Unlock()
			}(e.endpoints[0].Addr())
		}
		// 2) through the tunnel
		e.sendTunnelPing(pingIDGateway, e.gwTarget)
		if gs := e.gameServer(); gs.IsValid() {
			e.pingMu.Lock()
			if e.pings[pingIDGame].target != gs {
				e.pings[pingIDGame] = &pingState{target: gs}
			}
			e.pingMu.Unlock()
			e.sendTunnelPing(pingIDGame, gs)
		}
		// expire unanswered probes
		e.pingMu.Lock()
		for k, t := range e.pending {
			if time.Since(t) > 2*time.Second {
				delete(e.pending, k)
				if ps := e.pings[uint16(k>>16)]; ps != nil {
					ps.record(false, 0)
				}
			}
		}
		e.pingMu.Unlock()
	}
}

func (e *Engine) sendTunnelPing(id uint16, target netip.Addr) {
	if !target.IsValid() {
		return
	}
	src, ok := e.tunAddr(target.Is6())
	if !ok {
		return
	}
	e.pingMu.Lock()
	e.pingSeq++
	seq := e.pingSeq
	e.pending[uint32(id)<<16|uint32(seq)] = time.Now()
	e.pingMu.Unlock()
	e.tun.inject(buildICMPEcho(src, target, id, seq))
}

func (e *Engine) pingReply(id, seq uint16) {
	e.pingMu.Lock()
	defer e.pingMu.Unlock()
	k := uint32(id)<<16 | uint32(seq)
	if t, ok := e.pending[k]; ok {
		delete(e.pending, k)
		if ps := e.pings[id]; ps != nil {
			ps.record(true, time.Since(t))
		}
	}
}

// ---------------------------------------------------------------- stats / close

func (e *Engine) Stats() Stats {
	s := Stats{
		Up:         e.up.Load(),
		Down:       e.down.Load(),
		GameUp:     e.gameUp.Load(),
		GameDown:   e.gameDown.Load(),
		FullTunnel: e.full.Load(),
		Procs:      e.owner.Processes(),
		Endpoint:   e.endpoints[0].String(),
	}
	var addrs []string
	for _, a := range e.conf.Addresses {
		addrs = append(addrs, a.String())
	}
	s.TunnelAddr = strings.Join(addrs, ", ")
	var dns []string
	for _, d := range e.conf.DNS {
		dns = append(dns, d.String())
	}
	s.DNS = strings.Join(dns, ", ")
	wfpOn := e.wfpOn.Load() && e.wfp != nil
	s.WFPOn = wfpOn
	s.WFPSocket = e.wfp != nil && e.wfp.h != 0
	// WFP replaces the full tunnel, so it must not be reported while it is on.
	s.FullTunnel = s.FullTunnel && !wfpOn
	if wfpOn {
		s.Procs = e.wfp.table.SelectedProcs()
	}
	s.IPv6Direct = s.FullTunnel && !e.addr6.IsValid()
	s.DNSTunnel = s.FullTunnel && !e.noDNS.Load() && len(e.conf.DNS) > 0
	s.Diag = Diag{
		Captured: e.cCaptured.Load(), Injected: e.cInjected.Load(),
		InNoNAT: e.cInNoNAT.Load(), InjectErr: e.cInjectErr.Load(),
		TunDrop: e.tun.drops.Load(), Segmented: e.cSegmented.Load(),
		ICMPErr: e.cICMPErr.Load(), DNSQ: e.cDNSQ.Load(), DNSA: e.cDNSA.Load(),
		TableDumps: e.owner.Dumps(), V6Blocked: e.cV6Block.Load(),
	}
	sort.Slice(s.Procs, func(i, j int) bool { return s.Procs[i].PID < s.Procs[j].PID })

	e.natMu.Lock()
	for _, v := range e.nat {
		if time.Since(v.last) < 60*time.Second {
			s.Flows++
			if v.game {
				s.GameFlows++
			}
		}
	}
	e.natMu.Unlock()

	s.MirrorOn = e.mirror.enabled.Load()
	if e.udpDup != nil {
		s.UDPDupOn = e.udpDup.enabled.Load()
		s.UDPOriginals = int(e.udpDup.originals.Load())
		s.UDPCopies = int(e.udpDup.copies.Load())
		s.UDPForce = e.udpForce.Load()
		s.UDPNewestOut = e.latestOut.Load()
		s.UDPNewestIn = e.latestIn.Load()
		if e.outboundQ != nil {
			s.UDPSendDropped = e.outboundQ.dropped.Load()
		}
		if e.inboundQ != nil {
			s.UDPRecvDropped = e.inboundQ.dropped.Load()
		}
		s.UDPDupAccepted = e.udpDup.accepted.Load()
		s.UDPDupSent = e.udpDup.sent.Load()
		s.UDPDupDropped = e.udpDup.dropped.Load()
		s.UDPDupErrors = e.udpDup.errors.Load()
	}
	e.meterMu.Lock()
	if e.meter != nil {
		s.MeterAdapter = fmt.Sprintf("%s (%d pacotes)", meterAdapterName, e.meter.written.Load())
	} else {
		s.MeterAdapter = e.meterErr
	}
	s.MeterOK = e.meter != nil
	e.meterMu.Unlock()
	s.MirrorFlows = e.mirror.Flows()
	sort.Strings(s.MirrorFlows)

	e.pingMu.Lock()
	s.PingEndpoint = e.pings[0].result()
	s.PingTunnel = e.pings[pingIDGateway].result()
	s.PingGame = e.pings[pingIDGame].result()
	e.pingMu.Unlock()

	if uapi, err := e.dev.IpcGet(); err == nil {
		sc := bufio.NewScanner(strings.NewReader(uapi))
		for sc.Scan() {
			k, v, _ := strings.Cut(sc.Text(), "=")
			n, _ := strconv.ParseInt(v, 10, 64)
			switch k {
			case "rx_bytes":
				s.WGRx += uint64(n)
			case "tx_bytes":
				s.WGTx += uint64(n)
			case "last_handshake_time_sec":
				if n > 0 {
					t := time.Unix(n, 0)
					if t.After(s.Handshake) {
						s.Handshake = t
					}
				}
			}
		}
	}
	return s
}

func (e *Engine) SetProcesses(names []string) { e.owner.SetNames(names) }

// SetMirror must never block Bubble Tea's Update loop. Opening a Wintun
// adapter can take seconds (or wait on a driver), and the resulting log callback
// must not synchronously send to the same TUI event loop.
func (e *Engine) SetMirror(on bool) {
	if e.closing.Load() {
		return
	}
	e.logDisk("[espelho] ativo=%v", on)
	e.mirror.SetEnabled(on)
	e.setShugo(on)
	if on {
		e.requestMeter()
	}
}

// setShugo makes the mirror act as a relay for Shugo.gg: the compatibility
// layer exists exactly while [m] is on and is restored when it is turned off.
func (e *Engine) setShugo(on bool) {
	e.shugoMu.Lock()
	defer e.shugoMu.Unlock()
	if on && e.shugo == nil && !e.closing.Load() {
		e.shugo = startShugoCompat(e.logDisk)
	} else if !on && e.shugo != nil {
		e.shugo.Close()
		e.shugo = nil
	}
}

// requestMeter schedules at most one Wintun initialization. It never calls
// Windows driver APIs or user callbacks while holding meterMu.
func (e *Engine) requestMeter() {
	e.meterMu.Lock()
	if e.closing.Load() || !e.mirror.enabled.Load() || e.meter != nil || e.meterOpening {
		e.meterMu.Unlock()
		return
	}
	e.meterOpening = true
	e.meterErr = "inicializando AionWG-Meter…"
	e.meterMu.Unlock()
	go e.openMeterAsync()
}

func (e *Engine) openMeterAsync() {
	opener := e.meterOpener
	if opener == nil {
		opener = openMeterAdapter
	}
	m, err := opener()

	e.meterMu.Lock()
	e.meterOpening = false
	if e.closing.Load() || !e.mirror.enabled.Load() {
		e.meterErr = ""
		e.meterMu.Unlock()
		if m != nil {
			m.Close()
		}
		return
	}
	if err != nil {
		e.meterErr = err.Error()
		e.meterMu.Unlock()
		e.logf("adaptador do meter: %v", err)
		return
	}
	if m == nil {
		e.meterErr = "Wintun retornou adaptador nulo"
		e.meterMu.Unlock()
		e.logf("adaptador do meter: Wintun retornou adaptador nulo")
		return
	}
	e.meter, e.meterErr = m, ""
	e.meterMu.Unlock()
	e.logf("adaptador %s pronto — no meter, escolha esse adaptador (ou reabra o meter)", meterAdapterName)
}

func (e *Engine) meterWrite(pkt []byte) {
	e.meterMu.Lock()
	m := e.meter
	e.meterMu.Unlock()
	m.write(pkt)
}

// SetUDPDuplicate can be toggled without changing the primary route.
func (e *Engine) SetUDPDuplicate(on bool) {
	if e.closing.Load() || e.udpDup == nil {
		return
	}
	e.udpDup.setEnabled(on)
}

func (e *Engine) SetUDPRatio(originals, copies int) {
	if !e.closing.Load() && e.udpDup != nil {
		e.udpDup.setRatio(originals, copies)
	}
}
func (e *Engine) SetUDPForce(on bool) {
	if !e.closing.Load() {
		e.udpForce.Store(on)
	}
}
func (e *Engine) SetUDPNewestOut(on bool) {
	if !e.closing.Load() {
		e.latestOut.Store(on)
	}
}
func (e *Engine) SetUDPNewestIn(on bool) {
	if !e.closing.Load() {
		e.latestIn.Store(on)
	}
}

func (e *Engine) SetFullTunnel(on bool) { e.full.Store(on) }

func (e *Engine) SetNoDNS(off bool) { e.noDNS.Store(off) }

// SetWFP switches WFP mode. Both calls only touch atomics and a mutex-guarded
// map, so they are safe on Bubble Tea's Update goroutine.
func (e *Engine) SetWFP(on bool) {
	if !e.closing.Load() {
		e.wfpOn.Store(on)
	}
}

// SetWFPApps replaces the executables tunnelled in WFP mode; it applies to
// sockets already open, without reconnecting.
func (e *Engine) SetWFPApps(names []string) {
	if !e.closing.Load() && e.wfp != nil {
		e.wfp.table.SetApps(names)
		e.wfp.invalidateFallback()
	}
}

// ObservedRemotes returns server addresses used by the game and Steam.
func (e *Engine) ObservedRemotes() []netip.Addr {
	e.natMu.Lock()
	defer e.natMu.Unlock()
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, v := range e.nat {
		if (v.class == classGame || v.class == classApp) && !v.dnsOrig.IsValid() && !seen[v.remote] {
			seen[v.remote] = true
			out = append(out, v.remote)
		}
	}
	return out
}

// Endpoints returns the resolved VPN endpoints.
func (e *Engine) EndpointAddrs() []netip.Addr {
	var out []netip.Addr
	for _, ep := range e.endpoints {
		out = append(out, ep.Addr())
	}
	return out
}

func (e *Engine) Close() {
	if !e.closing.CompareAndSwap(false, true) {
		return
	}
	close(e.stop)
	if e.h != 0 {
		e.h.shutdown()
	}
	if e.dev != nil {
		e.dev.Close()
	}
	e.wg.Wait()
	if err := e.routes.flush(); err != nil {
		e.logf("WFP: gravando destinos no perfil: %v", err)
	}
	if e.h != 0 {
		e.h.close()
	}
	if e.owner != nil {
		e.owner.Close()
	}
	if e.wfp != nil {
		e.wfp.Close()
	}
	e.setShugo(false)
	if e.mirror != nil {
		e.mirror.Close()
	}
	e.meterMu.Lock()
	meter := e.meter
	e.meter = nil
	e.meterMu.Unlock()
	if meter != nil {
		meter.Close()
	}
}

// ---------------------------------------------------------------- direct ICMP (IcmpSendEcho)

var (
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

type icmpPinger struct {
	mu sync.Mutex
	h  uintptr
}

func newIcmpPinger() (*icmpPinger, error) {
	r, _, err := procIcmpCreateFile.Call()
	if windows.Handle(r) == windows.InvalidHandle {
		return nil, err
	}
	return &icmpPinger{h: r}, nil
}

func (p *icmpPinger) close() { procIcmpCloseHandle.Call(p.h) }

// ping returns the RTT and 0 on success; otherwise a Windows error code
// (ICMP_ECHO_REPLY.Status such as 11010 timeout / 11003 host unreachable, or GetLastError).
func (p *icmpPinger) ping(dst netip.Addr, timeout time.Duration) (time.Duration, uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := dst.As4()
	ip := *(*uint32)(unsafe.Pointer(&a[0])) // IPAddr is in network order in memory
	data := []byte("aionwg")
	reply := make([]byte, 28+len(data)+8+64)
	r, _, errno := procIcmpSendEcho.Call(p.h, uintptr(ip), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout.Milliseconds()))
	if r == 0 {
		if en, ok := errno.(syscall.Errno); ok && en != 0 {
			return 0, uint32(en)
		}
		return 0, 1
	}
	// ICMP_ECHO_REPLY: Address(4) Status(4) RoundTripTime(4) ...
	status := *(*uint32)(unsafe.Pointer(&reply[4]))
	rtt := *(*uint32)(unsafe.Pointer(&reply[8]))
	if status != 0 {
		return 0, status
	}
	d := time.Duration(rtt) * time.Millisecond
	if d == 0 {
		d = 500 * time.Microsecond
	}
	return d, 0
}
