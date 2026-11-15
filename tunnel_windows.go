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
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"aionwg/internal/telemetry"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// ---------------------------------------------------------------- engine

type natEntry struct {
	local      netip.Addr
	remote     netip.Addr
	remotePort uint16
	path       uint8
	dnsOrig    netip.Addr // valid when a DNS query was redirected to the tunnel DNS
	game       bool       // flow belongs to the game (mirror, game ping, game stats)
	class      uint8
	ifIdx      uint32
	subIfIdx   uint32
	last       time.Time
}

// mirroredClass: every WFP-selected app feeds the DPS meter mirror.
func mirroredClass(c uint8) bool {
	return c == classGame || c == classApp
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
	Processes        []string
	ProcessRules     []ProcessRule
	PingTarget       string
	Mirror           bool
	MirrorNoLoopback bool // skip the 127.0.0.1 TCP replay; AionWG-Meter feed unaffected
	UDPDuplicate     bool // send game UDP extra copies through the tunnel
	UDPOriginals     int  // A of A:B ratio
	UDPCopies        int  // B of A:B ratio
	UDPForce         bool // also copy game UDP outside AllowedIPs; never DNS/LAN/full tunnel
	UDPNewestOut     bool // opt-in latest-first ordering of primary game UDP sends
	UDPNewestIn      bool // opt-in latest-first ordering of primary game UDP arrivals
	FullTunnel       bool
	NoDNS            bool     // full tunnel: do NOT redirect DNS into the tunnel
	WFP              bool     // tunnel only WFPApps; replaces the port and full-tunnel modes
	WFPApps          []string // executables the user picked for WFP mode
	ConfigPath       string   // imported profile receiving learned WFP destinations
	ConfigPaths      []string
	BestEndpoint     bool // monitor and try faster endpoints while connected
	WarpMultipath    bool // WARP: open three extra sessions; opt-in for this connection
	CWBSearch        bool // pick the lowest-ping Curitiba endpoint, measured with a dummy target when no game runs
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
	Jitter time.Duration // mean absolute change between successful samples
	OK     bool
	Loss   float64 // 0..1 over the last 20 probes
	Err    uint32  // Windows IP_STATUS / GetLastError of the last failed direct ICMP (0 = none)
}

type Stats struct {
	Up, Down               uint64 // all bytes through the tunnel (inner)
	GameUp, GameDown       uint64 // game-only bytes
	WGRx, WGTx             uint64 // WireGuard wire bytes
	Handshake              time.Time
	Flows                  int
	GameFlows              int
	Procs                  []ProcInfo
	PingEndpoint           PingResult // direct ICMP to VPN server (outside the tunnel)
	PingTunnel             PingResult // ICMP through the tunnel to the gateway
	PingGame               PingResult // ICMP through the tunnel to the game server
	PingGameDirect         PingResult // ICMP straight to the game server, outside the tunnel
	MirrorOn               bool
	UDPDupOn               bool   // worker enabled; active only in split-tunnel mode
	UDPOriginals           int    // A of the A:B ratio
	UDPCopies              int    // B of the A:B ratio
	UDPForce               bool   // duplicate game UDP outside AllowedIPs
	UDPNewestOut           bool   // latest-first primary game UDP send
	UDPNewestIn            bool   // latest-first primary game UDP arrival
	UDPSendDropped         uint64 // oldest outbound UDP packets evicted from LIFO queue
	UDPRecvDropped         uint64 // oldest inbound UDP packets evicted from LIFO queue
	UDPDupAccepted         uint64 // copies queued
	UDPDupSent             uint64 // copies reinjected to Windows
	UDPDupDropped          uint64 // copies dropped rather than slowing the original
	UDPDupErrors           uint64 // secondary path errors
	MirrorFlows            []string
	MirrorAck              MirrorRTT // ACK round trip of the game TCP as seen by the mirror
	MirrorResp             MirrorRTT // request -> first reply payload (application level)
	MeterAdapter           string
	MeterOK                bool
	FullTunnel             bool
	DNS                    string // DNS used for the full tunnel ("" = none in config)
	IPv6Direct             bool   // full tunnel but config has no IPv6 address
	WFPOn                  bool   // WFP mode: only the selected apps are tunnelled
	WFPSocket              bool   // SOCKET layer open (false = system-table fallback only)
	PolicyBackend          string
	PacketBackend          string
	NativeWFP              NativeWFPStatus
	DNSTunnel              bool // DNS redirect active
	Diag                   Diag
	Telemetry              telemetry.Snapshot
	Endpoint               string
	TunnelAddr             string
	Route                  RouteTrace // latest traceroute of the route in use
	RouteMonitor           bool       // best-endpoint option active for this connection
	RouteNote              string     // last route monitor / endpoint switch message
	Exit                   ExitInfo   // where the tunnel exits (zero until measured)
	Paths                  []udpPathStatus
	Backend                string
	DriverLoaded           bool
	InterceptorActive      bool
	VirtualInterfaceActive bool
	WireGuardActive        bool
	HandshakeValid         bool
	RouteApplied           bool
	ForwardingActive       bool
	TunnelReachable        bool
	DestinationReachable   bool
}

type outboundUDPJob struct {
	packet  []byte // original routed packet, already SNAT'd for WireGuard
	copyUDP []byte // optional copy of packet for the secondary (duplicate) send
	path    uint8
}

type Engine struct {
	conf      *WGConf
	endpoints []netip.AddrPort // as resolved at start; use eps() after that
	epCur     atomic.Pointer[[]netip.AddrPort]
	// primaryHold is set while the primary endpoint is being switched: new flows
	// and duplicates use the extra UDP paths instead.
	primaryHold      atomic.Bool
	epMu             sync.Mutex // serialises runtime endpoint switches
	dev              *device.Device
	tun              *splitTun
	h                divertHandle
	owner            *ownerTracker
	mirror           *mirror
	shugoMu          sync.Mutex
	shugo            *shugoCompat  // Shugo.gg relay view; exists only while [m] is on
	shugoOld         chan struct{} // done of the last supervisor being stopped in the background
	udpDup           *udpDuplicator[uint8]
	paths            [maxPaths - 1]*udpPath
	dupPath          atomic.Uint64
	udpForce         atomic.Bool
	latestOut        atomic.Bool
	latestIn         atomic.Bool
	outboundQ        *latestQueue[outboundUDPJob]
	inboundQ         *latestQueue[[]byte]
	meterMu          sync.Mutex
	meter            *meterAdapter // Wintun copy for Npcap-based DPS meters
	meterErr         string
	meterDup         meterDedup                    // one copy of each inbound reply to the meter; the game gets all
	meterOpening     bool                          // protected by meterMu; never initialize Wintun on the TUI goroutine
	meterOpener      func() (*meterAdapter, error) // injectable for regression tests
	addr4            netip.Addr
	addr6            netip.Addr
	maxMSS4          uint16
	maxMSS6          uint16
	logf             func(string, ...any)
	telemetrySampler telemetry.Sampler

	natMu sync.Mutex
	nat   map[portKey]*natEntry
	// gameDst: servers the game (classGame) has used. Other WFP apps tunnel only
	// to these; the rest of their TCP/UDP leaves on the normal route.
	gameDst map[netip.Addr]bool

	up, down                                   atomic.Uint64
	gameUp, gameDown                           atomic.Uint64
	wgRxBytes, wgTxBytes                       atomic.Uint64
	wgHandshake                                atomic.Int64
	full                                       atomic.Bool
	noDNS                                      atomic.Bool
	wfpOn                                      atomic.Bool // WFP mode: only the selected apps are tunnelled
	wfp                                        *wfpMonitor // nil when the SOCKET layer could not be opened
	nativeWFP                                  nativeWFPPolicy
	nativeWFPUpdates                           chan []ProcessRule
	access                                     accessLog // remotes per program, reported every 30 s
	cCaptured, cInjected, cInNoNAT, cInjectErr atomic.Uint64
	cSegmented, cICMPErr, cDNSQ, cDNSA         atomic.Uint64
	cV6Block                                   atomic.Uint64
	ownUDP                                     atomic.Uint32 // our own WireGuard socket port (never captured)

	closing atomic.Bool
	wg      sync.WaitGroup
	stop    chan struct{}

	pingMu    sync.Mutex
	pingSeq   uint16
	pending   map[uint32]time.Time // id<<16|seq -> sent
	pings     map[uint16]*pingState
	gwTarget  netip.Addr
	profile   string // profile file name: key of the persisted routes
	lrMu      sync.Mutex
	learned   map[netip.AddrPort]bool // endpoints proven by a handshake (route monitor)
	routeMon  bool
	cwbOn     bool // dummy-target pings feed the Curitiba search
	routeNote atomic.Pointer[string]
	exit      atomic.Pointer[ExitInfo]
	geoMu     sync.Mutex
	geoWait   map[uint16]chan string // DNS id -> waiting exit query
	geoSeq    uint16
	trace     atomic.Pointer[RouteTrace]
	traceKick chan struct{}
	traceMu   sync.Mutex
	traceRun  uint8
	traceSent map[uint16]time.Time
	traceGot  map[uint16]traceAnswer
}

type pingState struct {
	target  netip.Addr
	last    time.Duration
	ok      bool
	seen    bool // a reply arrived once; earlier timeouts are startup noise, not loss
	err     uint32
	history []bool
	rtts    []time.Duration // recent replies, newest last
}

func (s *pingState) result() PingResult {
	r := PingResult{RTT: s.last, Jitter: rttJitter(s.rtts), OK: s.ok, Err: s.err}
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
		s.seen = true
		s.rtts = append(s.rtts, rtt)
		if len(s.rtts) > 10 {
			s.rtts = s.rtts[1:]
		}
	} else if !s.seen {
		return
	}
	s.history = append(s.history, ok)
	if len(s.history) > 20 {
		s.history = s.history[1:]
	}
}

const (
	pingIDGateway    = 0xA102
	pingIDGame       = 0xA103
	pingIDTrace      = 0xA104
	pingIDGameDirect = 0xA105 // map key only: this probe is a plain Windows ICMP echo
	pingIDDummy      = 0xA106 // map key only: idle-time target (cwbDummyTarget) when no game server is known
)

func StartEngine(conf *WGConf, opt EngineOptions, logf func(string, ...any)) (*Engine, error) {
	e := &Engine{
		conf:      conf,
		logf:      logf,
		traceKick: make(chan struct{}, 1),
		traceSent: map[uint16]time.Time{},
		traceGot:  map[uint16]traceAnswer{},
		routeMon:  opt.BestEndpoint,
		cwbOn:     opt.CWBSearch,
		nat:       map[portKey]*natEntry{},
		gameDst:   map[netip.Addr]bool{},
		stop:      make(chan struct{}),
		pending:   map[uint32]time.Time{},
		pings: map[uint16]*pingState{
			pingIDGateway:    {},
			pingIDGame:       {},
			pingIDGameDirect: {},
			pingIDDummy:      {},
			0:                {}, // endpoint (direct)
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

	profileKey := filepath.Base(opt.ConfigPath)
	var learnedEPs []netip.AddrPort
	if opt.BestEndpoint {
		learnedEPs = loadRoutes(routesPath(), profileKey)
	}
	for _, p := range conf.Peers {
		ep, err := ResolveEndpoint(p.Endpoint)
		if err != nil {
			return nil, err
		}
		if len(e.endpoints) == 0 {
			e.profile = profileKey
			e.learned = map[netip.AddrPort]bool{ep: true}
			if opt.BestEndpoint {
				for _, r := range learnedEPs {
					e.learned[r] = true
				}
			}
		}
		e.endpoints = append(e.endpoints, ep)
	}
	startEPs := append([]netip.AddrPort(nil), e.endpoints...)
	e.epCur.Store(&startEPs)
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
	e.owner.SetRules(opt.ProcessRules, opt.Processes)
	e.nativeWFP = newNativeWFPManager(logf)
	if err := e.nativeWFP.Open(); err != nil {
		logf("aviso: Native WFP User Mode indisponível: %v", err)
	} else if err := e.nativeWFP.ReplaceRules(opt.ProcessRules); err != nil {
		logf("aviso: políticas BLOCK não aplicadas no WFP nativo: %v", err)
	}
	if e.nativeWFP.Status().SessionOpen {
		e.nativeWFPUpdates = make(chan []ProcessRule, 1)
		e.wg.Add(1)
		go e.nativeWFPApplyLoop()
	}
	e.mirror = newMirror(opt.Mirror, logf)
	e.mirror.trace = e.logDisk
	e.mirror.noLoopback.Store(opt.MirrorNoLoopback)
	e.udpDup = newUDPDuplicator[uint8](udpDupQueueSize, opt.UDPDuplicate)
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
	e.wg.Add(1)
	go e.wgStatsLoop()
	if err := e.startUDPPaths(opt.WarpMultipath); err != nil {
		e.Close()
		return nil, err
	}

	for i := 0; i < 4; i++ {
		e.wg.Add(1)
		go e.divertLoop()
	}
	for _, loop := range []func(){e.housekeeping, e.pingLoop, e.traceLoop} {
		e.wg.Add(1)
		go func() { defer e.wg.Done(); loop() }()
	}
	e.wg.Add(1)
	go func() { defer e.wg.Done(); e.scanLoop(opt.BestEndpoint) }()
	if opt.BestEndpoint {
		e.wg.Add(1)
		go func() { defer e.wg.Done(); e.routeLoop() }()
	}
	if opt.CWBSearch {
		e.wg.Add(1)
		go func() { defer e.wg.Done(); e.cwbLoop() }()
	}
	if e.paths[0] != nil {
		e.wg.Add(1)
		go func() { defer e.wg.Done(); e.pathLoop() }()
	}
	e.wg.Add(3)
	go e.runUDPDuplicateWorker()
	go func() {
		defer e.wg.Done()
		e.outboundQ.run(e.stop, func(job outboundUDPJob) {
			if !e.closing.Load() {
				e.pathTun(job.path).inject(job.packet)
				if len(job.copyUDP) > 0 && e.udpDup != nil {
					e.udpDup.offer(job.copyUDP, job.path)
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
	if opt.BestEndpoint {
		logf("rota: busca dinâmica ativa: reavalia os endpoints conhecidos a cada %v; procura novos a cada %v quando o jogo está parado", routeEvery, discoverEvery)
	}
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
		for _, path := range e.paths {
			if path != nil {
				ep := path.currentEndpoint()
				if p.srcPort == path.port || (p.dstPort == ep.Port() && p.dst == ep.Addr()) {
					return false
				}
			}
		}
		for _, ep := range e.eps() {
			if p.dstPort == ep.Port() && p.dst == ep.Addr() {
				return false
			}
		}
	}
	if e.wfp != nil {
		if pid, ok := e.wfp.table.Owner(p.proto, p.srcPort, time.Now()); ok {
			e.access.add(e.wfp.table.ProcName(pid), netip.AddrPortFrom(p.dst, p.dstPort))
		}
	}
	class, full := e.classify(p.proto, p.srcPort)
	if class == classBlock {
		return true
	}
	if class == classBypass || (class == classNone && !full) {
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
	if isGame {
		e.markGameDst(p.dst)
	} else if class == classApp && e.wfpOn.Load() && e.wfp != nil && !e.isGameDst(p.dst) {
		return false // other WFP app, not a game server: normal route
	}
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
	// WFP mode: the selected app's traffic is tunnelled whatever AllowedIPs says.
	wfpApp := isGame && e.wfpOn.Load() && e.wfp != nil
	if !wfpApp && !e.conf.Allowed(dst) {
		// Force UDP: game UDP to destinations excluded by AllowedIPs. The original
		// keeps the normal Windows route; only the extra copies take the tunnel
		// (the device accepts any destination, see WGConf.UAPI). No LAN, DNS or VPN endpoints.
		if e.udpDup != nil && e.udpForce.Load() &&
			shouldDuplicateGameUDP(isGame, full, p.proto, p.dstPort) &&
			!e.conf.Bypass(dst) && dst.IsGlobalUnicast() {
			cp := clonePktBuf(pkt[:pktLen(pkt, &p)])
			setSrc(cp, &p, src)
			fixChecksums(cp, &p)
			e.udpDup.offer(cp, 0)
			putPktBuf(cp)
		}
		return false
	}
	if mirroredClass(class) {
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
		ne = &natEntry{path: e.selectPath(k)}
		e.nat[k] = ne
	} else if ne.remote != p.dst || ne.remotePort != p.dstPort {
		ne.path = e.selectPath(k)
	}
	if ne.path > 0 && e.pathTun(ne.path) == e.tun {
		ne.path = 0
	}
	ne.local, ne.remote, ne.remotePort, ne.dnsOrig, ne.game, ne.class = p.src, p.dst, p.dstPort, dnsOrig, isGame, class
	ne.ifIdx, ne.subIfIdx = addr.IfIdx, addr.SubIfIdx
	ne.last = time.Now()
	path := ne.path
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
			job := outboundUDPJob{packet: q, path: path}
			if eligibleCopy {
				// Keep the source buffer alive for the asynchronous worker.
				job.copyUDP = clonePktBuf(q) // before offer: the queue takes ownership of q
			}
			e.outboundQ.offer(job)
		} else {
			if eligibleCopy {
				// Queue the copy before inject: inject hands q to the tunnel, which recycles it.
				e.udpDup.offer(q, path)
			}
			e.pathTun(path).inject(q)
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
		if from, seq, ok := parseTraceReply(pkt, &p, pingIDTrace); ok {
			e.traceHit(from, seq)
			return
		}
		if id, seq, ok := parseICMPEchoReply(pkt, &p); ok {
			e.pingReply(id, seq)
			return
		}
		e.relayICMPError(pkt, &p)
		return
	}
	if p.proto == protoUDP && p.dstPort == geoPort {
		e.geoReply(pkt, &p)
		return
	}
	e.natMu.Lock()
	ne := e.nat[natKey(p.proto, p.v6, p.dstPort)]
	var local, dnsOrig netip.Addr
	var ifIdx, subIfIdx uint32
	var game, mirrored bool
	if ne != nil {
		local, dnsOrig, game, mirrored = ne.local, ne.dnsOrig, ne.game, mirroredClass(ne.class)
		ifIdx, subIfIdx = ne.ifIdx, ne.subIfIdx
		ne.last = time.Now()
	}
	e.natMu.Unlock()
	if ne == nil || local.Is6() != p.v6 {
		e.cInNoNAT.Add(1)
		return
	}
	if mirrored {
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
	if mirrored && e.mirror.enabled.Load() && !e.meterDup.seen(out, &p, time.Now()) {
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
			cur := e.healthSample()
			if line := formatHealth(cur, prev); line != "" {
				e.logDisk("%s", line)
			}
			if ack, resp := e.mirror.RTT(); ack.N+resp.N > 0 {
				e.logDisk("[espelho-rtt] ack=%v (media %v, n=%d) resposta=%v (media %v, n=%d)",
					ack.Last.Round(time.Millisecond), ack.Avg.Round(time.Millisecond), ack.N,
					resp.Last.Round(time.Millisecond), resp.Avg.Round(time.Millisecond), resp.N)
			}
			e.meterMu.Lock()
			mt := e.meter
			e.meterMu.Unlock()
			if avg, mx, n := mt.takeLatency(); n > 0 {
				e.logDisk("[meter-lat] escritas=%d no adaptador: media=%v max=%v respostas-duplicadas-ocultas=%d", n, avg.Round(time.Microsecond), mx.Round(time.Microsecond), e.meterDup.droppedCount())
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
			for _, line := range e.access.take() {
				e.logDisk("[acesso] %s", line)
			}
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
		PingGameMs: pingMs(s.PingGame), PingGameDirectMs: pingMs(s.PingGameDirect),
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
	icmpGame, _ := newIcmpPinger() // own handle: the endpoint probe above can wait 1.5 s
	if icmpGame != nil {
		defer icmpGame.close()
	}
	var gameInFlight atomic.Bool
	var inFlight atomic.Bool
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
		}
		// 1) direct to the VPN server (outside the tunnel)
		if icmp != nil && e.eps()[0].Addr().Is4() {
			if inFlight.CompareAndSwap(false, true) {
				go func(t netip.Addr) {
					defer inFlight.Store(false)
					rtt, code := icmp.ping(t, 1500*time.Millisecond)
					e.pingMu.Lock()
					e.pings[0].err = code
					e.pings[0].record(code == 0, rtt)
					e.pingMu.Unlock()
				}(e.eps()[0].Addr())
			}
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
		if e.cwbOn {
			e.pingMu.Lock()
			if e.pings[pingIDDummy].target != cwbDummyTarget {
				e.pings[pingIDDummy] = &pingState{target: cwbDummyTarget}
			}
			e.pingMu.Unlock()
			e.sendTunnelPing(pingIDDummy, cwbDummyTarget)
		}
		// 3) straight to the game server, outside the tunnel: shows what the tunnel costs
		if gs := e.gameServer(); gs.IsValid() && gs.Is4() && icmpGame != nil {
			e.pingMu.Lock()
			if ps := e.pings[pingIDGameDirect]; ps == nil || ps.target != gs {
				e.pings[pingIDGameDirect] = &pingState{target: gs}
			}
			e.pingMu.Unlock()
			if gameInFlight.CompareAndSwap(false, true) {
				go func(t netip.Addr) {
					defer gameInFlight.Store(false)
					rtt, code := icmpGame.ping(t, 1500*time.Millisecond)
					e.pingMu.Lock()
					if ps := e.pings[pingIDGameDirect]; ps != nil && ps.target == t {
						ps.err = code
						ps.record(code == 0, rtt)
					}
					e.pingMu.Unlock()
				}(gs)
			}
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

func (e *Engine) wgStatsLoop() {
	defer e.wg.Done()
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
		}
		devices := [maxPaths]*device.Device{e.dev}
		for i, path := range e.paths {
			if path != nil {
				devices[i+1] = path.dev
			}
		}
		var rx, tx uint64
		var handshake int64
		for _, dev := range devices {
			if dev == nil {
				continue
			}
			uapi, err := dev.IpcGet()
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(strings.NewReader(uapi))
			for sc.Scan() {
				k, v, _ := strings.Cut(sc.Text(), "=")
				n, _ := strconv.ParseInt(v, 10, 64)
				switch k {
				case "rx_bytes":
					rx += uint64(n)
				case "tx_bytes":
					tx += uint64(n)
				case "last_handshake_time_sec":
					if n > 0 && n > handshake {
						handshake = n
					}
				}
			}
		}
		e.wgRxBytes.Store(rx)
		e.wgTxBytes.Store(tx)
		if handshake > 0 {
			e.wgHandshake.Store(time.Unix(handshake, 0).UnixNano())
		}
	}
}

func (e *Engine) Stats() Stats {
	s := Stats{
		Up:                     e.up.Load(),
		Down:                   e.down.Load(),
		GameUp:                 e.gameUp.Load(),
		GameDown:               e.gameDown.Load(),
		WGRx:                   e.wgRxBytes.Load(),
		WGTx:                   e.wgTxBytes.Load(),
		FullTunnel:             e.full.Load(),
		Telemetry:              e.telemetrySampler.Sample(),
		Procs:                  e.owner.Processes(),
		Endpoint:               e.eps()[0].String(),
		DriverLoaded:           e.h != 0,
		InterceptorActive:      e.h != 0,
		VirtualInterfaceActive: e.tun != nil,
		WireGuardActive:        e.dev != nil,
		RouteApplied:           e.h != 0 && e.dev != nil,
		ForwardingActive:       e.h != 0 && e.dev != nil && e.tun != nil,
	}
	if n := e.wgHandshake.Load(); n > 0 {
		s.Handshake = time.Unix(0, n)
	}
	s.Paths = append(s.Paths, udpPathStatus{Endpoint: e.eps()[0]})
	for _, path := range e.paths {
		if path != nil {
			now := time.Now()
			last := path.lastRx.Load()
			var age time.Duration
			if last > 0 {
				age = now.Sub(time.Unix(0, last))
			}
			s.Paths = append(s.Paths, udpPathStatus{
				Endpoint: path.currentEndpoint(),
				Active:   path.active(now),
				RTT:      time.Duration(path.rtt.Load()),
				Age:      age,
			})
		}
	}
	if rt := e.trace.Load(); rt != nil {
		s.Route = *rt
	}
	s.RouteMonitor = e.routeMon
	if n := e.routeNote.Load(); n != nil {
		s.RouteNote = *n
	}
	if x := e.exit.Load(); x != nil {
		s.Exit = *x
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
	s.PacketBackend = "WinDivert NETWORK"
	s.PolicyBackend = "Native WFP User Mode Policy"
	if e.nativeWFP != nil {
		s.NativeWFP = e.nativeWFP.Status()
		if !s.NativeWFP.SessionOpen {
			s.PolicyBackend = "Native WFP User Mode Policy (erro)"
		}
	}
	s.Backend = s.PacketBackend
	if wfpOn {
		s.Backend = "Native WFP User Mode Policy + WinDivert NETWORK"
	}
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
	for _, path := range e.paths {
		if path != nil {
			s.Diag.TunDrop += path.tun.drops.Load()
		}
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
	s.MirrorAck, s.MirrorResp = e.mirror.RTT()

	e.pingMu.Lock()
	s.PingEndpoint = e.pings[0].result()
	s.PingTunnel = e.pings[pingIDGateway].result()
	s.PingGame = e.pings[pingIDGame].result()
	if ps := e.pings[pingIDGameDirect]; ps != nil {
		s.PingGameDirect = ps.result()
	}
	e.pingMu.Unlock()
	s.TunnelReachable = s.PingTunnel.OK
	s.DestinationReachable = s.PingGame.OK
	s.Paths[0].Active = s.PingTunnel.OK

	s.HandshakeValid = !s.Handshake.IsZero() && time.Since(s.Handshake) < 3*time.Minute
	return s
}

func (e *Engine) SetProcesses(names []string) { e.owner.SetNames(names) }
func (e *Engine) nativeWFPApplyLoop() {
	defer e.wg.Done()
	for {
		select {
		case <-e.stop:
			return
		case rules := <-e.nativeWFPUpdates:
			if e.nativeWFP == nil {
				return
			}
			if err := e.nativeWFP.ReplaceRules(rules); err != nil {
				e.logf("WFP nativo: regras não aplicadas: %v", err)
			}
		}
	}
}

func (e *Engine) queueNativeWFPRules(rules []ProcessRule) {
	if e.nativeWFPUpdates == nil || e.closing.Load() {
		return
	}
	queued := append([]ProcessRule(nil), rules...)
	select {
	case e.nativeWFPUpdates <- queued:
	default:
		select {
		case <-e.nativeWFPUpdates:
		default:
		}
		select {
		case e.nativeWFPUpdates <- queued:
		default:
		}
	}
}

func (e *Engine) SetProcessRules(rules []ProcessRule, names []string) {
	e.owner.SetRules(rules, names)
	if e.nativeWFP != nil {
		e.queueNativeWFPRules(rules)
	}
}

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
// The stop runs in the background (it can wait seconds per target) so the UI
// goroutine never blocks; Close waits for it, and a re-enable waits for it too.
func (e *Engine) setShugo(on bool) {
	e.shugoMu.Lock()
	defer e.shugoMu.Unlock()
	if on && e.shugo == nil && !e.closing.Load() {
		e.shugo = startShugoCompat(e.logDisk, e.shugoOld)
	} else if !on && e.shugo != nil {
		old := e.shugo
		e.shugo, e.shugoOld = nil, old.done
		go old.Close()
	}
}

// waitShugo blocks until a background shugo stop has restored the hooks.
func (e *Engine) waitShugo() {
	e.shugoMu.Lock()
	old := e.shugoOld
	e.shugoMu.Unlock()
	if old != nil {
		<-old
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

// markGameDst records a server the game talks to.
func (e *Engine) markGameDst(dst netip.Addr) {
	e.natMu.Lock()
	e.gameDst[dst] = true
	e.natMu.Unlock()
}

// isGameDst reports whether the game has talked to dst; other WFP apps tunnel
// only to those servers.
func (e *Engine) isGameDst(dst netip.Addr) bool {
	e.natMu.Lock()
	defer e.natMu.Unlock()
	return e.gameDst[dst]
}

// Endpoints returns the resolved VPN endpoints.
func (e *Engine) EndpointAddrs() []netip.Addr {
	var out []netip.Addr
	for _, ep := range e.eps() {
		out = append(out, ep.Addr())
	}
	return out
}

// eps is the endpoint list currently in use (it can change at runtime).
func (e *Engine) eps() []netip.AddrPort { return *e.epCur.Load() }

// endpointSwitchWait bounds how long a runtime switch waits for the handshake.
var endpointSwitchWait = 6 * time.Second

// SetEndpointString switches the first peer's endpoint while the tunnel runs.
// v is "ip" or "ip:port"; the port defaults to the current one.
func (e *Engine) SetEndpointString(v string) error {
	v = strings.TrimSpace(v)
	ep, err := netip.ParseAddrPort(v)
	if err != nil {
		a, aerr := netip.ParseAddr(v)
		if aerr != nil {
			return fmt.Errorf("endpoint inválido %q (use IP ou IP:porta)", v)
		}
		ep = netip.AddrPortFrom(a, e.eps()[0].Port())
	}
	return e.SetEndpoint(ep)
}

// SetEndpoint switches the first peer's endpoint in memory: the profile file
// is never written and the next connection uses the profile again. A switch
// that does not complete a handshake is undone.
func (e *Engine) SetEndpoint(ep netip.AddrPort) error {
	e.epMu.Lock()
	defer e.epMu.Unlock()
	if e.closing.Load() {
		return errors.New("túnel fechando")
	}
	prev := e.eps()
	if prev[0] == ep {
		e.routeLog("rota: já está em %s; nada a trocar", ep)
		return nil
	}
	// An extra path holding ep gives it to the primary; the primary's old
	// endpoint goes to that path once the handshake is confirmed.
	j := e.pathIndexUsing(ep)
	e.primaryHold.Store(true)
	defer e.primaryHold.Store(false)
	apply := func(to netip.AddrPort) error {
		next := append([]netip.AddrPort{to}, prev[1:]...)
		if err := e.dev.IpcSet(e.conf.UAPI(next)); err != nil {
			return err
		}
		e.epCur.Store(&next)
		e.pingMu.Lock()
		e.pings[0] = &pingState{target: to.Addr()}
		e.pingMu.Unlock()
		return nil
	}
	if err := apply(ep); err != nil {
		return err
	}
	key := hex.EncodeToString(e.conf.Peers[0].PublicKey)
	ok := false
	for end := time.Now().Add(endpointSwitchWait); !ok && time.Now().Before(end); {
		ipc, _ := e.dev.IpcGet()
		if ok = handshakenPeers(ipc)[key]; !ok && !e.nap(100*time.Millisecond) {
			return errors.New("túnel fechando")
		}
	}
	if ok {
		if j >= 0 {
			p := e.paths[j]
			if err := p.setEndpoint(prev[0]); err != nil {
				if rerr := apply(prev[0]); rerr != nil {
					return fmt.Errorf("caminho %d não aceitou %s e o principal não voltou: %w", j+2, prev[0], errors.Join(err, rerr))
				}
				return fmt.Errorf("caminho %d não aceitou %s: %w", j+2, prev[0], err)
			}
			e.logf("UDP caminho %d: trocado para %s (o principal assumiu %s)", j+2, prev[0], ep)
		}
		e.routeLog("rota: endpoint trocado %s -> %s (handshake ok; o perfil não foi alterado)", prev[0], ep)
		e.learn(ep)
		e.kickTrace()
		return nil
	}
	if err := apply(prev[0]); err != nil {
		return fmt.Errorf("sem handshake em %s e não foi possível voltar para %s: %w", ep, prev[0], err)
	}
	e.routeLog("rota: %s não completou o handshake em %v; voltou para %s", ep, endpointSwitchWait, prev[0])
	e.kickTrace()
	return fmt.Errorf("sem handshake em %s", ep)
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
	for _, path := range e.paths {
		if path != nil {
			path.close()
		}
	}
	e.wg.Wait()
	if e.h != 0 {
		e.h.close()
	}
	if e.owner != nil {
		e.owner.Close()
	}
	if e.wfp != nil {
		e.wfp.Close()
	}
	if e.nativeWFP != nil {
		e.nativeWFP.Close()
	}
	e.setShugo(false)
	e.waitShugo()
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

// close waits for an echo in flight (p.mu) and disables the pinger for good.
func (p *icmpPinger) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.h != 0 {
		procIcmpCloseHandle.Call(p.h)
		p.h = 0
	}
}

// ping returns the RTT and 0 on success; otherwise a Windows error code
// (ICMP_ECHO_REPLY.Status such as 11010 timeout / 11003 host unreachable, or GetLastError).
func (p *icmpPinger) ping(dst netip.Addr, timeout time.Duration) (time.Duration, uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.h == 0 {
		return 0, 1
	}
	a := dst.As4()
	ip := *(*uint32)(unsafe.Pointer(&a[0])) // IPAddr is in network order in memory
	data := []byte("aionwg")
	reply := make([]byte, 28+len(data)+8+64)
	r, _, errno := procIcmpSendEcho.Call(p.h, uintptr(ip), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout.Milliseconds()))
	if r == 0 {
		procIcmpCloseHandle.Call(p.h)
		if nh, _, _ := procIcmpCreateFile.Call(); windows.Handle(nh) != windows.InvalidHandle {
			p.h = nh
		}
		if en, ok := errno.(syscall.Errno); ok && en != 0 {
			return 0, uint32(en)
		}
		return 0, 1
	}
	// ICMP_ECHO_REPLY: Address(4) Status(4) RoundTripTime(4) ...
	status := *(*uint32)(unsafe.Pointer(&reply[4]))
	rtt := *(*uint32)(unsafe.Pointer(&reply[8]))
	if status != 0 {
		procIcmpCloseHandle.Call(p.h)
		if nh, _, _ := procIcmpCreateFile.Call(); windows.Handle(nh) != windows.InvalidHandle {
			p.h = nh
		}
		return 0, status
	}
	d := time.Duration(rtt) * time.Millisecond
	if d == 0 {
		d = 500 * time.Microsecond
	}
	return d, 0
}

// legProbe measures the direct leg to an endpoint; tests replace it.
var legProbe = icmpMedian

// icmpMedian is the median of 5 echo replies; it fails with fewer than 3.
func icmpMedian(a netip.Addr) (time.Duration, bool) {
	p, err := newIcmpPinger()
	if err != nil {
		return 0, false
	}
	defer p.close()
	var rtts []time.Duration
	for range 5 {
		if rtt, code := p.ping(a, 800*time.Millisecond); code == 0 {
			rtts = append(rtts, rtt)
		}
	}
	if len(rtts) < 3 {
		return 0, false
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	return rtts[len(rtts)/2], true
}

// icmpOnce is a single echo, used to sweep many addresses cheaply.
func icmpOnce(a netip.Addr) (time.Duration, bool) {
	p, err := newIcmpPinger()
	if err != nil {
		return 0, false
	}
	defer p.close()
	rtt, code := p.ping(a, 600*time.Millisecond)
	return rtt, code == 0
}

// probeHandshake reports whether a throwaway WireGuard device completes a
// handshake with p at ep. ICMP can answer where WireGuard does not.
func probeHandshake(conf *WGConf, p PeerConf, ep netip.AddrPort, wait time.Duration) bool {
	c := *conf
	c.Peers = []PeerConf{p}
	dev := device.NewDevice(newSplitTun(conf.MTU), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if dev.IpcSet(c.UAPI([]netip.AddrPort{ep})) != nil || dev.Up() != nil {
		return false
	}
	key := hex.EncodeToString(p.PublicKey)
	for end := time.Now().Add(wait); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		ipc, _ := dev.IpcGet()
		if handshakenPeers(ipc)[key] {
			return true
		}
	}
	return false
}

// learn remembers an endpoint proven by a handshake, for this session and (per
// profile, outside the .conf) for the next ones.
func (e *Engine) learn(ep netip.AddrPort) {
	e.lrMu.Lock()
	if e.learned == nil {
		e.learned = map[netip.AddrPort]bool{}
	}
	known := e.learned[ep]
	e.learned[ep] = true
	e.lrMu.Unlock()
	if !known && e.profile != "" {
		if err := saveRoute(routesPath(), e.profile, ep); err != nil {
			e.logf("rota: não foi possível gravar o endpoint aprendido: %v", err)
		}
	}
}

func (e *Engine) learnedList() []netip.AddrPort {
	e.lrMu.Lock()
	defer e.lrMu.Unlock()
	out := make([]netip.AddrPort, 0, len(e.learned))
	for ep := range e.learned {
		out = append(out, ep)
	}
	return out
}

// gamePing is the median reply time through the tunnel to the game server
// (0 = not enough samples).
func (e *Engine) gamePing() time.Duration {
	e.pingMu.Lock()
	defer e.pingMu.Unlock()
	if ps := e.pings[pingIDGame]; ps != nil {
		return medianRTT(ps.rtts)
	}
	return 0
}

// nap sleeps d and reports false when the engine is stopping.
func (e *Engine) nap(d time.Duration) bool {
	select {
	case <-e.stop:
		return false
	case <-time.After(d):
		return true
	}
}

// routeLoop is the live route monitor (see routemon.go): it only acts while the
// game has traffic, spaces attempts out, and keeps a switch only if the game
// ping measured through the new path is better.
func (e *Engine) routeLoop() {
	tk := time.NewTicker(routeEvery)
	defer tk.Stop()
	var next time.Time
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
		}
		gs := e.gameServer()
		if e.closing.Load() {
			continue
		}
		if !gs.IsValid() {
			continue // no game traffic: nothing to compare (new endpoints: scanLoop)
		}
		if time.Now().Before(next) {
			continue
		}
		cur := e.eps()[0]
		curLeg, ok := legProbe(cur.Addr())
		if !ok {
			continue
		}
		legs := map[netip.AddrPort]time.Duration{}
		for _, a := range e.learnedList() {
			if a == cur || e.pathEndpointUsed(a) {
				continue
			}
			if leg, ok := legProbe(a.Addr()); ok {
				legs[a] = leg
			}
		}
		alt, found := pickRoute(curLeg, legs)
		if !found {
			continue
		}
		before := e.gamePing()
		e.routeLog("rota: testando %s (perna direta %v contra %v; ping do jogo atual %v)", alt, legs[alt], curLeg, before)
		if err := e.SetEndpoint(alt); err != nil {
			next = time.Now().Add(failCooldown)
			continue
		}
		e.pingMu.Lock()
		e.pings[pingIDGame] = &pingState{target: gs}
		e.pingMu.Unlock()
		select {
		case <-e.stop:
			return
		case <-time.After(routeSettle):
		}
		if e.gameServer() != gs { // pingLoop switched target: the RTTs are not comparable
			continue
		}
		after := e.gamePing()
		if keepRoute(before, after) {
			e.routeLog("rota: mantida %s — ping do jogo %v -> %v", alt, before, after)
			next = time.Now().Add(routeCooldown)
			continue
		}
		e.routeLog("rota: ping do jogo não melhorou (%v -> %v); voltando para %s", before, after, cur)
		_ = e.SetEndpoint(cur)
		next = time.Now().Add(failCooldown)
	}
}

// routeLog logs a route message and keeps it as the note shown on screen.
func (e *Engine) routeLog(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	e.routeNote.Store(&s)
	e.logf("%s", s)
}

// ---------------------------------------------------------------- traceroute

type traceAnswer struct {
	addr netip.Addr
	at   time.Time
}

func (e *Engine) kickTrace() {
	select {
	case e.traceKick <- struct{}{}:
	default:
	}
}

// traceHit records an answer to a tunnel probe of the current run.
func (e *Engine) traceHit(from netip.Addr, seq uint16) {
	e.traceMu.Lock()
	defer e.traceMu.Unlock()
	if run, _ := traceUnseq(seq); run != e.traceRun || e.traceGot == nil {
		return
	}
	if _, dup := e.traceGot[seq]; !dup {
		e.traceGot[seq] = traceAnswer{from, time.Now()}
	}
}

// traceTunnel sends TTL-limited echoes through the tunnel and collects who
// answered; hops that stay silent are left empty.
func (e *Engine) traceTunnel(dst netip.Addr) []Hop {
	src, ok := e.tunAddr(dst.Is6())
	if !ok {
		return nil
	}
	e.traceMu.Lock()
	e.traceRun++
	run := e.traceRun
	e.traceSent = map[uint16]time.Time{}
	e.traceGot = map[uint16]traceAnswer{}
	e.traceMu.Unlock()
	for ttl := 1; ttl <= maxTraceHops; ttl++ {
		seq := traceSeq(run, ttl)
		e.traceMu.Lock()
		e.traceSent[seq] = time.Now()
		e.traceMu.Unlock()
		e.tun.inject(buildICMPEchoTTL(src, dst, pingIDTrace, seq, uint8(ttl)))
	}
	for deadline := time.Now().Add(1500 * time.Millisecond); time.Now().Before(deadline) && !e.closing.Load(); time.Sleep(25 * time.Millisecond) {
		e.traceMu.Lock()
		reached := false
		for _, a := range e.traceGot {
			reached = reached || a.addr == dst
		}
		e.traceMu.Unlock()
		if reached {
			time.Sleep(150 * time.Millisecond) // nearer hops can arrive just after
			break
		}
	}
	e.traceMu.Lock()
	defer e.traceMu.Unlock()
	hops := make([]Hop, 0, maxTraceHops)
	for ttl := 1; ttl <= maxTraceHops; ttl++ {
		seq := traceSeq(run, ttl)
		h := Hop{TTL: ttl}
		if a, ok := e.traceGot[seq]; ok {
			h.Addr, h.RTT = a.addr, a.at.Sub(e.traceSent[seq])
		}
		hops = append(hops, h)
	}
	return trimHops(hops, dst)
}

// traceDirect probes the path from this PC to dst outside the tunnel, one
// TTL per goroutine so the whole trace takes about one timeout.
func (e *Engine) traceDirect(dst netip.Addr) []Hop {
	if !dst.Is4() {
		return nil
	}
	hops := make([]Hop, maxTraceHops)
	var wg sync.WaitGroup
	for i := range hops {
		hops[i] = Hop{TTL: i + 1}
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := newIcmpPinger()
			if err != nil {
				return
			}
			defer p.close()
			if from, rtt, ok := p.pingTTL(dst, uint8(i+1), 900*time.Millisecond); ok {
				hops[i].Addr, hops[i].RTT = from, rtt
			}
		}()
	}
	wg.Wait()
	return trimHops(hops, dst)
}

// pingTTL sends one echo with a limited TTL and returns who answered: a router
// (TTL expired in transit) or the destination.
func (p *icmpPinger) pingTTL(dst netip.Addr, ttl uint8, timeout time.Duration) (from netip.Addr, rtt time.Duration, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.h == 0 {
		return
	}
	a := dst.As4()
	ip := *(*uint32)(unsafe.Pointer(&a[0]))
	opt := struct { // IP_OPTION_INFORMATION
		Ttl, Tos, Flags, OptionsSize uint8
		_                            [4]byte
		OptionsData                  uintptr
	}{Ttl: ttl}
	data := []byte("aionwg")
	reply := make([]byte, 40+len(data)+8+64)
	r, _, _ := procIcmpSendEcho.Call(p.h, uintptr(ip), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		uintptr(unsafe.Pointer(&opt)), uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout.Milliseconds()))
	if r == 0 {
		return
	}
	const ipTTLExpiredTransit = 11013
	if status := *(*uint32)(unsafe.Pointer(&reply[4])); status != 0 && status != ipTTLExpiredTransit {
		return
	}
	rtt = time.Duration(*(*uint32)(unsafe.Pointer(&reply[8]))) * time.Millisecond
	if rtt == 0 {
		rtt = 500 * time.Microsecond
	}
	return netip.AddrFrom4([4]byte(reply[0:4])), rtt, true
}

// runTrace measures both segments of the route in use and publishes them.
func (e *Engine) runTrace() {
	ep := e.eps()[0].Addr()
	rt := RouteTrace{At: time.Now(), Endpoint: ep, Direct: e.traceDirect(ep)}
	rt.Dest = e.gameServer()
	rt.DestIsGame = rt.Dest.IsValid()
	if !rt.Dest.IsValid() {
		rt.Dest = e.gwTarget
	}
	if rt.Dest.IsValid() {
		rt.Tunnel = e.traceTunnel(rt.Dest)
	}
	e.trace.Store(&rt)
}

// traceLoop refreshes the route view shortly after connecting, every 45 s and
// whenever the endpoint changes.
func (e *Engine) traceLoop() {
	tk := time.NewTicker(45 * time.Second)
	defer tk.Stop()
	first := time.After(4 * time.Second)
	for {
		select {
		case <-e.stop:
			return
		case <-first:
			first = nil // a nil channel never fires again
		case <-tk.C:
		case <-e.traceKick:
		}
		if e.closing.Load() {
			return
		}
		e.runTrace()
	}
}

// pingMs is the last reply in whole milliseconds, 0 when the probe is failing.
func pingMs(p PingResult) int {
	if !p.OK {
		return 0
	}
	return max(1, int(p.RTT.Milliseconds()))
}

// discoverIdle looks for an endpoint faster than the current one while the game
// has no traffic, so the throwaway handshake cannot disturb a match. It tries
// at most one candidate per call and remembers the result (learned or failed).
func (e *Engine) discoverIdle() {
	cur := e.eps()[0]
	if !cur.Addr().Is4() || len(e.conf.Peers) == 0 {
		return
	}
	p := e.conf.Peers[0]
	host, _, _ := net.SplitHostPort(p.Endpoint)
	skip := loadBad(routesPath(), e.profile, time.Now())
	for _, l := range e.learnedList() {
		skip[l.Addr()] = true
	}
	for _, path := range e.paths {
		if path != nil {
			skip[path.currentEndpoint().Addr()] = true
		}
	}
	known := endpointCandidates(cur, host, lookupIPv4)
	seen := map[netip.Addr]bool{}
	for _, a := range known {
		seen[a] = true
	}
	for _, a := range warpSeeds(cur.Addr()) {
		if !seen[a] {
			known = append(known, a)
		}
	}
	cands := dropAddrs(known, skip)
	if len(cands) < 2 {
		return
	}
	curRTT, ranked := rankEndpoints(cur, cands, icmpOnce, icmpMedian)
	if curRTT == 0 || len(ranked) == 0 || e.gameServer().IsValid() {
		return // nothing faster, or the game started meanwhile
	}
	r := ranked[0]
	if probeHandshake(e.conf, p, r.AddrPort, 2*time.Second) {
		e.learn(r.AddrPort)
		e.routeLog("rota: novo endpoint aprendido %s (perna direta %v contra %v); o monitor passa a considerá-lo", r.Addr(), r.RTT, curRTT)
		return
	}
	_ = saveBad(routesPath(), e.profile, r.AddrPort, time.Now())
	e.routeLog("rota: %s (%v) respondeu a ICMP mas não ao WireGuard; descartado por 7 dias", r.Addr(), r.RTT)
}
