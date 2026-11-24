//go:build windows

package app

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type pinglessPath struct {
	id     uint16
	exit   int
	route  PinglessRoute
	via    netip.AddrPort
	conn   *net.UDPConn
	stats  RouteStats
	mu     sync.Mutex
}

type pinglessExitState struct {
	name    string
	session uint64
	cipher  *PacketCipher
	paths   []uint16
	active  []uint16
	mu      sync.Mutex
}

type pinglessFlow struct {
	id         uint32
	clientAddr netip.AddrPort
	remoteAddr netip.AddrPort
	exitIdx    int
	txSeq      uint64
	rxWindow   PinglessSeqWindow
	lastActive time.Time
	packetsUp  uint64
	packetsDn  uint64
	ifIdx      uint32
	subIfIdx   uint32
}

// PinglessEngine implements TunnelEngine for Pingless relays.
type PinglessEngine struct {
	cfg       *PinglessConfig
	h         divertHandle
	owner     *ownerTracker
	mirror    *mirror
	meterMu   sync.Mutex
	meter     *meterAdapter
	meterErr  string
	logf      func(string, ...any)

	exits     []*pinglessExitState
	paths     []*pinglessPath

	flowsMu   sync.Mutex
	flows     map[netip.AddrPort]*pinglessFlow // keyed by clientAddr (game local port)
	flowsByID map[uint32]*pinglessFlow
	nextFlow  uint32

	up, down         atomic.Uint64
	gameUp, gameDown atomic.Uint64
	cCaptured        atomic.Uint64
	cInjected        atomic.Uint64
	cInjectErr       atomic.Uint64

	closing atomic.Bool
	stop    chan struct{}
	wg      sync.WaitGroup

	probeSeq atomic.Uint32
	started  time.Time
}

func StartPinglessEngine(cfg *PinglessConfig, opt EngineOptions, logf func(string, ...any)) (*PinglessEngine, error) {
	keys := NewPinglessSessionKeys(cfg.PSK)

	pe := &PinglessEngine{
		cfg:       cfg,
		logf:      logf,
		flows:     make(map[netip.AddrPort]*pinglessFlow),
		flowsByID: make(map[uint32]*pinglessFlow),
		stop:      make(chan struct{}),
		started:   time.Now(),
	}

	for exitIdx, eSpec := range cfg.Exits {
		var sessBytes [8]byte
		_, _ = rand.Read(sessBytes[:])
		sessionID := binary.LittleEndian.Uint64(sessBytes[:])
		cipher, err := keys.Session(sessionID, false)
		if err != nil {
			pe.Close()
			return nil, fmt.Errorf("iniciando cifra Pingless para exit %s: %w", eSpec.Name, err)
		}

		exitState := &pinglessExitState{
			name:    eSpec.Name,
			session: sessionID,
			cipher:  cipher,
		}

		for _, rSpec := range eSpec.Routes {
			viaAP, err := ResolveEndpoint(rSpec.Via)
			if err != nil {
				pe.Close()
				return nil, fmt.Errorf("resolvendo rota %s (%s): %w", rSpec.Name, rSpec.Via, err)
			}

			var laddr *net.UDPAddr
			if rSpec.Bind != "" {
				if bIP, err := netip.ParseAddr(rSpec.Bind); err == nil {
					laddr = &net.UDPAddr{IP: bIP.AsSlice(), Port: 0}
				}
			}

			conn, err := net.ListenUDP("udp", laddr)
			if err != nil {
				pe.Close()
				return nil, fmt.Errorf("abrindo socket para rota %s: %w", rSpec.Name, err)
			}
			_ = conn.SetReadBuffer(1 << 20)
			_ = conn.SetWriteBuffer(1 << 20)

			pathID := uint16(len(pe.paths))
			path := &pinglessPath{
				id:    pathID,
				exit:  exitIdx,
				route: rSpec,
				via:   viaAP,
				conn:  conn,
			}
			pe.paths = append(pe.paths, path)
			exitState.paths = append(exitState.paths, pathID)
			logf("Pingless rota %d (%s) -> exit %s via %s", pathID, rSpec.Name, eSpec.Name, viaAP)
		}
		pe.exits = append(pe.exits, exitState)
	}

	// Capture filter for games: only outbound UDP packets not destined to the relay sockets
	base := "outbound and not loopback and udp"
	filter := base
	for _, p := range pe.paths {
		ipf := "ip.DstAddr"
		if p.via.Addr().Is6() {
			ipf = "ipv6.DstAddr"
		}
		filter += fmt.Sprintf(" and not (udp.DstPort == %d and %s == %s)", p.via.Port(), ipf, p.via.Addr())
	}

	h, err := divertOpen(filter, divertLayerNetwork, 0, 0)
	if err != nil && filter != base {
		logf("aviso Pingless: %v — usando filtro simples", err)
		h, err = divertOpen(base, divertLayerNetwork, 0, 0)
	}
	if err != nil {
		pe.Close()
		return nil, err
	}
	pe.h = h
	h.setParam(0, 16384)
	h.setParam(1, 2000)
	h.setParam(2, 33554432)

	pe.owner = newOwnerTracker(opt.Processes)
	pe.mirror = newMirror(opt.Mirror, logf)
	if opt.Mirror {
		pe.openMeter()
	}

	// Start receive loops for each route path
	for _, path := range pe.paths {
		pe.wg.Add(1)
		go pe.recvLoop(path)
	}

	// Start probe & route reselection loop
	pe.wg.Add(1)
	go pe.probeLoop()

	// Start WinDivert outbound capture loop
	pe.wg.Add(1)
	go pe.captureLoop()

	return pe, nil
}

func (pe *PinglessEngine) captureLoop() {
	defer pe.wg.Done()
	buf := make([]byte, 65535)
	var addr divertAddress
	sealBuf := make([]byte, HeaderLen, 2048)

	for {
		if pe.closing.Load() {
			return
		}
		n, err := pe.h.recv(buf, &addr)
		if err != nil {
			if pe.closing.Load() {
				return
			}
			continue
		}
		pkt := buf[:n]
		info, ok := parsePacket(pkt)
		if !ok || info.proto != protoUDP {
			pe.h.send(pkt, &addr)
			continue
		}

		// Check if process is targeted
		class := pe.owner.Class(protoUDP, info.srcPort)
		if class == classNone {
			pe.h.send(pkt, &addr)
			continue
		}
		clientAP := netip.AddrPortFrom(info.src, info.srcPort)
		remoteAP := netip.AddrPortFrom(info.dst, info.dstPort)
		payload := pkt[info.l4+8:]

		pe.cCaptured.Add(1)
		pe.up.Add(uint64(len(payload)))
		pe.gameUp.Add(uint64(len(payload)))

		// Get or create flow
		pe.flowsMu.Lock()
		flow, exists := pe.flows[clientAP]
		if !exists {
			pe.nextFlow++
			flowID := pe.nextFlow
			exitIdx := pe.bestExit()
			flow = &pinglessFlow{
				id:         flowID,
				clientAddr: clientAP,
				remoteAddr: remoteAP,
				exitIdx:    exitIdx,
				lastActive: time.Now(),
				ifIdx:      addr.IfIdx,
				subIfIdx:   addr.SubIfIdx,
			}
			pe.flows[clientAP] = flow
			pe.flowsByID[flowID] = flow
			pe.logf("Pingless: novo fluxo %d %s -> %s (exit %s)", flowID, clientAP, remoteAP, pe.exits[exitIdx].name)
		}
		flow.lastActive = time.Now()
		flow.packetsUp++
		flow.txSeq++
		seq := flow.txSeq
		flowID := flow.id
		exitIdx := flow.exitIdx
		pe.flowsMu.Unlock()

		exit := pe.exits[exitIdx]
		dataBody := &DataBody{
			Flow:    flowID,
			Seq:     seq,
			Peer:    remoteAP,
			Payload: payload,
		}

		sealed, err := exit.cipher.SealData(dataBody, sealBuf)
		if err != nil {
			continue
		}

		// Send over active routes (multipath redundancy)
		exit.mu.Lock()
		active := exit.active
		if len(active) == 0 {
			active = exit.paths
		}
		targets := append([]uint16(nil), active...)
		exit.mu.Unlock()

		for _, pid := range targets {
			p := pe.paths[pid]
			rAddr := &net.UDPAddr{IP: p.via.Addr().AsSlice(), Port: int(p.via.Port())}
			if _, err := p.conn.WriteTo(sealed, rAddr); err == nil {
				p.mu.Lock()
				p.stats.bytesUp += uint64(len(sealed))
				p.mu.Unlock()
			}
		}
	}
}

func (pe *PinglessEngine) recvLoop(p *pinglessPath) {
	defer pe.wg.Done()
	buf := make([]byte, MaxDatagramSize)
	exit := pe.exits[p.exit]

	for {
		if pe.closing.Load() {
			return
		}
		n, from, err := p.conn.ReadFrom(buf)
		if err != nil {
			if pe.closing.Load() {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		udpFrom, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		fromAddr, _ := netip.AddrFromSlice(udpFrom.IP)
		fromAP := netip.AddrPortFrom(fromAddr.Unmap(), uint16(udpFrom.Port))
		if fromAP != p.via {
			continue
		}

		hdr, kind, body, err := exit.cipher.Open(buf[:n])
		if err != nil {
			continue
		}
		_ = hdr
		now := time.Now()

		switch kind {
		case KindPong:
			if pong, err := DecodePingBody(body); err == nil && pong.Path == p.id {
				p.mu.Lock()
				p.stats.OnPong(pong.Probe, now)
				p.mu.Unlock()
			}
		case KindData:
			if len(body) < DataFixedLen+7 {
				continue
			}
			flowID := binary.LittleEndian.Uint32(body[0:4])
			seq := binary.LittleEndian.Uint64(body[4:12])
			peerAP, used, err := DecodeAddr(body[12:])
			if err != nil {
				continue
			}
			payload := body[12+used:]

			p.mu.Lock()
			p.stats.bytesDown += uint64(n)
			p.mu.Unlock()

			pe.flowsMu.Lock()
			flow, ok := pe.flowsByID[flowID]
			if !ok {
				pe.flowsMu.Unlock()
				continue
			}
			if !flow.rxWindow.Accept(seq) {
				// duplicate or late packet dropped
				pe.flowsMu.Unlock()
				continue
			}
			flow.packetsDn++
			flow.lastActive = now
			clientAP := flow.clientAddr
			ifIdx := flow.ifIdx
			subIfIdx := flow.subIfIdx
			pe.flowsMu.Unlock()

			// Forge inbound UDP packet from peer (game server) to clientAP (local game socket)
			inboundPkt, _ := BuildInboundUDPPacket(peerAP, clientAP, payload)
			if pe.injectInbound(inboundPkt, clientAP.Addr().Is6(), ifIdx, subIfIdx) {
				pe.cInjected.Add(1)
				pe.down.Add(uint64(len(payload)))
				pe.gameDown.Add(uint64(len(payload)))
			} else {
				pe.cInjectErr.Add(1)
			}
		}
	}
}

func (pe *PinglessEngine) injectInbound(pkt []byte, v6 bool, ifIdx, subIfIdx uint32) bool {
	var a divertAddress
	a.SetOutbound(false)
	a.SetIPv6(v6)
	a.IfIdx = ifIdx
	a.SubIfIdx = subIfIdx
	if err := pe.h.send(pkt, &a); err != nil {
		return false
	}
	return true
}

func (pe *PinglessEngine) probeLoop() {
	defer pe.wg.Done()
	interval := time.Duration(pe.cfg.ProbeIntervalMS) * time.Millisecond
	if interval < 20*time.Millisecond {
		interval = DefaultProbeInterval
	}
	tk := time.NewTicker(interval)
	defer tk.Stop()
	sealBuf := make([]byte, HeaderLen, 64)

	for {
		select {
		case <-pe.stop:
			return
		case <-tk.C:
		}
		now := time.Now()
		sentUS := uint64(now.Sub(pe.started).Microseconds())

		for _, p := range pe.paths {
			exit := pe.exits[p.exit]
			probe := pe.probeSeq.Add(1)
			body := PingBody{
				Path:   p.id,
				Probe:  probe,
				SentUS: sentUS,
			}
			sealed, err := exit.cipher.SealPing(body, sealBuf)
			if err != nil {
				continue
			}
			p.mu.Lock()
			p.stats.OnProbeSent(probe, now)
			rAddr := &net.UDPAddr{IP: p.via.Addr().AsSlice(), Port: int(p.via.Port())}
			if _, err := p.conn.WriteTo(sealed, rAddr); err != nil {
				p.stats.OnProbeSendFailed(probe)
			}
			p.mu.Unlock()
		}

		for _, exit := range pe.exits {
			pe.reselectExit(exit, now)
		}
		pe.sweepFlows(now)
	}
}

func (pe *PinglessEngine) reselectExit(exit *pinglessExitState, now time.Time) {
	scores := make(map[uint16]float64)
	for _, pid := range exit.paths {
		p := pe.paths[pid]
		p.mu.Lock()
		if s, ok := p.stats.Score(now); ok {
			scores[pid] = s
		}
		p.mu.Unlock()
	}

	exit.mu.Lock()
	next := ReselectRoutes(scores, exit.active, pe.cfg.Multipath, pe.cfg.SwitchMarginMS)
	changed := len(next) != len(exit.active)
	if !changed {
		for i := range next {
			if next[i] != exit.active[i] {
				changed = true
				break
			}
		}
	}
	if changed {
		exit.active = next
		var names []string
		for _, pid := range next {
			names = append(names, pe.paths[pid].route.Name)
		}
		pe.logf("Pingless: exit %s rotas ativas: %v", exit.name, names)
	}
	exit.mu.Unlock()
}

func (pe *PinglessEngine) sweepFlows(now time.Time) {
	idle := time.Duration(pe.cfg.FlowIdleSecs) * time.Second
	var closed []struct {
		exitIdx int
		flowID  uint32
	}

	pe.flowsMu.Lock()
	for k, f := range pe.flows {
		if now.Sub(f.lastActive) > idle {
			delete(pe.flows, k)
			delete(pe.flowsByID, f.id)
			closed = append(closed, struct {
				exitIdx int
				flowID  uint32
			}{f.exitIdx, f.id})
		}
	}
	pe.flowsMu.Unlock()

	sealBuf := make([]byte, HeaderLen, 64)
	for _, c := range closed {
		exit := pe.exits[c.exitIdx]
		sealed, err := exit.cipher.SealClose(c.flowID, sealBuf)
		if err != nil {
			continue
		}
		exit.mu.Lock()
		active := exit.active
		if len(active) == 0 {
			active = exit.paths
		}
		exit.mu.Unlock()

		for _, pid := range active {
			p := pe.paths[pid]
			rAddr := &net.UDPAddr{IP: p.via.Addr().AsSlice(), Port: int(p.via.Port())}
			_, _ = p.conn.WriteTo(sealed, rAddr)
		}
	}
}

func (pe *PinglessEngine) bestExit() int {
	now := time.Now()
	bestIdx := 0
	bestScore := math.MaxFloat64
	for i, e := range pe.exits {
		for _, pid := range e.paths {
			p := pe.paths[pid]
			p.mu.Lock()
			if s, ok := p.stats.Score(now); ok && s < bestScore {
				bestScore = s
				bestIdx = i
			}
			p.mu.Unlock()
		}
	}
	return bestIdx
}

// ---------------------------------------------------------------- TunnelEngine methods

func (pe *PinglessEngine) Stats() Stats {
	s := Stats{
		Up:       pe.up.Load(),
		Down:     pe.down.Load(),
		GameUp:   pe.gameUp.Load(),
		GameDown: pe.gameDown.Load(),
		Procs:    pe.owner.Processes(),
	}
	if len(pe.paths) > 0 {
		s.Endpoint = fmt.Sprintf("Pingless (%d rotas)", len(pe.paths))
	}
	s.TunnelAddr = "Pingless Relay"
	s.Diag = Diag{
		Captured:  pe.cCaptured.Load(),
		Injected:  pe.cInjected.Load(),
		InjectErr: pe.cInjectErr.Load(),
	}
	sort.Slice(s.Procs, func(i, j int) bool { return s.Procs[i].PID < s.Procs[j].PID })

	pe.flowsMu.Lock()
	s.Flows = len(pe.flows)
	s.GameFlows = len(pe.flows)
	pe.flowsMu.Unlock()

	// Calculate best ping across routes for TUI display
	now := time.Now()
	bestRTT := 0.0
	found := false
	for _, p := range pe.paths {
		p.mu.Lock()
		if p.stats.Alive(now) && p.stats.srtt != nil {
			if !found || *p.stats.srtt < bestRTT {
				bestRTT = *p.stats.srtt
				found = true
			}
		}
		p.mu.Unlock()
	}
	if found {
		s.PingEndpoint = PingResult{
			Target: "relay",
			RTT:    time.Duration(bestRTT * float64(time.Millisecond)),
			OK:     true,
		}
		s.PingGame = s.PingEndpoint
	}

	pe.meterMu.Lock()
	if pe.meter != nil {
		s.MeterAdapter = fmt.Sprintf("%s (%d pacotes)", meterAdapterName, pe.meter.written.Load())
	} else {
		s.MeterAdapter = pe.meterErr
	}
	s.MeterOK = pe.meter != nil
	pe.meterMu.Unlock()

	return s
}

func (pe *PinglessEngine) SetProcesses(names []string) { pe.owner.SetNames(names) }
func (pe *PinglessEngine) SetProcessRules(rules []ProcessRule, names []string) {
	pe.owner.SetRules(rules, names)
}
func (pe *PinglessEngine) SetMirror(on bool) {
	pe.mirror.SetEnabled(on)
	if on {
		pe.openMeter()
	}
}
func (pe *PinglessEngine) SetUDPDuplicate(on bool)             {}
func (pe *PinglessEngine) SetUDPRatio(originals, copies int)   {}
func (pe *PinglessEngine) SetUDPForce(on bool)                 {}
func (pe *PinglessEngine) SetUDPNewestOut(on bool)             {}
func (pe *PinglessEngine) SetUDPNewestIn(on bool)              {}
func (pe *PinglessEngine) SetFullTunnel(on bool)               {} // Pingless is game-selective UDP
func (pe *PinglessEngine) SetNoDNS(off bool)                   {}
func (pe *PinglessEngine) SetWFP(on bool)                      {}
func (pe *PinglessEngine) SetWFPApps(names []string)           {}
func (pe *PinglessEngine) SetEndpoint(ep netip.AddrPort) error { return nil }
func (pe *PinglessEngine) SetEndpointString(v string) error    { return nil }
func (pe *PinglessEngine) WGConf() *WGConf                     { return nil }
func (pe *PinglessEngine) EndpointRows() []endpointRow         { return nil }
func (pe *PinglessEngine) EndpointCandidates(existingRows []endpointRow) []netip.AddrPort {
	var eps []netip.AddrPort
	for _, p := range pe.paths {
		eps = append(eps, p.via)
	}
	return eps
}
func (pe *PinglessEngine) ObservedRemotes() []netip.Addr {
	pe.flowsMu.Lock()
	defer pe.flowsMu.Unlock()
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, f := range pe.flows {
		a := f.remoteAddr.Addr()
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}
func (pe *PinglessEngine) EndpointAddrs() []netip.Addr {
	var out []netip.Addr
	for _, p := range pe.paths {
		out = append(out, p.via.Addr())
	}
	return out
}

func (pe *PinglessEngine) openMeter() {
	pe.meterMu.Lock()
	defer pe.meterMu.Unlock()
	if pe.meter != nil {
		return
	}
	m, err := openMeterAdapter()
	if err != nil {
		pe.meterErr = err.Error()
		pe.logf("adaptador do meter: %v", err)
		return
	}
	pe.meter, pe.meterErr = m, ""
	pe.logf("adaptador %s pronto", meterAdapterName)
}

func (pe *PinglessEngine) Close() {
	if !pe.closing.CompareAndSwap(false, true) {
		return
	}
	close(pe.stop)
	if pe.h != 0 {
		pe.h.shutdown()
	}
	for _, p := range pe.paths {
		_ = p.conn.Close()
	}
	pe.wg.Wait()
	if pe.h != 0 {
		pe.h.close()
	}
	if pe.owner != nil {
		pe.owner.Close()
	}
	if pe.mirror != nil {
		pe.mirror.Close()
	}
	pe.meterMu.Lock()
	if pe.meter != nil {
		pe.meter.Close()
		pe.meter = nil
	}
	pe.meterMu.Unlock()
}
