//go:build windows

package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var program *tea.Program

// Bubble Tea's Program.Send may block until Update consumes the message.
// Never call it synchronously from an Engine callback invoked by Update
// (notably the Mirror toggle), or the UI can deadlock itself.
var programLogs = make(chan logMsg, 256)

func queueProgramLog(msg logMsg) {
	enqueueProgramLog(programLogs, msg)
}

func enqueueProgramLog(queue chan<- logMsg, msg logMsg) {
	select {
	case queue <- msg:
	default: // bounded: drop diagnostic logs rather than freeze packet/UI threads
	}
}

// ---------------------------------------------------------------- styles

var (
	cAccent  = lipgloss.Color("#B48CFF")
	cGreen   = lipgloss.Color("#5FD787")
	cYellow  = lipgloss.Color("#FFD75F")
	cRed     = lipgloss.Color("#FF5F5F")
	cDim     = lipgloss.Color("#7A7A8C")
	cUp      = lipgloss.Color("#FF9F5F")
	cDown    = lipgloss.Color("#5FAFFF")
	cShimmer = lipgloss.Color("#FFFFFF")

	sTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(cAccent).Padding(0, 1)
	sBox   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cAccent).Padding(0, 1)
	sLabel = lipgloss.NewStyle().Foreground(cDim)
	sBold  = lipgloss.NewStyle().Bold(true)
	sDim   = lipgloss.NewStyle().Foreground(cDim)
	sSel   = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	sKey   = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
)

// ---------------------------------------------------------------- model

type mode int

const (
	modeNormal mode = iota
	modeImport
	modeProcs
	modePing
	modeUDPCopies
	modeDelete
	modeWFPApps
	modeEndpoint
)

type (
	tickMsg      time.Time
	animMsg      struct{}
	logMsg       string
	connectedMsg struct {
		eng  *Engine
		name string
		err  error
	}
	testMsg     TestResult
	testDoneMsg struct{}
)

type model struct {
	frame    int // animation frame, advances every animTick
	settings Settings
	configs  []string
	cursor   int
	mode     mode
	input    textinput.Model

	eng        *Engine
	engName    string
	connecting bool
	since      time.Time

	stats    Stats
	prev     Stats
	prevAt   time.Time
	upRate   float64 // bytes/s, everything in the tunnel (inner)
	downRate float64
	gUpRate  float64 // bytes/s, game only
	gDnRate  float64
	wgRxRate float64
	wgTxRate float64
	histUp   []float64
	histDown []float64
	histPing []float64

	logs []string

	running   []string // executables seen by the last scan, while the WFP picker is open
	appCursor int

	showDiag bool
	prevDiag Diag
	diagRate Diag // per second
	testing  bool
	tests    []TestResult
	width    int
	height   int
}

func newModel() model {
	ti := textinput.New()
	ti.CharLimit = 1024
	ti.Width = 60
	m := model{settings: loadSettings(), input: ti}
	m.configs = listConfigs()
	for i, c := range m.configs {
		if c == m.settings.LastConfig {
			m.cursor = i
		}
	}
	m.log("AionWG pronto. Processos-alvo: %s", strings.Join(m.settings.Processes, ", "))
	if len(m.configs) == 0 {
		m.log("Nenhuma config ainda — pressione [i] para importar um .conf do WireGuard")
	}
	return m
}

// log shows a UI line and records it in the file log.
func (m *model) log(f string, a ...any) {
	diskLog.Printf(f, a...)
	m.show(f, a...)
}

// show only puts a line on screen. Engine lines are already in the file log by
// the time they get here (connectCmd writes them before the lossy screen queue),
// so logging them again would duplicate them.
func (m *model) show(f string, a ...any) {
	m.logs = append(m.logs, time.Now().Format("15:04:05 ")+fmt.Sprintf(f, a...))
	if len(m.logs) > 200 {
		m.logs = m.logs[len(m.logs)-200:]
	}
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// animTick drives chart shimmer; faster than the 1s data tick.
func animTick() tea.Cmd {
	return tea.Tick(150*time.Millisecond, func(time.Time) tea.Msg { return animMsg{} })
}

func (m model) Init() tea.Cmd { return tea.Batch(tick(), animTick(), textinput.Blink) }

func connectCmd(name string, s Settings) tea.Cmd {
	return func() tea.Msg {
		conf, err := readConfig(name)
		if err != nil {
			return connectedMsg{err: err}
		}
		var mirrorPaths []string
		if exe, err := os.Executable(); err == nil {
			mirrorPaths = append(mirrorPaths, filepath.Join(filepath.Dir(exe), "configs-wireguard-oficial", name))
		}
		eng, err := StartEngine(conf, EngineOptions{
			Processes: s.Processes, PingTarget: s.PingTarget, Mirror: s.Mirror,
			UDPDuplicate: s.UDPDuplicate, UDPOriginals: s.UDPOriginals, UDPCopies: s.UDPCopies, UDPForce: s.UDPForce,
			UDPNewestOut: s.UDPNewestOut, UDPNewestIn: s.UDPNewestIn,
			FullTunnel: s.FullTunnel, NoDNS: s.NoDNS,
			WFP: s.WFP, WFPApps: s.WFPApps, BestEndpoint: s.BestEndpoint,
			ConfigPath:  filepath.Join(configDir(), name),
			ConfigPaths: mirrorPaths,
		}, func(f string, a ...any) {
			line := fmt.Sprintf(f, a...)
			diskLog.Printf("%s", line)
			queueProgramLog(logMsg(line))
		})
		return connectedMsg{eng: eng, name: name, err: err}
	}
}

func pushHist(h []float64, v float64) []float64 {
	h = append(h, v)
	if len(h) > 60 {
		h = h[len(h)-60:]
	}
	return h
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case animMsg:
		m.frame++
		return m, animTick()

	case tickMsg:
		if m.eng != nil {
			now := time.Now()
			s := m.eng.Stats()
			if !m.prevAt.IsZero() {
				dt := now.Sub(m.prevAt).Seconds()
				if dt > 0 {
					m.upRate = float64(s.Up-m.prev.Up) / dt
					m.downRate = float64(s.Down-m.prev.Down) / dt
					m.gUpRate = float64(s.GameUp-m.prev.GameUp) / dt
					m.gDnRate = float64(s.GameDown-m.prev.GameDown) / dt
					m.wgTxRate = float64(s.WGTx-m.prev.WGTx) / dt
					m.wgRxRate = float64(s.WGRx-m.prev.WGRx) / dt
				}
			}
			d, pd := s.Diag, m.prevDiag
			m.diagRate = Diag{
				Captured: d.Captured - pd.Captured, Injected: d.Injected - pd.Injected,
				InNoNAT: d.InNoNAT - pd.InNoNAT, InjectErr: d.InjectErr - pd.InjectErr,
				TunDrop: d.TunDrop - pd.TunDrop, Segmented: d.Segmented - pd.Segmented,
				ICMPErr: d.ICMPErr - pd.ICMPErr, DNSQ: d.DNSQ - pd.DNSQ, DNSA: d.DNSA - pd.DNSA,
				TableDumps: d.TableDumps - pd.TableDumps, V6Blocked: d.V6Blocked - pd.V6Blocked,
			}
			m.prevDiag = d
			m.prev, m.prevAt, m.stats = s, now, s
			m.histUp = pushHist(m.histUp, m.upRate)
			m.histDown = pushHist(m.histDown, m.downRate)
			p := bestPing(s)
			if p.OK {
				m.histPing = pushHist(m.histPing, float64(p.RTT.Microseconds())/1000)
			} else {
				m.histPing = pushHist(m.histPing, 0)
			}
		}
		if m.mode == modeWFPApps {
			m.running = ListAllProcesses() // only while the picker is open
			m.appCursor = clampCursor(m.appCursor, len(m.pickerList()))
		}
		return m, tick()

	case testMsg:
		r := TestResult(msg)
		m.tests = append(m.tests, r)
		st := "OK"
		if !r.OK {
			st = "ERRO"
		}
		m.log("Teste %s: %s — %s (%d ms)", r.Name, st, r.Detail, r.Dur.Milliseconds())
		return m, nil

	case testDoneMsg:
		m.testing = false
		m.log("Autoteste concluído")
		return m, nil

	case logMsg:
		m.show("%s", string(msg)) // already in the file log (see connectCmd)
		return m, nil

	case connectedMsg:
		m.connecting = false
		if msg.err != nil {
			m.log("ERRO ao conectar: %v", msg.err)
			return m, nil
		}
		m.eng, m.engName, m.since = msg.eng, msg.name, time.Now()
		m.prevAt, m.histUp, m.histDown, m.histPing = time.Time{}, nil, nil, nil
		m.settings.LastConfig = msg.name
		_ = saveSettings(m.settings)
		m.log("Conectado com %s — só o tráfego do AION 2 passa pelo túnel", msg.name)
		return m, nil

	case tea.KeyMsg:
		if m.mode != modeNormal {
			return m.updateInput(msg)
		}
		switch msg.String() {
		case "ctrl+c", "q":
			if m.eng != nil {
				m.eng.Close()
			}
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.configs)-1 {
				m.cursor++
			}
		case "enter", "c":
			if m.connecting {
				return m, nil
			}
			if m.eng != nil {
				m.eng.Close()
				m.eng = nil
				m.log("Desconectado")
				return m, nil
			}
			if len(m.configs) == 0 {
				m.log("Importe uma config primeiro ([i])")
				return m, nil
			}
			m.connecting = true
			name := m.configs[m.cursor]
			m.log("Conectando com %s…", name)
			return m, connectCmd(name, m.settings)
		case "i":
			m.mode = modeImport
			m.input.SetValue("")
			m.input.Placeholder = `C:\Users\voce\Downloads\vps.conf  (pode arrastar o arquivo para cá)`
			m.input.Focus()
		case "p":
			m.mode = modeProcs
			m.input.SetValue(strings.Join(m.settings.Processes, ", "))
			m.input.Placeholder = "Aion2.exe, Aion2-Win64-Shipping.exe"
			m.input.Focus()
		case "t":
			m.mode = modePing
			m.input.SetValue(m.settings.PingTarget)
			m.input.Placeholder = "vazio = automático (gateway do túnel)"
			m.input.Focus()
		case "v":
			if m.eng == nil {
				m.log("Conecte primeiro: [v] troca o endpoint do túnel em andamento")
				return m, nil
			}
			m.mode = modeEndpoint
			m.input.SetValue("")
			m.input.Placeholder = "IP ou IP:porta (só nesta sessão; o .conf não muda)"
			m.input.Focus()
		case "s":
			m.settings.FullTunnel = !m.settings.FullTunnel
			_ = saveSettings(m.settings)
			if m.eng != nil {
				m.eng.SetFullTunnel(m.settings.FullTunnel)
			}
			if m.settings.FullTunnel {
				m.log("Modo SISTEMA INTEIRO: todo o tráfego do PC passa pelo túnel (rede local continua direta)")
			} else {
				m.log("Modo SÓ JOGO: apenas os processos da lista [p] passam pelo túnel")
			}
			if m.eng != nil {
				m.log("Conexões já abertas podem cair uma vez e reconectar — é normal")
			}
		case "n":
			m.settings.NoDNS = !m.settings.NoDNS
			_ = saveSettings(m.settings)
			if m.eng != nil {
				m.eng.SetNoDNS(m.settings.NoDNS)
			}
			if m.settings.NoDNS {
				m.log("DNS pelo túnel DESLIGADO (sistema inteiro usa o DNS normal do Windows)")
			} else {
				m.log("DNS pelo túnel LIGADO (sistema inteiro usa o DNS da config)")
			}
		case "b":
			m.settings.BestEndpoint = !m.settings.BestEndpoint
			_ = saveSettings(m.settings)
			if m.settings.BestEndpoint {
				m.log("Melhor endpoint LIGADO — vale na próxima conexão (descobre e mede endpoints por ICMP, confirma por handshake)")
			} else {
				m.log("Melhor endpoint DESLIGADO — vale na próxima conexão (usa o endpoint da config)")
			}
		case "g":
			m.showDiag = !m.showDiag
		case "e":
			if len(m.configs) == 0 {
				return m, nil
			}
			name := m.configs[m.cursor]
			var obs, eps []netip.Addr
			if m.eng != nil && name == m.engName {
				obs, eps = m.eng.ObservedRemotes(), m.eng.EndpointAddrs()
			} else if c, err := readConfig(name); err == nil {
				for _, p := range c.Peers {
					if ap, err := ResolveEndpoint(p.Endpoint); err == nil {
						eps = append(eps, ap.Addr())
					}
				}
			}
			dir, n, err := exportOfficial(name, obs, eps)
			if err != nil {
				m.log("ERRO ao exportar: %v", err)
			} else {
				m.log("Configs p/ WireGuard oficial salvas em %s (-sistema.conf e -jogo.conf, %d IPs do jogo/Steam incluídos)", dir, n)
				if n == 0 {
					m.log("Dica: conecte, jogue um pouco e aperte [e] de novo para incluir os IPs reais dos servidores")
				}
			}
		case "x":
			if m.eng == nil {
				m.log("Conecte primeiro para rodar o autoteste")
				return m, nil
			}
			if m.testing {
				return m, nil
			}
			m.testing, m.tests = true, nil
			m.log("Autoteste iniciado…")
			dns, vpn := "", ""
			if c, err := readConfig(m.engName); err == nil {
				if d, ok := c.DNSFor(false); ok {
					dns = d.String()
				}
			}
			if ep := m.stats.Endpoint; ep != "" {
				if h, _, err := net.SplitHostPort(ep); err == nil {
					vpn = h
				}
			}
			return m, func() tea.Msg {
				runSelfTest(dns, vpn, func(r TestResult) { program.Send(testMsg(r)) })
				return testDoneMsg{}
			}
		case "u":
			m.settings.UDPDuplicate = !m.settings.UDPDuplicate
			_ = saveSettings(m.settings)
			if m.eng != nil {
				m.eng.SetUDPDuplicate(m.settings.UDPDuplicate)
			}
			if m.settings.UDPDuplicate {
				m.log("UDP %s LIGADO: original e copias pelo tunel WireGuard; nao garante ping menor.", udpRatioLabel(m.settings.UDPOriginals, m.settings.UDPCopies))
			} else {
				m.log("UDP DESLIGADO: sem copias extras")
			}
		case "r":
			m.mode = modeUDPCopies
			m.input.SetValue(udpRatioLabel(m.settings.UDPOriginals, m.settings.UDPCopies))
			m.input.Placeholder = "B (1:B) ou A:B, A e B de 1 a 8"
			m.input.Focus()
		case "f":
			m.settings.UDPForce = !m.settings.UDPForce
			_ = saveSettings(m.settings)
			if m.eng != nil {
				m.eng.SetUDPForce(m.settings.UDPForce)
			}
			m.log("Forcar UDP para copiar mesmo fora de AllowedIPs: %v (somente jogo; nao converte TCP em UDP)", m.settings.UDPForce)
		case "o":
			m.settings.UDPNewestOut = !m.settings.UDPNewestOut
			_ = saveSettings(m.settings)
			if m.eng != nil {
				m.eng.SetUDPNewestOut(m.settings.UDPNewestOut)
			}
			m.log("Reordenacao de ENVIO UDP do jogo (mais novo primeiro): %v. Pode causar perda/latencia.", m.settings.UDPNewestOut)
		case "a":
			m.settings.UDPNewestIn = !m.settings.UDPNewestIn
			_ = saveSettings(m.settings)
			if m.eng != nil {
				m.eng.SetUDPNewestIn(m.settings.UDPNewestIn)
			}
			m.log("Reordenacao de CHEGADA UDP do jogo (mais novo primeiro): %v. Pode quebrar sequencia do jogo.", m.settings.UDPNewestIn)
		case "m":
			m.settings.Mirror = !m.settings.Mirror
			_ = saveSettings(m.settings)
			if m.eng != nil {
				m.eng.SetMirror(m.settings.Mirror)
			}
			if m.settings.Mirror {
				m.log("Espelho para DPS meter LIGADO — no meter escolha o adaptador AionWG-Meter (ou o de loopback do Npcap)")
			} else {
				m.log("Espelho para DPS meter desligado")
			}
		case "d":
			if len(m.configs) > 0 && m.eng == nil {
				m.mode = modeDelete
			}
		case "w":
			m.settings.WFP = !m.settings.WFP
			_ = saveSettings(m.settings)
			if m.eng != nil {
				m.eng.SetWFP(m.settings.WFP)
			}
			if !m.settings.WFP {
				m.log("WFP desligado: volta o modo anterior (só jogo / sistema inteiro)")
			} else if len(m.settings.WFPApps) == 0 {
				// WFP with nothing selected tunnels nothing; make the user choose now.
				m.log("WFP ligado, mas nenhum app marcado: escolha os apps na lista")
				m.openPicker()
			} else {
				m.log("WFP ligado: só %d app(s) marcado(s) passam pelo túnel; ignora porta e sistema inteiro", len(m.settings.WFPApps))
			}
		case "l":
			m.openPicker()
		}
		return m, nil
	}
	return m, nil
}

func (m model) updateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.mode == modeWFPApps {
		return m.updatePicker(msg)
	}
	if m.mode == modeDelete {
		if msg.String() == "y" || msg.String() == "s" {
			name := m.configs[m.cursor]
			if err := deleteConfig(name); err != nil {
				m.log("ERRO: %v", err)
			} else {
				m.log("Config %s removida", name)
			}
			m.configs = listConfigs()
			if m.cursor >= len(m.configs) && m.cursor > 0 {
				m.cursor--
			}
		}
		m.mode = modeNormal
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m.mode = modeNormal
		m.input.Blur()
		return m, nil
	case "enter":
		v := strings.TrimSpace(m.input.Value())
		switch m.mode {
		case modeImport:
			name, err := importConfig(v)
			if err != nil {
				m.log("ERRO ao importar: %v", err)
			} else {
				m.log("Config importada: %s", name)
				m.configs = listConfigs()
				for i, c := range m.configs {
					if c == name {
						m.cursor = i
					}
				}
			}
		case modeProcs:
			var procs []string
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					procs = append(procs, p)
				}
			}
			if len(procs) == 0 {
				procs = defaultProcesses
			}
			m.settings.Processes = procs
			_ = saveSettings(m.settings)
			if m.eng != nil {
				m.eng.SetProcesses(procs)
			}
			m.log("Processos-alvo: %s", strings.Join(procs, ", "))
		case modeUDPCopies:
			a, b, ok := parseUDPRatio(v)
			if !ok {
				m.log("Proporcao invalida: use B (1:B) ou A:B, com A e B de 1 a %d", udpCopiesMax)
				return m, nil
			}
			m.settings.UDPOriginals, m.settings.UDPCopies = a, b
			_ = saveSettings(m.settings)
			if m.eng != nil {
				m.eng.SetUDPRatio(a, b)
			}
			m.log("UDP %s: a cada %d originais, %d copia(s) direta(s)", udpRatioLabel(a, b), a, b)
		case modeEndpoint:
			eng := m.eng
			m.mode = modeNormal
			m.input.Blur()
			if eng == nil {
				return m, nil
			}
			m.log("Trocando endpoint para %s…", v)
			return m, func() tea.Msg {
				if err := eng.SetEndpointString(v); err != nil {
					line := fmt.Sprintf("ERRO rota: %v", err)
					diskLog.Printf("%s", line)
					queueProgramLog(logMsg(line))
				}
				return nil
			}
		case modePing:
			m.settings.PingTarget = v
			_ = saveSettings(m.settings)
			m.log("Alvo de ping salvo (vale na próxima conexão)")
		}
		m.mode = modeNormal
		m.input.Blur()
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// ---------------------------------------------------------------- view helpers

func bestPing(s Stats) PingResult {
	if s.PingGame.OK {
		return s.PingGame
	}
	return s.PingTunnel
}

func fmtRate(bps float64) string {
	kb := bps / 1024
	if kb >= 1024 {
		return fmt.Sprintf("%.2f MB/s", kb/1024)
	}
	return fmt.Sprintf("%.1f KB/s", kb)
}

func fmtBytes(b uint64) string {
	f := float64(b)
	switch {
	case f >= 1<<30:
		return fmt.Sprintf("%.2f GB", f/(1<<30))
	case f >= 1<<20:
		return fmt.Sprintf("%.1f MB", f/(1<<20))
	case f >= 1<<10:
		return fmt.Sprintf("%.1f KB", f/(1<<10))
	}
	return fmt.Sprintf("%d B", b)
}

func pingColor(ms float64) lipgloss.Color {
	switch {
	case ms < 60:
		return cGreen
	case ms < 120:
		return cYellow
	}
	return cRed
}

func fmtPing(p PingResult) string {
	if p.Target == "" {
		return sDim.Render("—")
	}
	if !p.OK && p.RTT == 0 {
		if p.Err != 0 {
			return sDim.Render(fmt.Sprintf("sem resposta (erro %d)", p.Err))
		}
		return sDim.Render("sem resposta")
	}
	ms := float64(p.RTT.Microseconds()) / 1000
	s := lipgloss.NewStyle().Foreground(pingColor(ms)).Bold(true).Render(fmt.Sprintf("%.0f ms", ms))
	if !p.OK {
		s += sDim.Render(" (último)")
	}
	if p.Loss > 0 {
		s += lipgloss.NewStyle().Foreground(cRed).Render(fmt.Sprintf("  perda %.0f%%", p.Loss*100))
	}
	return s
}

// sparkline draws h as solid bars (█) colored by value; zero samples are a
// dim "|" baseline, or a red "x" when lossMark is set (ping with no reply).
func sparkline(h []float64, width int, color func(float64) lipgloss.Color, lossMark bool, frame int) string {
	if width <= 0 {
		return ""
	}
	if len(h) > width {
		h = h[len(h)-width:]
	}
	max := 0.0
	for _, v := range h {
		if v > max {
			max = v
		}
	}
	out := strings.Repeat(" ", width-len(h))
	for i, v := range h {
		switch {
		case v <= 0 && lossMark:
			out += lipgloss.NewStyle().Foreground(cRed).Render("x")
		case v <= 0 || max <= 0:
			out += sDim.Render("|")
		default:
			// Shimmer: a bright column travels left to right across the bars.
			fg := color(v)
			if (i+frame)%4 == 0 {
				fg = cShimmer
			}
			out += lipgloss.NewStyle().Foreground(fg).Render("█")
		}
	}
	return out
}

func fixedColor(c lipgloss.Color) func(float64) lipgloss.Color {
	return func(float64) lipgloss.Color { return c }
}

// histStats summarizes the non-zero samples as "min/med/max" (formatted by f).
func histStats(h []float64, f func(float64) string) string {
	var v []float64
	for _, x := range h {
		if x > 0 {
			v = append(v, x)
		}
	}
	if len(v) == 0 {
		return ""
	}
	sort.Float64s(v)
	return sDim.Render(fmt.Sprintf(" min %s · med %s · máx %s", f(v[0]), f(v[len(v)/2]), f(v[len(v)-1])))
}

// processSummary groups tunnelled processes by name ("steamwebhelper.exe ×6")
// and, unless warnGame is false, warns when the game itself is not running.
// WFP mode tunnels arbitrary apps, so there "the game is not open" is meaningless.
func processSummary(ps []ProcInfo, warnGame bool) string {
	order := []string{}
	count := map[string]int{}
	pid := map[string]uint32{}
	game := false
	for _, p := range ps {
		k := strings.ToLower(p.Name)
		if count[k] == 0 {
			order = append(order, p.Name)
			pid[k] = p.PID
		}
		count[k]++
		if !strings.HasPrefix(k, "steam") {
			game = true
		}
	}
	var parts []string
	for _, n := range order {
		k := strings.ToLower(n)
		if count[k] == 1 {
			parts = append(parts, fmt.Sprintf("%s (PID %d)", n, pid[k]))
		} else {
			parts = append(parts, fmt.Sprintf("%s ×%d", n, count[k]))
		}
	}
	out := ""
	if len(parts) > 0 {
		out = lipgloss.NewStyle().Foreground(cGreen).Render(strings.Join(parts, ", "))
	}
	if warnGame && !game {
		warn := lipgloss.NewStyle().Foreground(cYellow).Render("AION 2 não está aberto — abra o jogo")
		if out != "" {
			return warn + sDim.Render("  · ") + out
		}
		return warn
	}
	return out
}

func modeStatus(s Stats) string {
	if s.WFPOn {
		out := lipgloss.NewStyle().Foreground(cGreen).Render("WFP") +
			sDim.Render(" · só os apps marcados ([l]) · ignora porta e sistema inteiro")
		if !s.WFPSocket {
			out += lipgloss.NewStyle().Foreground(cYellow).Render(" · camada SOCKET indisponível: usando a tabela do sistema")
		}
		return out
	}
	if !s.FullTunnel {
		return lipgloss.NewStyle().Foreground(cDown).Render("só jogo") + sDim.Render("  · processos da lista [p]")
	}
	out := lipgloss.NewStyle().Foreground(cUp).Render("sistema inteiro") + sDim.Render(" · rede local direta")
	if s.DNS != "" && s.DNSTunnel {
		out += sDim.Render(" · DNS " + s.DNS + " pelo túnel ([n] desliga)")
	} else if s.DNS != "" {
		out += lipgloss.NewStyle().Foreground(cYellow).Render(" · DNS pelo túnel desligado ([n] liga)")
	} else {
		out += lipgloss.NewStyle().Foreground(cYellow).Render(" · config sem DNS: DNS sai direto")
	}
	if s.IPv6Direct {
		out += sDim.Render(" · IPv6 bloqueado (config sem IPv6)")
	}
	return out
}

func flowStatus(s Stats) string {
	if s.WFPOn {
		return fmt.Sprintf("%d fluxos dos apps WFP no túnel", s.GameFlows)
	}
	if s.FullTunnel {
		return fmt.Sprintf("%d fluxos no túnel (%d do jogo)", s.Flows, s.GameFlows)
	}
	return fmt.Sprintf("%d fluxos do jogo no túnel", s.GameFlows)
}

func udpDupStatus(s Stats) string {
	if !s.UDPDupOn {
		return sDim.Render("desligado ([u] liga)")
	}
	if s.FullTunnel {
		return lipgloss.NewStyle().Foreground(cYellow).Render("pausado: sistema inteiro")
	}
	return lipgloss.NewStyle().Foreground(cYellow).Render(fmt.Sprintf("%s · direto %d · perdas %d · erros %d · forcar %v", udpRatioLabel(s.UDPOriginals, s.UDPCopies), s.UDPDupSent, s.UDPDupDropped, s.UDPDupErrors, s.UDPForce))
}

func mirrorStatus(s Stats) string {
	if !s.MirrorOn {
		return sDim.Render("desligado  ([m] liga, para NotMeter / Shugo.gg)")
	}
	green := lipgloss.NewStyle().Foreground(cGreen)
	yellow := lipgloss.NewStyle().Foreground(cYellow)
	out := ""
	if s.MeterOK {
		out = green.Render("adaptador " + s.MeterAdapter)
	} else {
		out = yellow.Render("adaptador: " + s.MeterAdapter)
	}
	if len(s.MirrorFlows) == 0 {
		out += sDim.Render(" · loopback: aguardando o jogo (entre / troque de zona)")
	} else {
		out += sDim.Render(" · loopback: " + strings.Join(s.MirrorFlows, "  "))
	}
	return out
}

func row(label, value string) string {
	return sLabel.Render(fmt.Sprintf("%-12s", label)) + value
}

// ---------------------------------------------------------------- view

// View renders the densest-needed layout: full detail when it fits the
// terminal height, otherwise three more compact levels (see render).
func (m model) View() string {
	out := m.render(0)
	for level := 1; level <= 3 && m.height > 0 && lipgloss.Height(out) > m.height; level++ {
		out = m.render(level)
	}
	if lines := strings.Split(out, "\n"); m.height > 0 && len(lines) > m.height {
		// still too tall (tiny terminal): keep the header and the bottom (prompt / keys)
		out = lines[0] + "\n" + strings.Join(lines[len(lines)-m.height+1:], "\n")
	}
	return out
}

// render builds the screen. level 0 = everything; 1 = Ping beside Tráfego on
// wide terminals, one-line config list, no "Ordem UDP" row; 2 = also no
// sparklines/charts and a shorter route.
func (m model) render(level int) string {
	w := m.width
	if w < 70 {
		w = 70
	}
	inner := w - 4

	// header
	status := lipgloss.NewStyle().Foreground(cRed).Bold(true).Render("● DESCONECTADO")
	if m.connecting {
		status = lipgloss.NewStyle().Foreground(cYellow).Bold(true).Render("◌ CONECTANDO…")
	} else if m.eng != nil {
		status = lipgloss.NewStyle().Foreground(cGreen).Bold(true).Render("● CONECTADO")
	}
	title := sTitle.Render("AION 2 · WireGuard Split Tunnel")
	modeBadge := lipgloss.NewStyle().Foreground(lipgloss.Color("#000000")).Background(cDown).Padding(0, 1).Render("SÓ JOGO")
	if m.settings.FullTunnel {
		modeBadge = lipgloss.NewStyle().Foreground(lipgloss.Color("#000000")).Background(cUp).Padding(0, 1).Render("SISTEMA INTEIRO")
	}
	if m.settings.WFP {
		modeBadge = lipgloss.NewStyle().Foreground(lipgloss.Color("#000000")).Background(cGreen).Padding(0, 1).Render("WFP")
	}
	title += " " + modeBadge
	gap := w - lipgloss.Width(title) - lipgloss.Width(status) - 1
	if gap < 1 {
		gap = 1
	}
	header := title + strings.Repeat(" ", gap) + status

	// status panel
	var stat []string
	if m.eng != nil {
		s := m.stats
		hs := sDim.Render("aguardando…")
		if !s.Handshake.IsZero() {
			ago := time.Since(s.Handshake).Round(time.Second)
			c := cGreen
			if ago > 3*time.Minute {
				c = cRed
			}
			hs = lipgloss.NewStyle().Foreground(c).Render(fmt.Sprintf("há %s", ago))
		}
		procs := processSummary(s.Procs, !s.WFPOn)
		procLabel := "Processo"
		if s.WFPOn {
			procLabel = "Apps WFP"
			if procs == "" {
				procs = lipgloss.NewStyle().Foreground(cYellow).Render("nenhum app marcado em execução ([l] escolhe)")
			}
		}
		modo := []string{row("Modo", modeStatus(s)), row("Conexões", flowStatus(s))}
		if level >= 3 {
			modo = []string{row("Modo", modeStatus(s)+sDim.Render("  ·  ")+flowStatus(s))}
		}
		stat = append(stat,
			row("Config", sBold.Render(m.engName)+sDim.Render("  · ativo há "+time.Since(m.since).Round(time.Second).String())),
			row("Endpoint", s.Endpoint+sDim.Render("   túnel ")+s.TunnelAddr+sDim.Render("   [v] troca")),
			row("Saída", exitStatus(s.Exit)),
			row("Handshake", hs),
			row(procLabel, procs),
		)
		stat = append(stat, modo...)
		stat = append(stat,
			row("Espelho DPS", mirrorStatus(s)),
			row("UDP extra", udpDupStatus(s)),
		)
		if level == 0 {
			stat = append(stat, row("Ordem UDP", fmt.Sprintf("saida recente %v (perdas %d) · chegada recente %v (perdas %d)", s.UDPNewestOut, s.UDPSendDropped, s.UDPNewestIn, s.UDPRecvDropped)))
		}
		stat = append(stat, row("Melhor rota", routeStatus(s)))
		if s.RouteNote != "" && level < 3 {
			stat = append(stat, row("", sDim.Render(s.RouteNote)))
		}
	} else {
		stat = append(stat, sDim.Render("Selecione uma config abaixo e pressione Enter para conectar."))
		on := sDim.Render("desligado  ([m] liga)")
		if m.settings.Mirror {
			on = lipgloss.NewStyle().Foreground(cGreen).Render("ligado")
		}
		stat = append(stat, row("Espelho DPS", on))
		du := sDim.Render("desligado ([u] liga)")
		if m.settings.UDPDuplicate {
			du = lipgloss.NewStyle().Foreground(cYellow).Render("ligado (experimental)")
		}
		stat = append(stat, row("UDP extra", fmt.Sprintf("%s · forcar %v · %s", udpRatioLabel(m.settings.UDPOriginals, m.settings.UDPCopies), m.settings.UDPForce, du)))
		stat = append(stat, row("Ordem UDP", fmt.Sprintf("saida recente %v · chegada recente %v", m.settings.UDPNewestOut, m.settings.UDPNewestIn)))
		br := sDim.Render("desligado ([b] liga)")
		if m.settings.BestEndpoint {
			br = lipgloss.NewStyle().Foreground(cGreen).Render("ligado") + sDim.Render(" ([b] desliga) · descobre e confirma por handshake ao conectar")
		}
		stat = append(stat, row("Melhor rota", br))
		md := "só jogo  ([s] muda para sistema inteiro)"
		if m.settings.FullTunnel {
			md = "sistema inteiro  ([s] muda para só jogo)"
		}
		if m.settings.WFP {
			md = fmt.Sprintf("WFP · %d app(s) marcados ([l] escolhe, [w] desliga) · ignora porta e sistema", len(m.settings.WFPApps))
		}
		stat = append(stat, row("Modo", sDim.Render(md)))
	}

	// ping panel
	wide := level >= 1 && w >= 130
	pw := inner // content width of the Ping / Tráfego boxes
	if wide {
		pw = (w-2)/2 - 2
	}
	var ping []string
	if m.eng != nil {
		s := m.stats
		gameLbl := "Jogo (túnel)"
		ping = append(ping,
			row("VPN direto", fmtPing(s.PingEndpoint)+sDim.Render("  "+s.PingEndpoint.Target)),
			row("Túnel", fmtPing(s.PingTunnel)+sDim.Render("  "+s.PingTunnel.Target)),
			row(gameLbl, fmtPing(s.PingGame)+sDim.Render("  "+s.PingGame.Target)),
			row("Jogo (direto)", fmtPing(s.PingGameDirect)+sDim.Render("  "+s.PingGameDirect.Target)),
			row("Custo do túnel", tunnelCost(s)),
		)
		if s.MirrorAck.N+s.MirrorResp.N > 0 {
			ping = append(ping, row("Espelho RTT", sDim.Render(fmt.Sprintf("ack %v (média %v) · resposta %v (média %v)",
				s.MirrorAck.Last.Round(time.Millisecond), s.MirrorAck.Avg.Round(time.Millisecond),
				s.MirrorResp.Last.Round(time.Millisecond), s.MirrorResp.Avg.Round(time.Millisecond)))))
		}
		if level < 2 {
			ping = append(ping, sLabel.Render(fmt.Sprintf("%-12s", "Histórico"))+sparkline(m.histPing, pw-14, func(v float64) lipgloss.Color { return pingColor(v) }, true, m.frame))
		}
		if level == 0 {
			ping = append(ping, sLabel.Render(fmt.Sprintf("%-12s", ""))+histStats(m.histPing, func(v float64) string { return fmt.Sprintf("%.0f ms", v) }))
		}
	}

	// traffic panel
	var traffic []string
	if m.eng != nil {
		s := m.stats
		pair := func(up, down float64) string {
			a := lipgloss.NewStyle().Foreground(cUp).Bold(true).Width(18).Render("▲ " + fmtRate(up))
			return a + lipgloss.NewStyle().Foreground(cDown).Bold(true).Render("▼ "+fmtRate(down))
		}
		tot := func(label string, up, down float64, tu, td uint64) []string {
			r := row(label, pair(up, down))
			t := fmt.Sprintf("total ▲ %s  ▼ %s", fmtBytes(tu), fmtBytes(td))
			if level >= 3 {
				return []string{r + sDim.Render("  "+t)}
			}
			return []string{r, row("", sDim.Render(t))}
		}
		lbl := "Túnel total"
		if s.FullTunnel {
			lbl = "Sistema"
		}
		traffic = append(traffic, tot(lbl, m.upRate, m.downRate, s.Up, s.Down)...)
		traffic = append(traffic, tot("AION 2", m.gUpRate, m.gDnRate, s.GameUp, s.GameDown)...)
		traffic = append(traffic,
			row("WireGuard", sDim.Render(fmt.Sprintf("▲ %s  ▼ %s  (com overhead · total ▲ %s ▼ %s)",
				fmtRate(m.wgTxRate), fmtRate(m.wgRxRate), fmtBytes(s.WGTx), fmtBytes(s.WGRx)))),
		)
		if level < 2 {
			traffic = append(traffic,
				sLabel.Render(fmt.Sprintf("%-12s", "Upload"))+rateChart(m.histUp, pw-14, fixedColor(cUp), m.frame),
				sLabel.Render(fmt.Sprintf("%-12s", "Download"))+rateChart(m.histDown, pw-14, fixedColor(cDown), m.frame),
			)
		}
	}

	// configs
	var cfg []string
	if len(m.configs) == 0 {
		cfg = append(cfg, sDim.Render("(nenhuma — [i] para importar)"))
	}
	for i, c := range m.configs {
		if level >= 1 && m.eng != nil && i != m.cursor {
			continue // connected and short of room: only the selected config
		}
		mark := "  "
		line := c
		if i == m.cursor {
			mark = sSel.Render("▸ ")
			line = sSel.Render(c)
		}
		if m.eng != nil && c == m.engName {
			line += lipgloss.NewStyle().Foreground(cGreen).Render("  ● em uso")
		}
		if level >= 1 && m.eng != nil && len(m.configs) > 1 {
			line += sDim.Render(fmt.Sprintf("   (%d configs · ↑↓ escolhe)", len(m.configs)))
		}
		cfg = append(cfg, mark+line)
	}

	box := func(title string, lines []string) string {
		t := lipgloss.NewStyle().Foreground(cAccent).Bold(true).Render(title)
		return sBox.Width(inner).Render(t + "\n" + strings.Join(lines, "\n"))
	}
	halfBox := func(title string, lines []string) string {
		t := lipgloss.NewStyle().Foreground(cAccent).Bold(true).Render(title)
		return sBox.Width(pw).Render(t + "\n" + strings.Join(lines, "\n"))
	}

	routeMax := 10
	if level >= 2 {
		routeMax = 4
	}
	parts := []string{header, box("Status", stat)}
	if m.eng != nil {
		routeLn := routeLinesMax(m.stats, routeMax)
		if level >= 3 {
			routeLn = routeSummary(m.stats)
		}
		rt := box("Rota em uso (traceroute)", routeLn)
		if wide {
			parts = append(parts, lipgloss.JoinHorizontal(lipgloss.Top, halfBox("Ping", ping), halfBox("Tráfego", traffic)), rt)
		} else {
			parts = append(parts, box("Ping", ping), rt, box("Tráfego", traffic))
		}
	}
	if m.eng != nil && m.showDiag {
		d, r := m.stats.Diag, m.diagRate
		line := func(label string, total, rate uint64) string {
			return row(label, fmt.Sprintf("%-10d %s", total, sDim.Render(fmt.Sprintf("(%d/s)", rate))))
		}
		warn := func(label string, total, rate uint64) string {
			s := line(label, total, rate)
			if rate > 0 {
				s += lipgloss.NewStyle().Foreground(cRed).Render("  ◀")
			}
			return s
		}
		diag := []string{
			line("→ túnel", d.Captured, r.Captured),
			line("← túnel", d.Injected, r.Injected),
			line("DNS perg.", d.DNSQ, r.DNSQ),
			line("DNS resp.", d.DNSA, r.DNSA),
			warn("Sem fluxo", d.InNoNAT, r.InNoNAT),
			warn("Erro inj.", d.InjectErr, r.InjectErr),
			warn("Fila cheia", d.TunDrop, r.TunDrop),
			line("LSO divid.", d.Segmented, r.Segmented),
			line("ICMP erro", d.ICMPErr, r.ICMPErr),
			line("Tabelas", d.TableDumps, r.TableDumps),
			line("IPv6 bloq.", d.V6Blocked, r.V6Blocked),
		}
		parts = append(parts, box("Diagnóstico  [g] fecha", diag))
	}
	if len(m.tests) > 0 || m.testing {
		var tl []string
		for _, r := range m.tests {
			mark := lipgloss.NewStyle().Foreground(cGreen).Render("✔")
			if !r.OK {
				mark = lipgloss.NewStyle().Foreground(cRed).Render("✘")
			}
			tl = append(tl, mark+" "+sLabel.Render(fmt.Sprintf("%-28s", r.Name))+
				lipgloss.NewStyle().Width(inner-34).Render(r.Detail+sDim.Render(fmt.Sprintf("  %d ms", r.Dur.Milliseconds()))))
		}
		if m.testing {
			tl = append(tl, lipgloss.NewStyle().Foreground(cYellow).Render("◌ testando…"))
		}
		parts = append(parts, box("Autoteste  [x] repete", tl))
	}
	parts = append(parts, box("Configs", cfg))

	// footer / prompt, built first so the log is sized with its real height
	var foot string
	switch m.mode {
	case modeImport:
		foot = sBold.Render("Caminho do .conf: ") + m.input.View() + sDim.Render("  [Enter] ok  [Esc] cancelar")
	case modeProcs:
		foot = sBold.Render("Processos (separados por vírgula): ") + m.input.View()
	case modePing:
		foot = sBold.Render("IP para ping no túnel: ") + m.input.View()
	case modeUDPCopies:
		foot = sBold.Render("Proporcao UDP (X = 1:X, X:X = rajada; X 1..8): ") + m.input.View() + sDim.Render("  [Enter] ok  [Esc] cancelar")
	case modeEndpoint:
		foot = sBold.Render("Novo endpoint (IP ou IP:porta): ") + m.input.View() + sDim.Render("  [Enter] ok  [Esc] cancelar")
	case modeDelete:
		foot = lipgloss.NewStyle().Foreground(cRed).Bold(true).Render(
			fmt.Sprintf("Remover %s? [s/y] sim  [qualquer tecla] não", m.configs[m.cursor]))
	case modeWFPApps:
		foot = m.wfpPicker(w)
	default:
		k := func(key, desc string) string { return sKey.Render("["+key+"]") + " " + sDim.Render(desc) }
		act := "conectar"
		if m.eng != nil {
			act = "desconectar"
		}
		foot = lipgloss.NewStyle().Width(w).Render(strings.Join([]string{
			k("Enter", act), k("i", "importar"), k("↑↓", "escolher"), k("p", "processos"),
			k("w", "WFP"), k("l", "apps WFP"),
			k("s", "sistema inteiro"), k("n", "DNS túnel"), k("b", "melhor rota"), k("v", "trocar endpoint"), k("m", "espelho DPS"), k("u", "dup UDP"), k("r", "proporcao"), k("f", "forcar UDP"), k("o", "envio recente"), k("a", "chegada recente"), k("x", "autoteste"), k("g", "diagnóstico"), k("e", "exportar p/ WG oficial"), k("t", "alvo do ping"), k("d", "remover"), k("q", "sair"),
		}, "  "))
	}

	// logs: fill remaining height (log box = 2 borders + title)
	logN := 6
	if m.height > 0 {
		used := lipgloss.Height(strings.Join(parts, "\n")) + 3 + lipgloss.Height(foot)
		logN = max(m.height-used, 1)
		if level == 0 {
			logN = max(logN, 3)
		}
	}
	lg := m.logs
	if len(lg) > logN {
		lg = lg[len(lg)-logN:]
	}
	var lgr []string
	for _, l := range lg {
		st := sDim
		if strings.Contains(l, "ERRO") {
			st = lipgloss.NewStyle().Foreground(cRed)
		}
		lgr = append(lgr, st.Width(inner-2).Render(l))
	}
	if all := strings.Split(strings.Join(lgr, "\n"), "\n"); len(all) > logN {
		lgr = all[len(all)-logN:]
	}
	parts = append(parts, box("Log", lgr))

	parts = append(parts, foot)
	return strings.Join(parts, "\n")
}

// openPicker opens the app list with a fresh process scan. The receiver is a
// pointer on purpose: Update has a value receiver, so a value method would
// change a copy and the picker would never open.
func (m *model) openPicker() {
	m.running = ListAllProcesses()
	m.appCursor = 0
	m.mode = modeWFPApps
}

// wfpPickerRows is how many apps the picker shows at once; the rest scroll.
const wfpPickerRows = 10

// pickerList is the picker content: running apps merged with the selection.
func (m model) pickerList() []appEntry {
	self := "aionwg.exe"
	if exe, err := os.Executable(); err == nil {
		self = filepath.Base(exe)
	}
	return buildAppList(m.running, m.settings.WFPApps, self)
}

// wfpPicker renders the scrollable app list, keeping the cursor visible.
func (m model) wfpPicker(w int) string {
	list := m.pickerList()
	cur := clampCursor(m.appCursor, len(list))
	top := 0
	if cur >= wfpPickerRows {
		top = cur - wfpPickerRows + 1
	}
	end := top + wfpPickerRows
	if end > len(list) {
		end = len(list)
	}
	var lines []string
	if len(list) == 0 {
		lines = append(lines, sDim.Render("(nenhum processo encontrado)"))
	}
	for i := top; i < end; i++ {
		e := list[i]
		mark := "[ ]"
		if e.Selected {
			mark = lipgloss.NewStyle().Foreground(cGreen).Bold(true).Render("[x]")
		}
		name := e.Name
		if !e.Running {
			name += sDim.Render("  (fechado)")
		}
		cursor := "  "
		if i == cur {
			cursor = sSel.Render("▸ ")
			name = sSel.Render(e.Name)
			if !e.Running {
				name += sDim.Render("  (fechado)")
			}
		}
		lines = append(lines, cursor+mark+" "+name)
	}
	title := fmt.Sprintf("Apps pelo WFP — %d marcado(s) de %d  [↑↓] mover  [espaço] marcar  [Esc/Enter] fechar", len(m.settings.WFPApps), len(list))
	return sBox.Width(w - 4).Render(sBold.Render(title) + "\n" + strings.Join(lines, "\n"))
}

// updatePicker handles keys while the app picker is open. Toggling applies to
// the running engine at once and is saved, so the choice survives a restart.
func (m model) updatePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	list := m.pickerList()
	switch msg.String() {
	case "esc", "enter", "l":
		m.mode = modeNormal
	case "up", "k":
		if m.appCursor > 0 {
			m.appCursor--
		}
	case "down", "j":
		if m.appCursor < len(list)-1 {
			m.appCursor++
		}
	case " ":
		if m.appCursor >= 0 && m.appCursor < len(list) {
			m.settings.WFPApps = toggleApp(m.settings.WFPApps, list[m.appCursor].Name)
			_ = saveSettings(m.settings)
			if m.eng != nil {
				m.eng.SetWFPApps(m.settings.WFPApps)
			}
			// the toggled app moves (selected ones sort first): keep the cursor on it
			for i, e := range m.pickerList() {
				if strings.EqualFold(e.Name, list[m.appCursor].Name) {
					m.appCursor = i
					break
				}
			}
		}
	}
	return m, nil
}

// diskLog is nil when the file cannot be opened; fileLog methods accept nil, so
// callers never check. Logging to disk is diagnostic and must never stop the app.
var diskLog *fileLog

func runTUI() error {
	if l, err := openFileLog(filepath.Join(appDir(), "aionwg.log")); err == nil {
		diskLog = l
		defer l.Close()
	}
	s := loadSettings()
	diskLog.Printf("==== AionWG iniciado · espelho=%v wfp=%v sistema_inteiro=%v udp_dup=%v",
		s.Mirror, s.WFP, s.FullTunnel, s.UDPDuplicate)
	program = tea.NewProgram(newModel(), tea.WithAltScreen())
	finished := make(chan struct{})
	go func() {
		for {
			select {
			case msg := <-programLogs:
				program.Send(msg) // only the dispatcher can block here
			case <-finished:
				return
			}
		}
	}()
	_, err := program.Run()
	close(finished)
	diskLog.Printf("==== AionWG encerrado")
	return err
}

// rateChart draws a throughput history with its min/med/max summary, shrinking
// the bars so the line still fits the panel.
func rateChart(h []float64, width int, color func(float64) lipgloss.Color, frame int) string {
	st := histStats(h, fmtRate)
	w := width - lipgloss.Width(st)
	if w < 10 {
		w, st = width, ""
	}
	return sparkline(h, w, color, false, frame) + st
}

// routeStatus describes the best-route option of the running connection.
func routeStatus(s Stats) string {
	if s.RouteMonitor {
		return lipgloss.NewStyle().Foreground(cGreen).Render("monitorando") +
			sDim.Render(" · troca só se o ping do jogo melhorar ([b] liga/desliga na próxima conexão · [v] troca à mão)")
	}
	return sDim.Render("desligado ([b] liga na próxima conexão · [v] troca o endpoint à mão)")
}

// collapseLines keeps the first and last lines of a long hop list.
func collapseLines(lines []string, max int) []string {
	if len(lines) <= max {
		return lines
	}
	head := max / 2
	tail := max - head - 1
	out := append([]string{}, lines[:head]...)
	out = append(out, sDim.Render(fmt.Sprintf("      … %d saltos omitidos …", len(lines)-head-tail)))
	return append(out, lines[len(lines)-tail:]...)
}

func routeLines(s Stats) []string { return routeLinesMax(s, 10) }

// routeLinesMax draws the route in use like a traceroute: the hops from this PC
// to the VPN endpoint, then the hops inside the tunnel to the game server; each
// segment is collapsed to at most maxHops lines.
func routeLinesMax(s Stats, maxHops int) []string {
	rt := s.Route
	if rt.At.IsZero() {
		return []string{sDim.Render("medindo a rota…")}
	}
	hop := func(h Hop, mark string) string {
		addr, rtt := "*", ""
		if h.Addr.IsValid() {
			addr = h.Addr.String()
			ms := float64(h.RTT.Microseconds()) / 1000
			rtt = lipgloss.NewStyle().Foreground(pingColor(ms)).Render(fmt.Sprintf("%.0f ms", ms))
		}
		return fmt.Sprintf(" %2d  %-39s %s%s", h.TTL, addr, rtt, mark)
	}
	segment := func(hops []Hop, last netip.Addr, mark string, empty string) []string {
		if len(hops) == 0 {
			return []string{sDim.Render("      " + empty)}
		}
		lines := make([]string, len(hops))
		for i, h := range hops {
			m := ""
			if h.Addr == last {
				m = mark
			}
			lines[i] = hop(h, m)
		}
		return collapseLines(lines, maxHops)
	}
	age := time.Since(rt.At).Round(time.Second)
	out := []string{sBold.Render("PC") + sDim.Render(" → internet → endpoint ") + rt.Endpoint.String() + sDim.Render(fmt.Sprintf("   (medido há %s)", age))}
	out = append(out, segment(rt.Direct, rt.Endpoint, sDim.Render("  ◀ endpoint"), "nenhum salto respondeu a ICMP no caminho direto")...)
	out = append(out, lipgloss.NewStyle().Foreground(cAccent).Render("══ túnel WireGuard ══▶"))
	dest, mark := "gateway do túnel", sDim.Render("  ◀ gateway")
	if rt.DestIsGame {
		dest, mark = "jogo", lipgloss.NewStyle().Foreground(cGreen).Render("  ◀ jogo")
	}
	out = append(out, sDim.Render("endpoint → "+dest+" ")+rt.Dest.String())
	out = append(out, segment(rt.Tunnel, rt.Dest, mark, "nenhum salto respondeu dentro do túnel (o provedor pode filtrar ICMP/TTL)")...)
	return out
}

// tunnelCost is how many ms the tunnel adds to the game ping compared with going
// straight to the game server (both measured now).
func tunnelCost(s Stats) string {
	t, d := pingMs(s.PingGame), pingMs(s.PingGameDirect)
	if t == 0 || d == 0 {
		return sDim.Render("— (precisa do ping do jogo pelo túnel e direto)")
	}
	diff := t - d
	col, note := cGreen, "  (o túnel não está piorando o ping)"
	switch {
	case diff > 15:
		col = cRed
	case diff > 5:
		col = cYellow
	}
	if diff > 0 {
		note = "  (o túnel soma isso ao ping do jogo)"
	}
	return lipgloss.NewStyle().Foreground(col).Bold(true).Render(fmt.Sprintf("%+d ms", diff)) + sDim.Render(note)
}

// routeSummary is the two-line route for small terminals: hop count and the
// round trip to the endpoint / destination.
func routeSummary(s Stats) []string {
	rt := s.Route
	if rt.At.IsZero() {
		return []string{sDim.Render("medindo a rota…")}
	}
	seg := func(hops []Hop, dest netip.Addr) string {
		out := fmt.Sprintf("%d saltos", len(hops))
		for _, h := range hops {
			if h.Addr == dest {
				return out + fmt.Sprintf(", chegou em %.0f ms", float64(h.RTT.Microseconds())/1000)
			}
		}
		return out + ", destino sem resposta ICMP"
	}
	return []string{
		sBold.Render("PC → endpoint ") + rt.Endpoint.String() + sDim.Render("  "+seg(rt.Direct, rt.Endpoint)),
		sBold.Render("túnel → ") + rt.Dest.String() + sDim.Render("  "+seg(rt.Tunnel, rt.Dest)),
	}
}

// exitStatus shows where the tunnel exits (data centre, city and IP).
func exitStatus(x ExitInfo) string {
	if x.At.IsZero() {
		return sDim.Render("medindo…")
	}
	return sBold.Render(x.String())
}
