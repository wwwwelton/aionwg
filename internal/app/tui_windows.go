//go:build windows

package app

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
	modeEndpointPick
	modeSearch
	modeTunnelDuplicate
	modeTunnelRename
	modeRelay
	modeProbeFile
)

type uiScreen int

const (
	screenDashboard uiScreen = iota
	screenProcesses
	screenTunnels
	screenRoutes
	screenWFP
	screenUDP
	screenWarp
	screenLatency
	screenDiagnostics
	screenSettings
)

type uiOverlay int

const (
	overlayNone uiOverlay = iota
	overlayPalette
	overlayHelp
)

type commandItem struct {
	name string
	key  string
	run  func(*model)
}

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
	frame      int // animation frame, advances every animTick
	settings   Settings
	configs    []string
	cursor     int
	mode       mode
	input      textinput.Model
	screen     uiScreen
	previous   uiScreen
	overlay    uiOverlay
	palette    int
	filter     string
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
	managed   []ManagedProcess
	appCursor int
	epCursor  int // cursor of the endpoint picker

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

var screenLabels = [...]string{
	"Dashboard", "Processos", "Túneis", "Rotas", "WFP",
	"UDP", "WARP", "Latência", "Diagnóstico", "Configurações",
}

func (m *model) setScreen(s uiScreen) {
	if s < screenDashboard || s > screenSettings || m.screen == s {
		return
	}
	m.previous, m.screen = m.screen, s
}

func (m *model) backScreen() {
	if m.screen == screenDashboard {
		return
	}
	m.screen, m.previous = m.previous, screenDashboard
}

func (m model) navTabs() string {
	maxWidth := m.width - 4
	if maxWidth < 70 {
		maxWidth = 70
	}
	labels := screenLabels[:]
	if maxWidth < 120 {
		labels = []string{"Dash", "Proc", "Tun", "Rot", "WFP", "UDP", "WRP", "RTT", "Diag", "Set"}
	}
	var lines []string
	line := ""
	for i, label := range labels {
		tab := fmt.Sprintf("F%d %s", i+1, label)
		if uiScreen(i) == m.screen {
			tab = lipgloss.NewStyle().Foreground(lipgloss.Color("#000000")).Background(cAccent).Padding(0, 1).Render(tab)
		} else {
			tab = lipgloss.NewStyle().Foreground(cDim).Render(tab)
		}
		next := tab
		if line != "" {
			next = line + "  " + tab
		}
		if line != "" && lipgloss.Width(next) > maxWidth {
			lines = append(lines, line)
			line = tab
		} else {
			line = next
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func (m model) backendLabel() string {
	if m.eng == nil {
		return sDim.Render("não conectado")
	}
	if m.stats.Backend != "" {
		col := cYellow
		if m.stats.WFPOn {
			col = cGreen
		}
		return lipgloss.NewStyle().Foreground(col).Render(m.stats.Backend)
	}
	if m.stats.WFPOn {
		return lipgloss.NewStyle().Foreground(cGreen).Render("Hybrid · WFP SOCKET + WinDivert NETWORK")
	}
	return lipgloss.NewStyle().Foreground(cYellow).Render("Legacy · WinDivert NETWORK")
}

func stateValue(ok bool) string {
	if ok {
		return lipgloss.NewStyle().Foreground(cGreen).Render("ativo")
	}
	return lipgloss.NewStyle().Foreground(cYellow).Render("inativo")
}

func stateSummary(s Stats) string {
	return fmt.Sprintf("driver %s · interceptação %s · interface %s · WG %s · handshake %s · rota %s · forward %s · túnel %s · destino %s",
		stateValue(s.DriverLoaded), stateValue(s.InterceptorActive), stateValue(s.VirtualInterfaceActive),
		stateValue(s.WireGuardActive), stateValue(s.HandshakeValid), stateValue(s.RouteApplied),
		stateValue(s.ForwardingActive), stateValue(s.TunnelReachable), stateValue(s.DestinationReachable))
}

func (m model) moduleLines() []string {
	s := m.stats
	switch m.screen {
	case screenProcesses:
		procs := processSummary(s.Procs, false)
		if m.eng == nil {
			procs = strings.Join(m.settings.Processes, ", ")
		}
		if procs == "" {
			procs = sDim.Render("nenhum processo observado")
		}
		lines := []string{
			row("Política", "DEFAULT · lista atual preservada"),
			row("Regras", formatProcessRules(m.settings)),
			row("Túnel", procs),
			row("WFP apps", fmt.Sprintf("%d selecionados · [l] editar", len(m.settings.WFPApps))),
			row("Ação", sDim.Render("[p] editar regras · [l] selecionar apps WFP · [/] filtrar")),
		}
		visible := filterManagedProcesses(m.managed, m.filter)
		for _, process := range visible {
			connections := fmt.Sprintf("%d conexões", len(process.Connections))
			value := process.Path
			if value == "" {
				value = "caminho indisponível"
			}
			lines = append(lines, row(fmt.Sprintf("%d %s", process.PID, process.Name), string(process.Policy)+" · "+connections+" · "+value))
		}
		if len(visible) == 0 {
			lines = append(lines, row("", sDim.Render("nenhum processo ativo corresponde ao filtro")))
		}
		return lines
	case screenTunnels:
		name := selectedConfig(m.configs, m.cursor)
		connected := sDim.Render("desconectado")
		if m.eng != nil && name == m.engName {
			connected = lipgloss.NewStyle().Foreground(cGreen).Render("conectado")
		}
		lines := []string{
			row("Perfis", fmt.Sprintf("%d configurações", len(m.configs))),
			row("Selecionado", name),
			row("Conectado", connected),
		}
		if profile, err := NewTunnelManager(configDir()).Profile(name); err != nil {
			lines = append(lines, row("Validação", lipgloss.NewStyle().Foreground(cRed).Render(err.Error())))
		} else {
			lines = append(lines,
				row("Protocolo", profile.Protocol),
				row("Endpoint", valueOrDash(profile.Endpoint)),
				row("Interface", joinProfileValues(profile.Addresses)),
				row("MTU", fmt.Sprintf("%d", profile.MTU)),
				row("DNS", valueOrDash(joinProfileValues(profile.DNS))),
				row("AllowedIPs", valueOrDash(joinProfileValues(profile.AllowedIPs))),
				row("Keepalive", fmt.Sprintf("%ds", profile.Keepalive)),
			)
		}
		if m.eng != nil && name == m.engName {
			lines = append(lines, row("Handshake", stateValue(!s.Handshake.IsZero())+" · RX "+fmtBytes(s.WGRx)+" · TX "+fmtBytes(s.WGTx)))
		}
		return lines
	case screenRoutes:
		lines := []string{
			row("Backend", m.backendLabel()),
			row("Endpoint", valueOrDash(s.Endpoint)),
			row("Monitor", routeStatus(s)),
			row("Rota", routeSummaryLine(s)),
			row("Ação", sDim.Render("[b] melhor rota · [B] conta de teste · [v] trocar endpoint · [t] alvo do ping")),
		}
		for _, candidate := range routeCandidates(s, m.settings.WarpMultipath) {
			lines = append(lines, row(string(candidate.Kind), routeCandidateText(candidate)))
		}
		return lines
	case screenWFP:
		socket := "indisponível"
		if s.WFPSocket {
			socket = "ativo"
		}
		policy := valueOrDash(s.PolicyBackend)
		packet := valueOrDash(s.PacketBackend)
		session := stateValue(s.NativeWFP.SessionOpen)
		provider := stateValue(s.NativeWFP.ProviderRegistered)
		sublayer := stateValue(s.NativeWFP.SubLayerRegistered)
		lines := []string{
			row("Backend", m.backendLabel()),
			row("Policy", policy),
			row("Packet", packet),
			row("Sessão", session+" · provider "+provider+" · sublayer "+sublayer),
			row("Filtros", fmt.Sprintf("%d filtros · %d regras BLOCK", s.NativeWFP.FiltersInstalled, s.NativeWFP.RulesActive)),
			row("Driver", stateValue(s.DriverLoaded)+" · WinDivert"),
			row("Interceptação", stateValue(s.InterceptorActive)),
			row("Interface", stateValue(s.VirtualInterfaceActive)),
			row("WireGuard", stateValue(s.WireGuardActive)),
			row("Handshake", stateValue(s.HandshakeValid)),
			row("Rota/forward", stateValue(s.RouteApplied)+" / "+stateValue(s.ForwardingActive)),
			row("SOCKET/ALE", socket),
			row("Processos", fmt.Sprintf("%d selecionados · %d fluxos", len(m.settings.WFPApps), s.GameFlows)),
			row("Ação", sDim.Render("[w] alternar · [l] selecionar apps")),
		}
		if s.NativeWFP.LastError != "" {
			lines = append(lines, row("Erro WFP", s.NativeWFP.LastError))
		}
		return lines
	case screenUDP:
		lines := []string{
			row("Duplicação", udpDupStatus(s)),
			row("Proporção", udpRatioLabel(m.settings.UDPOriginals, m.settings.UDPCopies)),
			row("Forçar UDP", fmt.Sprintf("%v", m.settings.UDPForce)),
			row("Envio recente", fmt.Sprintf("%v", m.settings.UDPNewestOut)),
			row("Chegada recente", fmt.Sprintf("%v", m.settings.UDPNewestIn)),
		}
		if m.eng != nil {
			lines = append(lines, row("Contadores", fmt.Sprintf("originais %d · cópias %d · descartes %d · erros %d", s.UDPDupAccepted, s.UDPDupSent, s.UDPDupDropped, s.UDPDupErrors)))
		}
		return lines
	case screenWarp:
		paths := "uma sessão"
		if len(s.Paths) > 0 {
			paths = udpPathsStatus(s.Paths)
		}
		return []string{
			row("Rota", valueOrDash(s.Endpoint)),
			row("Sessões", paths),
			row("Multipath", fmt.Sprintf("%v · [h] alternar", m.settings.WarpMultipath)),
			row("Origem", "sessões WARP gerenciadas pelo AionWG"),
		}
	case screenLatency:
		return []string{
			row("VPN direto", fmtPing(s.PingEndpoint)),
			row("Túnel", fmtPing(s.PingTunnel)),
			row("Jogo túnel", fmtPing(s.PingGame)),
			row("Jogo direto", fmtPing(s.PingGameDirect)),
			row("Histórico", histStats(m.histPing, func(v float64) string { return fmt.Sprintf("%.0f ms", v) })),
		}
	case screenDiagnostics:
		d := s.Diag
		return []string{
			row("Backend", m.backendLabel()),
			row("Recursos", telemetrySummary(s)),
			row("Fluxos", fmt.Sprintf("%d ativos · %d jogo", s.Flows, s.GameFlows)),
			row("Capturados", fmt.Sprintf("%d", d.Captured)),
			row("Reinjetados", fmt.Sprintf("%d", d.Injected)),
			row("Erros", fmt.Sprintf("injeção %d · sem NAT %d · filas %d", d.InjectErr, d.InNoNAT, d.TunDrop)),
			row("Ação", sDim.Render("[g] diagnóstico detalhado · [x] autoteste")),
		}
	case screenSettings:
		return []string{
			row("Full tunnel", fmt.Sprintf("%v", m.settings.FullTunnel)),
			row("DNS túnel", fmt.Sprintf("%v", !m.settings.NoDNS)),
			row("Melhor rota", fmt.Sprintf("%v", m.settings.BestEndpoint)),
			row("WFP", fmt.Sprintf("%v", m.settings.WFP)),
			row("Multipath", fmt.Sprintf("%v", m.settings.WarpMultipath)),
			row("Relays próprios", strings.Join(m.settings.CustomRelays, ", ")),
			row("Conta de teste [b]", valueOrDash(m.settings.ProbeConfig)+" · [B] escolhe o .conf de teste (pode ser o mesmo do perfil)"),
			row("Persistência", "settings.json; chaves não exibidas"),
		}
	}
	return nil
}

func selectedConfig(configs []string, cursor int) string {
	if cursor >= 0 && cursor < len(configs) {
		return configs[cursor]
	}
	return "—"
}

func valueOrDash(v string) string {
	if v == "" {
		return "—"
	}
	return v
}

func routeSummaryLine(s Stats) string {
	if s.Route.At.IsZero() {
		return "medindo…"
	}
	return fmt.Sprintf("%d saltos diretos · %d no túnel · medido há %s", len(s.Route.Direct), len(s.Route.Tunnel), time.Since(s.Route.At).Round(time.Second))
}

func (m *model) beginTunnelInput(next mode, placeholder string) {
	if m.screen != screenTunnels {
		m.setScreen(screenTunnels)
	}
	if len(m.configs) == 0 {
		m.log("Nenhum perfil para operar")
		return
	}
	m.mode = next
	m.input.SetValue("")
	m.input.Placeholder = placeholder
	m.input.Focus()
}

func (m model) commandItems() []commandItem {
	screenCommand := func(s uiScreen) func(*model) {
		return func(m *model) { m.setScreen(s) }
	}
	return []commandItem{
		{"Dashboard", "F1", screenCommand(screenDashboard)},
		{"Processos", "F2", func(m *model) { m.setScreen(screenProcesses); m.openPicker() }},
		{"Túneis", "F3", screenCommand(screenTunnels)},
		{"Rotas", "F4", screenCommand(screenRoutes)},
		{"WFP", "F5", screenCommand(screenWFP)},
		{"UDP e pacotes", "F6", screenCommand(screenUDP)},
		{"WARP e endpoints", "F7", screenCommand(screenWarp)},
		{"Latência", "F8", screenCommand(screenLatency)},
		{"Diagnóstico", "F9", func(m *model) { m.setScreen(screenDiagnostics); m.showDiag = true }},
		{"Configurações", "F10", screenCommand(screenSettings)},
		{"Importar configuração", "i", func(m *model) {
			m.mode = modeImport
			m.input.SetValue("")
			m.input.Placeholder = `C:\Users\voce\Downloads\vps.conf`
			m.input.Focus()
		}},
		{"Duplicar perfil", "Ctrl+D", func(m *model) {
			m.beginTunnelInput(modeTunnelDuplicate, "novo nome do perfil")
		}},
		{"Renomear perfil", "Ctrl+R", func(m *model) {
			m.beginTunnelInput(modeTunnelRename, "novo nome do perfil")
		}},
		{"Validar perfil", "Ctrl+V", func(m *model) {
			name := selectedConfig(m.configs, m.cursor)
			if _, err := NewTunnelManager(configDir()).Profile(name); err != nil {
				m.log("ERRO na validação de %s: %v", name, err)
			} else {
				m.log("Perfil %s válido; chaves não exibidas", name)
			}
		}},
		{"Conta de teste do [b]", "B", func(m *model) { m.beginProbeInput() }},
		{"Configurar relays", "Ctrl+L", func(m *model) {
			m.mode = modeRelay
			m.input.SetValue(strings.Join(m.settings.CustomRelays, ", "))
			m.input.Placeholder = "host:porta, outro-host:porta (vazio remove)"
			m.input.Focus()
		}},
	}
}

func (m model) filteredCommands() []commandItem {
	query := strings.ToLower(strings.TrimSpace(m.input.Value()))
	if query == "" {
		return m.commandItems()
	}
	var out []commandItem
	for _, c := range m.commandItems() {
		if strings.Contains(strings.ToLower(c.name), query) || strings.Contains(strings.ToLower(c.key), query) {
			out = append(out, c)
		}
	}
	return out
}

func (m model) overlayView() string {
	w := m.width - 8
	if w < 60 {
		w = 60
	}
	var lines []string
	switch m.overlay {
	case overlayPalette:
		lines = append(lines, sBold.Render("Paleta de comandos")+"  "+m.input.View())
		items := m.filteredCommands()
		if len(items) == 0 {
			lines = append(lines, sDim.Render("nenhum comando corresponde à pesquisa"))
		}
		for i, c := range items {
			mark := "  "
			if i == m.palette {
				mark = sSel.Render("▸ ")
			}
			lines = append(lines, mark+sKey.Render(c.key)+"  "+c.name)
		}
		lines = append(lines, sDim.Render("[↑↓] escolher · [Enter] executar · [Esc] fechar"))
	case overlayHelp:
		lines = []string{
			sBold.Render("Ajuda contextual"),
			"F1–F10 módulos · Ctrl+K paleta · / filtrar configs · ? ajuda · Esc voltar",
			"Enter/c conectar · ↑↓/jk navegar · i importar · p processos · w WFP · l apps",
			"s sistema inteiro · n DNS · b melhor rota · v endpoint · h multipath WARP",
			"m espelho DPS · u duplicação · r proporção · f forçar UDP · o/a ordem UDP",
			"x autoteste · g diagnóstico · e exportar · t alvo ping · B conta de teste do b · d remover · q sair",
			sDim.Render("Os atalhos legados continuam ativos; o backend mostrado é o estado real."),
		}
	}
	return sBox.Width(w).Render(strings.Join(lines, "\n"))
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

func startEngine(name string, s Settings) (*Engine, error) {
	conf, err := readConfig(name)
	if err != nil {
		return nil, err
	}
	var mirrorPaths []string
	if exe, err := os.Executable(); err == nil {
		mirrorPaths = append(mirrorPaths, filepath.Join(filepath.Dir(exe), "configs-wireguard-oficial", name))
	}
	return StartEngine(conf, EngineOptions{
		Processes: s.Processes, ProcessRules: s.ProcessRules, PingTarget: s.PingTarget, Mirror: s.Mirror,
		MirrorNoLoopback: s.MirrorNoLoopback,
		UDPDuplicate:     s.UDPDuplicate, UDPOriginals: s.UDPOriginals, UDPCopies: s.UDPCopies, UDPForce: s.UDPForce,
		UDPNewestOut: s.UDPNewestOut, UDPNewestIn: s.UDPNewestIn,
		FullTunnel: s.FullTunnel, NoDNS: s.NoDNS,
		WFP: s.WFP, WFPApps: s.WFPApps, BestEndpoint: s.BestEndpoint, WarpMultipath: s.WarpMultipath, CWBSearch: s.CWBSearch, CustomRelays: s.CustomRelays,
		ConfigPath: filepath.Join(configDir(), name), ConfigPaths: mirrorPaths,
	}, func(f string, a ...any) {
		line := fmt.Sprintf(f, a...)
		diskLog.Printf("%s", line)
		queueProgramLog(logMsg(line))
	})
}

func connectCmd(name string, s Settings) tea.Cmd {
	return func() tea.Msg {
		eng, err := startEngine(name, s)
		return connectedMsg{eng: eng, name: name, err: err}
	}
}

func switchProfileCmd(oldName, newName string, s Settings) tea.Cmd {
	return func() tea.Msg {
		eng, err := startEngine(newName, s)
		if err == nil {
			return connectedMsg{eng: eng, name: newName}
		}
		rollback, rollbackErr := startEngine(oldName, s)
		if rollbackErr != nil {
			return connectedMsg{err: fmt.Errorf("perfil %s falhou: %v; rollback %s também falhou: %w", newName, err, oldName, rollbackErr)}
		}
		return connectedMsg{eng: rollback, name: oldName, err: fmt.Errorf("perfil %s falhou: %v; rollback para %s aplicado", newName, err, oldName)}
	}
}

func pushHist(h []float64, v float64) []float64 {
	h = append(h, v)
	if len(h) > 60 {
		h = h[len(h)-60:]
	}
	return h
}

func (m model) updateOverlay(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.overlay {
	case overlayHelp:
		if msg.String() == "esc" || msg.String() == "?" {
			m.overlay = overlayNone
		}
		return m, nil
	case overlayPalette:
		switch msg.String() {
		case "esc":
			m.overlay = overlayNone
			m.input.Blur()
		case "up", "shift+tab":
			if m.palette > 0 {
				m.palette--
			}
		case "down", "tab":
			items := m.filteredCommands()
			if m.palette < len(items)-1 {
				m.palette++
			}
		case "enter":
			items := m.filteredCommands()
			if m.palette >= 0 && m.palette < len(items) {
				items[m.palette].run(&m)
			}
			m.overlay = overlayNone
			m.input.Blur()
		default:
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			m.palette = clampCursor(m.palette, len(m.filteredCommands()))
			return m, cmd
		}
	}
	return m, nil
}

func screenForFunctionKey(key string) (uiScreen, bool) {
	switch key {
	case "f1":
		return screenDashboard, true
	case "f2":
		return screenProcesses, true
	case "f3":
		return screenTunnels, true
	case "f4":
		return screenRoutes, true
	case "f5":
		return screenWFP, true
	case "f6":
		return screenUDP, true
	case "f7":
		return screenWarp, true
	case "f8":
		return screenLatency, true
	case "f9":
		return screenDiagnostics, true
	case "f10":
		return screenSettings, true
	}
	return screenDashboard, false
}

func (m *model) startSearch() {
	m.mode = modeSearch
	m.input.SetValue(m.filter)
	if m.screen == screenProcesses {
		m.input.Placeholder = "filtrar PID, executável, caminho ou conexão"
	} else {
		m.input.Placeholder = "filtrar configurações"
	}
	m.input.Focus()
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
		if m.screen == screenProcesses {
			m.managed = processManagerSnapshot(m.settings.ProcessRules)
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
		if msg.eng == nil {
			m.log("ERRO ao conectar: %v", msg.err)
			return m, nil
		}
		m.eng, m.engName, m.since = msg.eng, msg.name, time.Now()
		m.prevAt, m.histUp, m.histDown, m.histPing = time.Time{}, nil, nil, nil
		m.settings.LastConfig = msg.name
		_ = saveSettings(m.settings)
		if msg.err != nil {
			m.log("ERRO ao trocar perfil: %v", msg.err)
		} else {
			m.log("Conectado com %s — só o tráfego do AION 2 passa pelo túnel", msg.name)
		}
		return m, nil

	case tea.KeyMsg:
		if m.overlay != overlayNone {
			return m.updateOverlay(msg)
		}
		if m.mode != modeNormal {
			return m.updateInput(msg)
		}
		if s, ok := screenForFunctionKey(msg.String()); ok {
			m.setScreen(s)
			return m, nil
		}
		switch msg.String() {
		case "ctrl+k":
			m.overlay, m.palette = overlayPalette, 0
			m.input.SetValue("")
			m.input.Placeholder = "pesquisar comandos"
			m.input.Focus()
			return m, nil
		case "?":
			m.overlay = overlayHelp
			return m, nil
		case "/":
			m.startSearch()
			return m, nil
		case "tab":
			m.setScreen(uiScreen((int(m.screen) + 1) % len(screenLabels)))
			return m, nil
		case "shift+tab":
			m.setScreen(uiScreen((int(m.screen) + len(screenLabels) - 1) % len(screenLabels)))
			return m, nil
		case "esc":
			m.backScreen()
			return m, nil
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
			if len(m.configs) == 0 {
				m.log("Importe uma config primeiro ([i])")
				return m, nil
			}
			name := m.configs[m.cursor]
			if m.eng != nil {
				if name == m.engName {
					m.eng.Close()
					m.eng = nil
					m.log("Desconectado")
					return m, nil
				}
				oldName := m.engName
				m.eng.Close()
				m.eng = nil
				m.connecting = true
				m.log("Trocando %s por %s…", oldName, name)
				return m, switchProfileCmd(oldName, name, m.settings)
			}
			m.connecting = true
			m.log("Conectando com %s…", name)
			return m, connectCmd(name, m.settings)
		case "i":
			m.mode = modeImport
			m.input.SetValue("")
			m.input.Placeholder = `C:\Users\voce\Downloads\vps.conf  (pode arrastar o arquivo para cá)`
			m.input.Focus()
		case "p":
			m.mode = modeProcs
			m.input.SetValue(formatProcessRules(m.settings))
			m.input.Placeholder = "Aion2.exe, Discord.exe=BYPASS, malware.exe=BLOCK"
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
			m.mode = modeEndpointPick
			m.epCursor = m.endpointPickStart()
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
				m.log("Melhor endpoint LIGADO — procura endpoints com o programa rodando; o handshake é testado com uma conta WARP gratuita separada (escolha o perfil com [B]), sem derrubar a sessão; sem conta de teste, só testa com o jogo parado")
			} else {
				m.log("Melhor endpoint DESLIGADO — usa o endpoint da config; [v] continua disponível para troca manual")
			}
		case "B":
			m.beginProbeInput()
			return m, nil
		case "h":
			m.settings.WarpMultipath = !m.settings.WarpMultipath
			_ = saveSettings(m.settings)
			if m.settings.WarpMultipath {
				m.log("Multipath WARP LIGADO — vale na próxima conexão; pode gerar saídas públicas diferentes")
			} else {
				m.log("Multipath WARP DESLIGADO — uma sessão por padrão")
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
	if m.mode == modeEndpointPick {
		return m.updateEndpointPick(msg)
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
			rules, procs, err := parseProcessRules(v)
			if err != nil {
				m.log("ERRO nas regras: %v", err)
				return m, nil
			}
			if len(rules) == 0 {
				rules, procs, _ = parseProcessRules(strings.Join(defaultProcesses, ", "))
			}
			m.settings.Processes = procs
			m.settings.ProcessRules = rules
			_ = saveSettings(m.settings)
			if m.eng != nil {
				m.eng.SetProcessRules(rules, procs)
			}
			m.log("Regras de processo: %s", formatProcessRules(m.settings))
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
		case modeTunnelDuplicate:
			source := selectedConfig(m.configs, m.cursor)
			if err := NewTunnelManager(configDir()).Duplicate(source, v); err != nil {
				m.log("ERRO ao duplicar %s: %v", source, err)
			} else {
				m.configs = listConfigs()
				if name, err := profileFilename(v); err == nil {
					for i, config := range m.configs {
						if config == name {
							m.cursor = i
							break
						}
					}
				}
				m.log("Perfil duplicado: %s", v)
			}
		case modeTunnelRename:
			source := selectedConfig(m.configs, m.cursor)
			if m.eng != nil && source == m.engName {
				m.log("Desconecte o perfil antes de renomeá-lo")
				break
			}
			if err := NewTunnelManager(configDir()).Rename(source, v); err != nil {
				m.log("ERRO ao renomear %s: %v", source, err)
			} else {
				m.configs = listConfigs()
				if name, err := profileFilename(v); err == nil {
					for i, config := range m.configs {
						if config == name {
							m.cursor = i
							break
						}
					}
				}
				m.log("Perfil renomeado: %s → %s", source, v)
			}
		case modeProbeFile:
			m.applyProbeInput(v)
		case modeRelay:
			relays, err := parseRelayEndpoints(v)
			if err != nil {
				m.log("ERRO nos relays: %v", err)
				return m, nil
			}
			m.settings.CustomRelays = relays
			_ = saveSettings(m.settings)
			if len(relays) == 0 {
				m.log("Relays próprios removidos")
			} else {
				m.log("%d relay(s) próprio(s) salvo(s); medição começa na próxima conexão", len(relays))
			}
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
		case modeSearch:
			m.filter = v
			if m.screen == screenProcesses {
				m.log("Filtro de processos: %s", m.filter)
			} else {
				if m.filter != "" {
					for i, name := range m.configs {
						if strings.Contains(strings.ToLower(name), strings.ToLower(m.filter)) {
							m.cursor = i
							break
						}
					}
				}
				if m.filter == "" {
					m.log("Filtro limpo")
				} else {
					m.log("Filtro de configurações: %s", m.filter)
				}
			}
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
	if p.Jitter > 0 {
		s += sDim.Render(fmt.Sprintf("  jitter %v", p.Jitter.Round(time.Millisecond)))
	}

	return s
}
func telemetrySummary(s Stats) string {
	cpu := "N/A"
	if s.Telemetry.CPUAvailable {
		cpu = fmt.Sprintf("%.1f%%", s.Telemetry.CPUPercent)
	}
	return fmt.Sprintf("CPU %s · memória %s · goroutines %d",
		cpu, fmtBytes(s.Telemetry.MemoryBytes), s.Telemetry.Goroutines)
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
	return lipgloss.NewStyle().Foreground(cYellow).Render(fmt.Sprintf("%s · enviadas %d · perdas %d · erros %d · forcar %v", udpRatioLabel(s.UDPOriginals, s.UDPCopies), s.UDPDupSent, s.UDPDupDropped, s.UDPDupErrors, s.UDPForce))
}

func udpPathsStatus(paths []udpPathStatus) string {
	parts := make([]string, 0, len(paths))
	for i, p := range paths {
		status := "sem resposta"
		if p.Active {
			status = "ok"
			if p.RTT > 0 {
				status = p.RTT.Round(time.Millisecond).String()
			}
			if p.Age > 0 {
				status += "/" + p.Age.Round(time.Second).String()
			}
		}
		parts = append(parts, fmt.Sprintf("%d:%s (%s)", i+1, p.Endpoint, status))
	}
	return strings.Join(parts, " · ")
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
	if m.overlay != overlayNone {
		return m.overlayView()
	}
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
	header := title + strings.Repeat(" ", gap) + status + "\n" + m.navTabs()

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
		config := sBold.Render(m.engName) + sDim.Render("  · ativo há "+time.Since(m.since).Round(time.Second).String())
		if level >= 3 && len(s.Paths) > 1 {
			config += sDim.Render("  · handshake ") + hs
		}
		stat = append(stat,
			row("Config", config),
			row("Endpoint", s.Endpoint+sDim.Render("   túnel ")+s.TunnelAddr+sDim.Render("   [v] troca")),
			row("Saída", exitStatus(s.Exit)),
		)
		if level < 3 {
			stat = append(stat, row("Backend", m.backendLabel()), row("Estados", stateSummary(s)))
		}
		if level < 3 || len(s.Paths) <= 1 {
			stat = append(stat, row("Handshake", hs))
		}
		stat = append(stat, row(procLabel, procs))
		if len(s.Paths) > 1 {
			stat = append(stat, row("Caminhos", "UDP "+udpPathsStatus(s.Paths)))
		}
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
			br = lipgloss.NewStyle().Foreground(cGreen).Render("ligado") + sDim.Render(" ([b] desliga) · descobre e confirma candidatos após conectar")
		}
		stat = append(stat, row("Melhor rota", br))
		mp := sDim.Render("desligado ([h] liga)")
		if m.settings.WarpMultipath {
			mp = lipgloss.NewStyle().Foreground(cYellow).Render("ligado (experimental)  ([h] desliga)")
		}
		stat = append(stat, row("Multipath WARP", mp))
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
		if m.filter != "" && !strings.Contains(strings.ToLower(c), strings.ToLower(m.filter)) {
			continue
		}
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
	if len(cfg) == 0 && m.filter != "" {
		cfg = append(cfg, sDim.Render("nenhuma configuração corresponde ao filtro"))
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
	if m.screen != screenDashboard {
		parts = append(parts, box(screenLabels[m.screen], m.moduleLines()))
	}
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
		foot = sBold.Render("Regras (nome ou nome=POLICY): ") + m.input.View() + sDim.Render("  TUNNEL/BYPASS/BLOCK/DEFAULT")
	case modePing:
		foot = sBold.Render("IP para ping no túnel: ") + m.input.View()
	case modeUDPCopies:
		foot = sBold.Render("Proporcao UDP (X = 1:X, X:X = rajada; X 1..8): ") + m.input.View() + sDim.Render("  [Enter] ok  [Esc] cancelar")
	case modeEndpoint:
		foot = sBold.Render("Novo endpoint (IP ou IP:porta): ") + m.input.View() + sDim.Render("  [Enter] ok  [Esc] cancelar")
	case modeTunnelDuplicate:
		foot = sBold.Render("Novo nome do perfil: ") + m.input.View() + sDim.Render("  [Enter] ok  [Esc] cancelar")
	case modeTunnelRename:
		foot = sBold.Render("Novo nome do perfil: ") + m.input.View() + sDim.Render("  [Enter] ok  [Esc] cancelar")
	case modeRelay:
		foot = sBold.Render("Relays (host:porta, ...): ") + m.input.View() + sDim.Render("  [Enter] ok  [Esc] cancelar")
	case modeProbeFile:
		foot = sBold.Render("Conta de teste do [b] (.conf; vazio remove): ") + m.input.View() + sDim.Render("  [Enter] ok  [Esc] cancelar")
	case modeSearch:
		foot = sBold.Render("Filtro: ") + m.input.View() + sDim.Render("  [Enter] aplicar  [Esc] cancelar")
	case modeDelete:
		foot = lipgloss.NewStyle().Foreground(cRed).Bold(true).Render(
			fmt.Sprintf("Remover %s? [s/y] sim  [qualquer tecla] não", m.configs[m.cursor]))
	case modeWFPApps:
		foot = m.wfpPicker(w)
	case modeEndpointPick:
		foot = m.endpointPicker(w)
	default:
		k := func(key, desc string) string { return sKey.Render("["+key+"]") + " " + sDim.Render(desc) }
		act := "conectar"
		if m.eng != nil {
			act = "desconectar"
		}
		foot = lipgloss.NewStyle().Width(w).Render(strings.Join([]string{
			k("F1–F10", "módulos"), k("Ctrl+K", "comandos"), k("/", "filtrar"), k("?", "ajuda"),
			k("Enter", act), k("i", "importar"), k("↑↓", "escolher"), k("p", "processos"),
			k("w", "WFP"), k("l", "apps WFP"),
			k("s", "sistema inteiro"), k("n", "DNS túnel"), k("b", "melhor rota"), k("B", "conta de teste do b"), k("v", "trocar endpoint"), k("m", "espelho DPS"), k("u", "dup UDP"), k("r", "proporcao"), k("f", "forcar UDP"), k("o", "envio recente"), k("a", "chegada recente"), k("x", "autoteste"), k("g", "diagnóstico"), k("e", "exportar p/ WG oficial"), k("t", "alvo do ping"), k("d", "remover"), k("q", "sair"),
		}, "  "))
	}

	if m.mode == modeNormal && level >= 2 {
		foot = sDim.Render("F1–F10 módulos · Ctrl+K comandos · / filtro · ? ajuda · Tab navega · Enter conecta · q sai")
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
