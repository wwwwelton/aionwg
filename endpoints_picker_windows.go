//go:build windows

package main

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"strings"
)

// endpointPickRows is what the picker shows: the known endpoints plus a last
// item that opens the free-text input for any other address.
func (m model) endpointPickRows() []endpointRow {
	if m.eng == nil {
		return nil
	}
	return m.eng.endpointRows()
}

// endpointPickStart puts the cursor on the endpoint in use.
func (m model) endpointPickStart() int {
	for i, r := range m.endpointPickRows() {
		if r.current {
			return i
		}
	}
	return 0
}

// endpointPicker renders the endpoint list with address, location and ping.
func (m model) endpointPicker(w int) string {
	rows := m.endpointPickRows()
	cur := clampCursor(m.epCursor, len(rows)+1)
	var lines []string
	for i, r := range rows {
		ping := sDim.Render("sem medição")
		if r.rtt > 0 {
			ping = fmt.Sprintf("%d ms", r.rtt.Milliseconds())
		}
		tag := ""
		if r.current {
			tag = "  [em uso]"
		}
		if r.path != "" {
			tag += "  [" + r.path + "]"
		}
		tag = sDim.Render(tag)
		line := fmt.Sprintf("%-22s %-26s %s", r.ep.String(), r.label, ping) + tag
		if i == cur {
			lines = append(lines, sSel.Render("▸ ")+sSel.Render(line))
		} else {
			lines = append(lines, "  "+line)
		}
	}
	other := "digitar outro IP…"
	if cur == len(rows) {
		lines = append(lines, sSel.Render("▸ "+other))
	} else {
		lines = append(lines, "  "+sDim.Render(other))
	}
	if m.eng != nil {
		if cands := m.eng.endpointCandidates(rows); len(cands) > 0 {
			lines = append(lines, "", sDim.Render(fmt.Sprintf("sendo buscados (%d, ainda sem handshake):", len(cands))))
			for _, ep := range cands {
				lines = append(lines, sDim.Render("    "+ep.String()))
			}
		}
	}
	title := fmt.Sprintf("Endpoints — %d conhecido(s)  [↑↓] mover  [Enter] trocar  [Esc] fechar", len(rows))
	if len(rows) == 0 {
		lines = append([]string{sDim.Render("(nenhum endpoint validado ainda)")}, lines...)
	}
	return sBox.Width(w - 4).Render(sBold.Render(title) + "\n" + strings.Join(lines, "\n"))
}

// updateEndpointPick handles keys in the endpoint picker. Enter on a row
// switches the tunnel to that endpoint; the last item asks for a typed address.
func (m model) updateEndpointPick(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	rows := m.endpointPickRows()
	switch msg.String() {
	case "esc", "q":
		m.mode = modeNormal
	case "up", "k":
		if m.epCursor > 0 {
			m.epCursor--
		}
	case "down", "j":
		if m.epCursor < len(rows) {
			m.epCursor++
		}
	case "enter":
		if m.epCursor >= len(rows) {
			m.mode = modeEndpoint
			m.input.SetValue("")
			m.input.Placeholder = "IP ou IP:porta (só nesta sessão; o .conf não muda)"
			m.input.Focus()
			return m, nil
		}
		m.mode = modeNormal
		r := rows[m.epCursor]
		if r.current || m.eng == nil {
			return m, nil
		}
		eng := m.eng
		m.log("Trocando endpoint para %s…", r.ep)
		return m, func() tea.Msg {
			if err := eng.SetEndpoint(r.ep); err != nil {
				line := fmt.Sprintf("ERRO rota: %v", err)
				diskLog.Printf("%s", line)
				queueProgramLog(logMsg(line))
			}
			return nil
		}
	}
	return m, nil
}
