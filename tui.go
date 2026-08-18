package main

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	tuiStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#888"))
	redStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#e55"))
	goldStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#f0b000"))
	greenStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#0f0"))
	whiteStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#fff"))
	dimStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#555"))

	headerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#f0b000")).Bold(true)
	boxStyle    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#333")).Padding(0, 1)
	titleStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#f0b000")).Bold(true).Underline(true)
)

type tuiModel struct {
	width, height int
	cmdInput      string
	output        []string
	lastUpdate    time.Time
}

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(tickCmd(), tickCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(1*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type tickMsg time.Time

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "enter":
			cmd := strings.TrimSpace(m.cmdInput)
			if cmd != "" {
				result := ejecutarSistema(cmd)
				m.output = append(m.output, goldStyle.Render("$ ")+cmd)
				for _, line := range strings.Split(strings.TrimSpace(result), "\n") {
					if len(line) > 0 {
						m.output = append(m.output, "  "+line)
					}
				}
				if len(m.output) > 100 {
					m.output = m.output[len(m.output)-100:]
				}
			}
			m.cmdInput = ""
		case "backspace":
			if len(m.cmdInput) > 0 {
				m.cmdInput = m.cmdInput[:len(m.cmdInput)-1]
			}
		default:
			if len(msg.String()) == 1 {
				m.cmdInput += msg.String()
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tickMsg:
		m.lastUpdate = time.Time(msg)
		return m, tickCmd()
	}
	return m, nil
}

func (m tuiModel) View() string {
	if m.width < 80 {
		return "Terminal too small (min 80 cols)"
	}

	header := goldStyle.Render("▄▄▄▄▄") + whiteStyle.Render("  NEXTC ") + goldStyle.Render("▄▄▄▄▄")

	attackMu.Lock()
	activeAttacks := 0
	var attackLines []string
	now := time.Now()
	for _, att := range attackList {
		if att.Running {
			activeAttacks++
		}
		elapsed := now.Sub(att.Start).Seconds()
		pps := int64(0)
		if elapsed > 0 {
			pps = int64(float64(att.Stats.Sent) / elapsed)
		}
		status := redStyle.Render("●")
		if !att.Running {
			status = dimStyle.Render("○")
		}
		attackLines = append(attackLines, fmt.Sprintf("%s %s:%d %s %s %dK pkt %dK pps",
			status, att.Target, att.Port, whiteStyle.Render(att.Method),
			dimStyle.Render(fmt.Sprintf("%d thr", att.Threads)),
			att.Stats.Sent/1000, pps/1000))
	}
	attackMu.Unlock()

	nodesMu.Lock()
	nodeCount := len(nodes) + 1
	nodesMu.Unlock()

	statsLine := fmt.Sprintf("%s %s %s",
		greenStyle.Render(fmt.Sprintf("⚡ %d attacks", activeAttacks)),
		goldStyle.Render(fmt.Sprintf("🔗 %d nodes", nodeCount)),
		whiteStyle.Render(time.Now().Format("15:04:05")))

	leftCol := lipgloss.JoinVertical(lipgloss.Left,
		titleStyle.Render(" STATUS"),
		dimStyle.Render(strings.Repeat("─", 30)),
		statsLine,
		"",
		titleStyle.Render(" ATTACKS"),
		dimStyle.Render(strings.Repeat("─", 30)),
	)

	if len(attackLines) > 0 {
		leftCol += "\n" + strings.Join(attackLines, "\n")
	} else {
		leftCol += "\n" + dimStyle.Render("  No active attacks")
	}

	rightWidth := m.width - 45
	if rightWidth < 30 {
		rightWidth = 30
	}

	var outputLines []string
	start := 0
	maxOut := m.height - 12
	if maxOut < 5 {
		maxOut = 5
	}
	if len(m.output) > maxOut {
		start = len(m.output) - maxOut
	}
	for i := start; i < len(m.output); i++ {
		outputLines = append(outputLines, m.output[i])
	}

	rightCol := titleStyle.Render(" OUTPUT") + "\n" +
		dimStyle.Render(strings.Repeat("─", rightWidth)) + "\n" +
		strings.Join(outputLines, "\n")

	leftBox := boxStyle.Width(38).Height(m.height - 6).Render(leftCol)
	rightBox := boxStyle.Width(rightWidth + 2).Height(m.height - 6).Render(rightCol)

	main := lipgloss.JoinHorizontal(lipgloss.Top, leftBox, rightBox)

	cmdPrompt := goldStyle.Render("$ ") + m.cmdInput + whiteStyle.Render("█")

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		"",
		main,
		"",
		cmdPrompt,
		dimStyle.Render("ctrl+c quit | type command + enter"),
	)
}
