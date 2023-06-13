package permissions

import (
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nats-io/jwt/v2"
	"github.com/sandstorm/natsCtl/cli/common"
	"strings"
)

const (
	helpHeight = 8
)

var (
	cursorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("212"))

	cursorLineStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("57")).
			Foreground(lipgloss.Color("230"))

	placeholderStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("238"))

	endOfBufferStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("235"))

	focusedPlaceholderStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("99"))

	focusedBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("238"))

	blurredBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.HiddenBorder())
)

type keymap = struct {
	next, prev, quit, reply key.Binding
}

func newTextarea(initialValue string) textarea.Model {
	t := textarea.New()
	t.Prompt = ""
	t.Placeholder = "Type something"
	t.ShowLineNumbers = true
	t.Cursor.Style = cursorStyle
	t.FocusedStyle.Placeholder = focusedPlaceholderStyle
	t.BlurredStyle.Placeholder = placeholderStyle
	t.FocusedStyle.CursorLine = cursorLineStyle
	t.FocusedStyle.Base = focusedBorderStyle
	t.BlurredStyle.Base = blurredBorderStyle
	t.FocusedStyle.EndOfBuffer = endOfBufferStyle
	t.BlurredStyle.EndOfBuffer = endOfBufferStyle
	t.KeyMap.DeleteWordBackward.SetEnabled(false)
	t.KeyMap.LineNext = key.NewBinding(key.WithKeys("down"))
	t.KeyMap.LinePrevious = key.NewBinding(key.WithKeys("up"))
	t.SetValue(initialValue)
	t.Blur()
	return t
}

type Model struct {
	roleName   string
	width      int
	height     int
	keymap     keymap
	help       help.Model
	pubInput   textarea.Model
	subInput   textarea.Model
	focus      focused
	AllowReply bool
}

type focused int64

const (
	FocusPub focused = iota
	FocusSub
)
const totalFocusStates = 2

func (f focused) next() focused {
	return (f + 1) % totalFocusStates
}

func (f focused) prev() focused {
	next := f - 1
	if next < 0 {
		next = totalFocusStates - 1
	}
	return next
}

func NewModel(scopedSigningKey *jwt.UserScope) Model {
	m := Model{
		roleName: scopedSigningKey.Role,
		pubInput: newTextarea(
			strings.Join(scopedSigningKey.Template.Pub.Allow, "\n"),
		),
		subInput: newTextarea(
			strings.Join(removePrivateInbox(scopedSigningKey.Template.Sub.Allow), "\n"),
		),
		AllowReply: scopedSigningKey.Template.Resp != nil,
		help:       help.New(),
		keymap: keymap{
			next: key.NewBinding(
				key.WithKeys("tab"),
				key.WithHelp("tab", "next"),
			),
			prev: key.NewBinding(
				key.WithKeys("shift+tab"),
				key.WithHelp("shift+tab", "prev"),
			),
			quit: key.NewBinding(
				key.WithKeys("esc", "ctrl+c"),
				key.WithHelp("esc", "quit"),
			),
			reply: key.NewBinding(
				key.WithKeys("ctrl+r"),
				key.WithHelp("ctrl+r", "toggle reply"),
			),
		},
	}
	m.pubInput.Focus()
	return m
}

func (m Model) Init() tea.Cmd {
	return textarea.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keymap.quit):
			m.pubInput.Blur()
			m.subInput.Blur()
			return m, tea.Quit
		case key.Matches(msg, m.keymap.next):
			m.focus = m.focus.next()
			cmds = append(cmds, m.updateFocus())
		case key.Matches(msg, m.keymap.prev):
			m.focus = m.focus.prev()
			cmds = append(cmds, m.updateFocus())
		case key.Matches(msg, m.keymap.reply):
			m.AllowReply = !m.AllowReply
		}
	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.width = msg.Width
		m.sizeInputs()
	}

	newModel, cmd := m.pubInput.Update(msg)
	m.pubInput = newModel
	cmds = append(cmds, cmd)

	newModel, cmd = m.subInput.Update(msg)
	m.subInput = newModel
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m *Model) sizeInputs() {
	m.pubInput.SetHeight(m.height - helpHeight)
	m.pubInput.SetWidth(m.width / 2)

	m.subInput.SetHeight(m.height - helpHeight - 2)
	m.subInput.SetWidth(m.width / 2)
}

var bold = lipgloss.NewStyle().
	Bold(true)

func (m Model) View() string {
	help := m.help.ShortHelpView([]key.Binding{
		m.keymap.next,
		m.keymap.prev,
		m.keymap.reply,
		m.keymap.quit,
	})

	allowReply := bold.Render(" [ ]") + " replies " + bold.Render("denied")
	if m.AllowReply {
		allowReply = bold.Render(" [x]") + " replies " + bold.Render("allowed")
	}

	// pterm.Println("  comma separated list of subject patterns, f.e. k3s2021.pretix-prod.api.foo")
	// pterm.Printfln("  %s matches a single token in the subject", bold.Sprint('*'))
	// pterm.Printfln("  %s matches one or more tokens, and can only appear at the end of the subject", bold.Sprint('>'))
	// TODO: Templating.

	title := bold.Render("Role: "+m.roleName) + "\n\n"
	return title + lipgloss.JoinHorizontal(lipgloss.Top, bold.Render("PUBLISH")+"\n"+m.pubInput.View(), bold.Render("SUBSCRIBE")+"\n"+m.subInput.View()+"\n"+allowReply) + "\n\n" + help
}

func (m *Model) updateFocus() tea.Cmd {
	var cmd tea.Cmd
	if m.focus == FocusPub {
		cmd = m.pubInput.Focus()
	} else {
		m.pubInput.Blur()
	}

	if m.focus == FocusSub {
		cmd = m.subInput.Focus()
	} else {
		m.subInput.Blur()
	}
	return cmd
}

func (m Model) Pub() []string {
	lines := strings.Split(m.pubInput.Value(), "\n")
	return removeEmptyLinesOrLinesWithComment(lines)
}

func (m Model) Sub() []string {
	lines := strings.Split(m.subInput.Value(), "\n")
	return removeEmptyLinesOrLinesWithComment(lines)
}

func removeEmptyLinesOrLinesWithComment(lines []string) []string {
	var out []string
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" && trimmed[0] != '#' {
			out = append(out, trimmed)
		}
	}
	return out
}

func removePrivateInbox(allow jwt.StringList) []string {
	var out []string
	for _, line := range allow {
		if line != common.PrivateInboxSelector {
			out = append(out, line)
		}
	}
	return out
}
