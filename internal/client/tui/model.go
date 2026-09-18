package tui

import (
	"context"
	"fmt"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type state int

const (
	stateList state = iota
	stateDetail
	stateConfirmDelete
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Padding(0, 1)
	detailStyle = lipgloss.NewStyle().Padding(1, 2)
	statusStyle = lipgloss.NewStyle().Faint(true).Padding(0, 1)
	dangerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9")).Padding(1, 2)
)

type model struct {
	ctx      context.Context
	deps     Deps
	state    state
	list     list.Model
	selected secretItem
	status   string
	busy     bool
}

type syncDoneMsg struct {
	summary string
	err     error
}

type deleteDoneMsg struct {
	err error
}

type reloadedMsg struct {
	items []secretItem
	err   error
}

func newModel(ctx context.Context, deps Deps) (*model, error) {
	items, err := loadItems(deps)
	if err != nil {
		return nil, err
	}

	l := list.New(toListItems(items), list.NewDefaultDelegate(), 0, 0)
	l.Title = "GophKeeper"
	l.SetShowStatusBar(false)

	return &model{ctx: ctx, deps: deps, state: stateList, list: l, status: "enter: открыть · s: синхронизация · d: удалить · q: выход"}, nil
}

func toListItems(items []secretItem) []list.Item {
	out := make([]list.Item, len(items))
	for i, item := range items {
		out[i] = item
	}
	return out
}

func (m *model) Init() tea.Cmd { return nil }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetSize(msg.Width, msg.Height-2)
		return m, nil

	case syncDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.status = "Синхронизация не удалась: " + msg.err.Error()
			return m, nil
		}
		m.status = "Синхронизация: " + msg.summary
		return m, m.reload()

	case deleteDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.status = "Удаление не удалось: " + msg.err.Error()
			m.state = stateList
			return m, nil
		}
		m.status = "Запись удалена"
		m.state = stateList
		return m, m.reload()

	case reloadedMsg:
		if msg.err != nil {
			m.status = "Ошибка чтения кэша: " + msg.err.Error()
			return m, nil
		}
		m.list.SetItems(toListItems(msg.items))
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m *model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.state {
	case stateDetail:
		switch msg.String() {
		case "esc", "enter", "q":
			m.state = stateList
		}
		return m, nil

	case stateConfirmDelete:
		switch msg.String() {
		case "y":
			m.busy = true
			return m, m.deleteSelected()
		case "n", "esc":
			m.state = stateList
		}
		return m, nil
	}

	if m.list.FilterState() == list.Filtering {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "enter":
		if item, ok := m.list.SelectedItem().(secretItem); ok {
			m.selected = item
			m.state = stateDetail
		}
		return m, nil
	case "d":
		if item, ok := m.list.SelectedItem().(secretItem); ok {
			m.selected = item
			m.state = stateConfirmDelete
		}
		return m, nil
	case "s":
		if m.busy {
			return m, nil
		}
		m.busy = true
		m.status = "Синхронизация..."
		return m, m.runSync()
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m *model) View() string {
	switch m.state {
	case stateDetail:
		body := formatDetail(m.deps.Key, m.selected.rec, m.selected.meta)
		return titleStyle.Render("Просмотр секрета") + "\n" +
			detailStyle.Render(body) + "\n" +
			statusStyle.Render("esc: назад")
	case stateConfirmDelete:
		return dangerStyle.Render(fmt.Sprintf("Удалить запись %q? (y/n)", m.selected.Title()))
	default:
		return m.list.View() + "\n" + statusStyle.Render(m.status)
	}
}

func (m *model) runSync() tea.Cmd {
	return func() tea.Msg {
		summary, err := m.deps.Sync(m.ctx)
		return syncDoneMsg{summary: summary, err: err}
	}
}

func (m *model) deleteSelected() tea.Cmd {
	id := m.selected.rec.ID
	return func() tea.Msg {
		return deleteDoneMsg{err: m.deps.Delete(m.ctx, id)}
	}
}

func (m *model) reload() tea.Cmd {
	return func() tea.Msg {
		items, err := loadItems(m.deps)
		return reloadedMsg{items: items, err: err}
	}
}
