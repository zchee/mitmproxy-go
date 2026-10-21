// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package flowview renders detached flow messages and their connection details.
package flowview

import (
	"context"
	"fmt"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/contentviews/highlight"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

// Model owns one flow detail widget. Its snapshot must be detached from live state.
type Model struct {
	ctx                context.Context
	host               contract.Host
	snapshot           contract.Snapshot
	palette            style.Palette
	width, height, tab int
	header, lines      []string
	search             []Search
	searching          bool
	input, status      string
	errs               []error
}

var _ contract.Widget = (*Model)(nil)

// New creates a widget whose live operations run through host from commands.
func New(ctx context.Context, host contract.Host) *Model {
	palette, _ := style.NewPalette("solarized_dark", true)
	return &Model{ctx: ctx, host: host, palette: palette, width: 80, height: 22}
}

// SetSnapshot installs owned display data, preserving each tab's search position.
func (m *Model) SetSnapshot(s contract.Snapshot) {
	if m.snapshot.FocusID != s.FocusID {
		m.search = nil
		m.tab = 0
		m.searching, m.input, m.status = false, "", ""
	}
	m.snapshot = s
	name, transparent := "solarized_dark", true
	for _, option := range s.Options {
		if option.Name() == "console_palette" {
			name, _ = option.Current().(string)
		}
		if option.Name() == "console_palette_transparent" {
			transparent, _ = option.Current().(bool)
		}
	}
	if p, err := style.NewPalette(name, transparent); err == nil {
		m.palette = p
	}
	tabs := Tabs(s.Focused)
	if w, ok := s.Control.Current("flowview", false); ok {
		for i, tab := range tabs {
			if tab == w.Tab || tabName(tab) == w.Tab {
				m.tab = i
				break
			}
		}
	}
	if len(tabs) != len(m.search) {
		m.search = make([]Search, len(tabs))
	}
	m.tab = min(m.tab, max(0, len(tabs)-1))
	m.render()
}

// Resize changes the available body dimensions.
func (m *Model) Resize(width, height int) {
	m.width, m.height = max(1, width), max(1, height)
	m.render()
}

// Errors returns contentview/highlight failures from the last render.
func (m *Model) Errors() []error { return append([]error(nil), m.errs...) }

// Tabs returns upstream tab labels, including interception state.
func Tabs(f flow.Flow) []string {
	if f == nil {
		return nil
	}
	request, response := "Request", "Response"
	intercepted := f.Common().Intercepted()
	switch f := f.(type) {
	case *flow.HTTPFlow:
		if intercepted && f.Response == nil {
			request += " intercepted"
		}
		if intercepted && f.Response != nil && (f.WebSocket == nil || len(f.WebSocket.Messages) == 0) {
			response += " intercepted"
		}
		if f.WebSocket != nil {
			messages := "WebSocket Messages"
			if intercepted && len(f.WebSocket.Messages) > 0 {
				messages += " intercepted"
			}
			return []string{request, response, messages, "Detail"}
		}
		return []string{request, response, "Detail"}
	case *flow.TCPFlow:
		return []string{"TCP Stream", "Detail"}
	case *flow.UDPFlow:
		return []string{"UDP Stream", "Detail"}
	case *flow.DNSFlow:
		if intercepted {
			if f.Response == nil {
				request += " intercepted"
			} else {
				response += " intercepted"
			}
		}
		return []string{request, response, "Detail"}
	}
	return []string{"Detail"}
}

func tabName(label string) string { return strings.TrimSuffix(label, " intercepted") }

func (m *Model) mode() string {
	if value := m.snapshot.ViewSettings[fmt.Sprintf("flowview_mode_%d", m.tab)]; value != "" {
		return value
	}
	return m.snapshot.Detail.DefaultContentView
}

func (m *Model) render() {
	m.header, m.lines, m.errs = nil, nil, nil
	defer func() {
		// A newline-free body can exceed the formatter's logical-line cutoff.
		for i, line := range m.lines {
			m.lines[i] = ansi.Truncate(line, m.width*m.height, "…")
		}
		if m.tab < len(m.search) {
			m.search[m.tab].Focus = min(m.search[m.tab].Focus, max(0, len(m.lines)-1))
		}
	}()
	f := m.snapshot.Focused
	tabs := Tabs(f)
	if len(tabs) == 0 {
		return
	}
	showHost := false
	for _, option := range m.snapshot.Options {
		if option.Name() == "showhost" {
			showHost, _ = option.Current().(bool)
			break
		}
	}
	row := style.FormatFlow(f, "detailview", showHost, m.width, false)
	for line := range strings.SplitSeq(row.Text, "\n") {
		m.header = append(m.header, m.palette.Style("text").Render(style.Fit(line, m.width)))
	}
	if tabs[m.tab] == "Detail" {
		m.lines = Detail(f, m.palette)
		return
	}
	switch f := f.(type) {
	case *flow.HTTPFlow:
		switch m.tab {
		case 0:
			if f.Request != nil {
				m.http(&f.Request.Message, f.Request)
			}
		case 1:
			if f.Response == nil {
				m.lines = []string{"", m.palette.Render("highlight", "No response. Press e and edit any aspect to add one.")}
				return
			}
			m.http(&f.Response.Message, f.Response)
		case 2:
			for _, message := range f.WebSocket.Messages {
				m.stream(message, message.FromClient)
			}
			if f.WebSocket.ClosedByClient != nil {
				code, reason := 0, ""
				if f.WebSocket.CloseCode != nil {
					code = *f.WebSocket.CloseCode
				}
				if f.WebSocket.CloseReason != nil {
					reason = *f.WebSocket.CloseReason
				}
				tag := "error"
				if code == 1000 || code == 1001 || code == 1005 {
					tag = "alert"
				}
				m.lines = append(m.lines, m.palette.Render(tag, fmt.Sprintf("Connection closed: %d %s", code, reason)))
			}
			m.finishStream()
		}
	case *flow.TCPFlow:
		for _, message := range f.Messages {
			m.stream(message, message.FromClient)
		}
		m.finishStream()
	case *flow.UDPFlow:
		for _, message := range f.Messages {
			m.stream(message, message.FromClient)
		}
		m.finishStream()
	case *flow.DNSFlow:
		message, part := f.Request, "request"
		if m.tab == 1 {
			message, part = f.Response, "response"
		}
		m.lines = dnsLines(message, part, m.palette)
	}
}

func (m *Model) http(message *httpmsg.Message, input any) {
	keys := make([]string, len(message.Headers))
	keyWidth := 0
	for i, h := range message.Headers {
		keys[i] = strutil.BytesToEscapedStr(h.Name, false, false) + ":"
		keyWidth = max(keyWidth, len(keys[i]))
	}
	keyWidth = min(keyWidth, 30)
	for i, h := range message.Headers {
		keyLines := strings.Split(ansi.Wrap(keys[i], keyWidth, ""), "\n")
		value := strutil.BytesToEscapedStr(h.Value, false, false)
		values := strings.Split(ansi.Wrap(value, max(1, m.width-keyWidth-2), ""), "\n")
		for row := range max(len(keyLines), len(values)) {
			key, value := "", ""
			if row < len(keyLines) {
				key = keyLines[row]
			}
			if row < len(values) {
				value = values[row]
			}
			m.lines = append(m.lines, m.palette.Style("header").Render(style.Fit(key, keyWidth))+"  "+m.palette.Render("text", value))
		}
	}
	description, body, errs := Content(m.snapshot.Focused, input, m.mode(), m.snapshot.Detail, m.palette)
	m.errs = append(m.errs, errs...)
	m.lines = append(m.lines, m.contentStatus(description))
	m.lines = append(m.lines, body...)
}

// Content formats a detached message, preserving missing/empty-body distinctions.
func Content(f flow.Flow, message any, mode string, options contract.DetailOptions, palette style.Palette) (string, []string, []error) {
	var httpMessage *httpmsg.Message
	var request *httpmsg.Request
	switch value := message.(type) {
	case *httpmsg.Request:
		request, httpMessage = value, &value.Message
	case *httpmsg.Response:
		httpMessage = &value.Message
	case *httpmsg.Message:
		httpMessage = value
	}
	if httpMessage != nil {
		if httpMessage.RawContent == nil {
			return "", []string{palette.Render("error", "[content missing]")}, nil
		}
		if len(httpMessage.RawContent) == 0 {
			if request == nil {
				return "", []string{"No content"}, nil
			}
			if len(request.Query()) == 0 {
				return "", []string{"No request content"}, nil
			}
		}
	}
	limit := options.LineCutoff
	if options.FullContents {
		limit = 0
	}
	result := contentviews.PrettifyMessageWithMetadata(message, contentviews.Metadata{Flow: f, ProtobufDefinitions: options.ProtobufDefinitions}, mode, options.Registry, limit)
	var errs []error
	if result.Err != nil {
		errs = append(errs, result.Err)
	}
	chunks, err := highlight.Highlight(result.Text, result.SyntaxHighlight)
	if err != nil {
		errs = append(errs, err)
		chunks = []highlight.Chunk{{Text: result.Text}}
	}
	var body strings.Builder
	for _, chunk := range chunks {
		body.WriteString(palette.Render(chunk.Tag, chunk.Text))
	}
	lines := strings.Split(body.String(), "\n")
	if result.Truncated {
		lines = append(lines, palette.Render("highlight", fmt.Sprintf("Stopped displaying data after %d lines. Press f to load all data.", limit)))
	}
	return strings.TrimSpace(result.ViewName + " " + result.Description), lines, errs
}

func (m *Model) stream(message any, fromClient bool) {
	_, lines, errs := Content(m.snapshot.Focused, message, m.mode(), m.snapshot.Detail, m.palette)
	m.errs = append(m.errs, errs...)
	tag, mark := "to_client", "← "
	if fromClient {
		tag, mark = "from_client", "→ "
	}
	if len(lines) > 0 {
		lines[0] = m.palette.Render(tag, mark) + lines[0]
	}
	m.lines = append(m.lines, lines...)
}

func (m *Model) finishStream() {
	if len(m.lines) == 0 {
		m.lines = []string{m.palette.Render("highlight", "No messages.")}
		return
	}
	if m.snapshot.Focused.Common().Intercepted() {
		i := len(m.lines) - 1
		m.lines[i] = m.palette.Render("intercept", ansi.Strip(m.lines[i]))
	}
	m.lines = append([]string{m.contentStatus(m.mode())}, m.lines...)
}

func (m *Model) contentStatus(description string) string {
	leftWidth, rightWidth := (m.width+1)/2, m.width/2
	left := style.Fit(ansi.Truncate(style.Escape(description), leftWidth, ""), leftWidth)
	right := ansi.Truncate(style.Escape(" [m:"+m.mode()+"]"), rightWidth, "")
	return m.palette.Style("heading").Render(left + strings.Repeat(" ", rightWidth-ansi.StringWidth(right)) + right)
}

func dnsLines(message *dns.Message, part string, palette style.Palette) []string {
	if message == nil {
		return []string{palette.Render("highlight", "No "+part+".")}
	}
	question, answer := "Question", "Answer"
	if message.RecursionDesired {
		question = "Recursive " + question
	}
	if message.RecursionAvailable {
		answer = "Recursive " + answer
	}
	if message.AuthoritativeAnswer {
		answer = "Authoritative " + answer
	}
	lines := []string{question}
	for _, q := range message.Questions {
		lines = append(lines, fmt.Sprintf("  %s %s %s", q.Name, dns.TypeToString(q.Type), dns.ClassToString(q.Class)))
	}
	lines = append(lines, "", answer)
	for i, records := range [][]dns.ResourceRecord{message.Answers, message.Authorities, message.Additionals} {
		if i > 0 {
			lines = append(lines, "", []string{"", "Authority", "Addition"}[i])
		}
		for _, r := range records {
			value := (&dns.Message{Answers: []dns.ResourceRecord{r}}).String()
			lines = append(lines, fmt.Sprintf("  %s %s %s %d %s", r.Name, dns.TypeToString(r.Type), dns.ClassToString(r.Class), r.TTL, value))
		}
	}
	for i := range lines {
		lines[i] = palette.Render("text", lines[i])
	}
	return lines
}

// Update installs tab effects and handles local search and scrolling input.
func (m *Model) Update(msg tea.Msg) (tea.Cmd, bool) {
	tabs := Tabs(m.snapshot.Focused)
	if len(tabs) == 0 {
		return nil, false
	}
	if action, ok := msg.(contract.Action); ok && action.Kind == "tab" {
		m.selectTab(action.Index)
		return nil, true
	}
	if mouse, ok := msg.(tea.MouseClickMsg); ok {
		if mouse.Button != tea.MouseLeft || mouse.Y != len(m.header) || mouse.Y >= m.height || mouse.X < 0 || mouse.X >= m.width {
			return nil, false
		}
		start := 0
		for i, width := range tabWidths(m.width, len(tabs)) {
			if mouse.X < start {
				return nil, false
			}
			if mouse.X < start+width {
				return m.dispatchTab(contract.Action{Kind: "tab", Value: tabName(tabs[i]), Index: i}), true
			}
			start += width + 1
		}
		return nil, false
	}
	key, isKey := msg.(tea.KeyPressMsg)
	name := key.String()
	if action, ok := msg.(contract.Action); ok && action.Kind == "nav" {
		name = action.Value
		switch name {
		case "start":
			name = "home"
		case "next":
			name = "tab"
		}
	} else if !isKey {
		return nil, false
	}
	search := &m.search[m.tab]
	if m.searching {
		switch name {
		case "esc":
			m.searching = false
		case "enter":
			search.Term = m.input
			search.Find(m.lines, false)
			m.searching = false
		case "backspace":
			r := []rune(m.input)
			if len(r) > 0 {
				m.input = string(r[:len(r)-1])
			}
		default:
			m.input += key.Text
		}
		return nil, true
	}
	switch name {
	case "tab", "right", "left":
		direction := "next"
		if name == "left" {
			direction = "prev"
		}
		return m.dispatchTab(contract.Action{Kind: "tab", Value: direction, Index: -1}), true
	case "/":
		m.searching = true
		m.input = ""
		return nil, true
	case "n", "N":
		if !search.Find(m.lines, name == "N") {
			m.status = "Search not found."
		}
		return nil, true
	case "j", "down":
		search.Focus = min(search.Focus+1, max(0, len(m.lines)-1))
		return nil, true
	case "k", "up":
		search.Focus = max(0, search.Focus-1)
		return nil, true
	case "pageup":
		search.Focus = max(0, search.Focus-max(1, m.height-len(m.header)-1))
		return nil, true
	case "pagedown":
		search.Focus = min(max(0, len(m.lines)-1), search.Focus+max(1, m.height-len(m.header)-1))
		return nil, true
	case "g", "home":
		search.Focus = 0
		return nil, true
	case "G", "end":
		search.Focus = max(0, len(m.lines)-1)
		return nil, true
	}
	return nil, false
}

func (m *Model) selectTab(index int) {
	if index >= 0 && index < len(Tabs(m.snapshot.Focused)) {
		m.tab = index
		m.render()
	}
}

func (m *Model) dispatchTab(action contract.Action) tea.Cmd {
	if m.host == nil {
		index := action.Index
		if index < 0 {
			delta := 1
			if action.Value == "prev" {
				delta = -1
			}
			tabs := len(Tabs(m.snapshot.Focused))
			index = (m.tab + tabs + delta) % tabs
		}
		m.selectTab(index)
		return nil
	}
	return func() tea.Msg {
		if err := m.host.Dispatch(m.ctx, action); err != nil {
			return contract.ErrorMsg{Source: "flow view", Err: err}
		}
		return nil
	}
}

func tabWidths(width, count int) []int {
	count = min(count, (width+1)/2)
	widths := make([]int, count)
	remaining := width - max(0, count-1)
	// Equal-weight columns round half up, then redistribute the remaining cells.
	for i := range widths {
		columns := count - i
		widths[i] = (2*remaining + columns) / (2 * columns)
		remaining -= widths[i]
	}
	return widths
}

// View renders the selected tab at the current viewport size.
func (m *Model) View() string {
	tabs := Tabs(m.snapshot.Focused)
	if len(tabs) == 0 {
		return ""
	}
	widths := tabWidths(m.width, len(tabs))
	headers := make([]string, len(widths))
	for i, width := range widths {
		tag := "heading_inactive"
		if i == m.tab {
			tag = "heading"
		}
		label := style.Truncate(style.Escape(tabs[i]), width)
		left := (width - style.Width(label) + 1) / 2
		headers[i] = m.palette.Style(tag).Render(style.Fit(strings.Repeat(" ", left)+label, width))
	}
	output := slices.Clone(m.header)
	output = append(output, strings.Join(headers, " "))
	start := m.search[m.tab].Focus
	for i := start; i < len(m.lines) && len(output) < m.height; i++ {
		line := m.lines[i]
		if m.search[m.tab].Matched && i == start {
			line = m.palette.Render("focusfield", ansi.Strip(line))
		}
		for part := range strings.SplitSeq(ansi.Hardwrap(line, m.width, true), "\n") {
			if len(output) < m.height {
				output = append(output, part)
			}
		}
	}
	if m.searching {
		output = append(output, "Search for: "+style.Escape(m.input))
	} else if m.status != "" {
		output = append(output, style.Escape(m.status))
	}
	return strings.Join(output[:min(len(output), m.height)], "\n")
}
