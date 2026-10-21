// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	teatest "github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/internal/tools/console/grideditor"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/options"
)

type integrationFrame struct {
	text                 string
	state                contract.State
	generation           uint64
	total, intercepted   int
	interceptedResponses int
	grid                 [][]grideditor.Cell
	message              string
}

type integrationQuery struct{ reply chan integrationFrame }

type integrationModel struct {
	model   *Model
	changed chan struct{}
}

func (m *integrationModel) Init() tea.Cmd  { return m.model.Init() }
func (m *integrationModel) View() tea.View { return m.model.View() }
func (m *integrationModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if query, ok := msg.(integrationQuery); ok {
		frame := integrationFrame{text: ansi.Strip(m.model.View().Content), state: m.model.state.Clone(), generation: m.model.snapshot.Generation, total: m.model.snapshot.Total, message: m.model.message}
		for _, row := range m.model.snapshot.Rows {
			if row.Intercepted {
				frame.intercepted++
				if row.HasResponse {
					frame.interceptedResponses++
				}
			}
		}
		if grid, ok := m.model.widget(m.model.state.Pane).(*grideditor.Model); ok {
			frame.grid = grid.Values()
		}
		query.reply <- frame
		return m, nil
	}
	_, cmd := m.model.Update(msg)
	select {
	case m.changed <- struct{}{}:
	default:
	}
	return m, cmd
}

type integrationReady struct{ ready chan struct{} }

func (a *integrationReady) Running(context.Context) error { close(a.ready); return nil }

type integrationHarness struct {
	master   *Master
	model    *integrationModel
	terminal *teatest.TestModel
}

func newIntegrationHarness(t *testing.T, listeners bool) *integrationHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	t.Cleanup(cancel)
	opts := options.New()
	mustConsole(t, opts.Update(ctx, map[string]any{"confdir": t.TempDir(), "server": listeners, "mode": []string{"regular@127.0.0.1:0"}}))
	master, err := New(ctx, Config{Options: opts, Stdout: io.Discard, Stderr: io.Discard})
	mustConsole(t, err)
	model, err := master.NewModel()
	mustConsole(t, err)
	probe := &integrationReady{ready: make(chan struct{})}
	mustConsole(t, master.Addons.Add(ctx, probe))
	observed := &integrationModel{model: model, changed: make(chan struct{}, 1)}
	terminal := teatest.NewTestModel(t, observed, teatest.WithInitialTermSize(80, 24), teatest.WithProgramOptions(tea.WithContext(master.Bridge.Context())))
	finished := make(chan error, 1)
	t.Cleanup(func() {
		if err := terminal.Quit(); err != nil {
			t.Error(err)
		}
		terminal.WaitFinished(t, teatest.WithFinalTimeout(5*time.Second))
		master.Shutdown()
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("assembled core lifecycle did not join")
		}
		if err := master.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	go master.Bridge.DrainTo(terminal.Send)()
	go master.Bridge.DeliverEffectsTo(terminal.Send)()
	go func() { finished <- master.Run(ctx) }()
	select {
	case <-probe.ready:
	case err := <-finished:
		finished <- err
		t.Fatalf("assembled lifecycle failed before running: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("assembled lifecycle never reached running")
	}
	h := &integrationHarness{master: master, model: observed, terminal: terminal}
	h.wait(t, func(frame integrationFrame) bool { return frame.generation != 0 })
	return h
}

func (h *integrationHarness) wait(t *testing.T, ready func(integrationFrame) bool) integrationFrame {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var last integrationFrame
	for {
		reply := make(chan integrationFrame, 1)
		h.terminal.Send(integrationQuery{reply: reply})
		select {
		case last = <-reply:
			if ready(last) {
				return last
			}
		case <-ctx.Done():
			t.Fatalf("UI inspection timed out: %v", ctx.Err())
		}
		select {
		case <-h.model.changed:
		case <-ctx.Done():
			t.Fatalf("assembled UI did not settle: %v\nstate=%+v\nmessage=%s\n%s", ctx.Err(), last.state, last.message, last.text)
		}
	}
}

func (h *integrationHarness) execute(t *testing.T, lines ...string) {
	t.Helper()
	ctx, finish := BeginInvocation(h.master.Bridge.Context())
	var result contract.Result
	err := h.master.Do(ctx, func(ctx context.Context) error {
		for _, line := range lines {
			var err error
			result, err = h.master.Bridge.Execute(ctx, line)
			if err != nil {
				return err
			}
		}
		return nil
	})
	mustConsole(t, err)
	h.terminal.Send(resultMsg{result: result, effects: finish()})
}

func (h *integrationHarness) add(t *testing.T, flows ...flow.Flow) {
	t.Helper()
	mustConsole(t, h.master.Do(t.Context(), func(ctx context.Context) error { h.master.View.Add(ctx, flows); return nil }))
}

func TestConsoleIntegration(t *testing.T) {
	tests := map[string]struct{ group string }{
		"test_integration": {"upstream"}, "test_options_home_end": {"upstream"},
		"test_keybindings_home_end": {"upstream"}, "test_replay_count": {"upstream"},
		"intercept_resume": {"live"}, "edit_replay": {"live"}, "filter_save": {"live"},
	}
	for _, group := range []string{"upstream", "live"} {
		t.Run(group, func(t *testing.T) {
			for name, test := range tests {
				if test.group != group {
					continue
				}
				t.Run(name, func(t *testing.T) {
					h := newIntegrationHarness(t, name == "intercept_resume")
					switch name {
					case "test_integration":
						path, err := filepath.Abs("testdata/dumpfile-7-current.mitm")
						mustConsole(t, err)
						h.execute(t, "view.flows.load "+command.Quote(path))
						h.wait(t, func(frame integrationFrame) bool { return frame.total == 2 })
						h.terminal.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
						h.wait(t, func(frame integrationFrame) bool {
							w, _ := frame.state.Current("", true)
							return w.Context == "flowview"
						})
						h.terminal.Send(tea.KeyPressMsg{Code: tea.KeyTab})
						h.terminal.Send(tea.KeyPressMsg{Code: tea.KeyTab})
						h.wait(t, func(frame integrationFrame) bool { w, _ := frame.state.Current("flowview", false); return w.Index == 2 })
						h.terminal.Send(tea.KeyPressMsg{Code: ' ', Text: " "})
						h.terminal.Send(tea.KeyPressMsg{Code: tea.KeyTab})
						h.terminal.Send(tea.KeyPressMsg{Code: tea.KeyTab})
						h.wait(t, func(frame integrationFrame) bool { return strings.Contains(frame.text, "http://example.com/") })
					case "test_options_home_end", "test_keybindings_home_end":
						key, contextName, label := 'O', "options", "Options"
						if name == "test_keybindings_home_end" {
							key, contextName, label = 'K', "keybindings", "Key Binding"
						}
						h.terminal.Send(tea.KeyPressMsg{Code: key, Text: string(key)})
						h.wait(t, func(frame integrationFrame) bool {
							w, _ := frame.state.Current("", true)
							return w.Context == contextName
						})
						h.terminal.Send(tea.KeyPressMsg{Code: tea.KeyHome})
						h.terminal.Send(tea.KeyPressMsg{Code: tea.KeyEnd})
						h.wait(t, func(frame integrationFrame) bool { return strings.Contains(frame.text, label) })
					case "test_replay_count":
						h.execute(t, "replay.server.count")
						h.wait(t, func(frame integrationFrame) bool {
							w, ok := frame.state.Current("dataviewer", true)
							return ok && w.Name == "dataviewer" && strings.Contains(frame.text, "Data viewer")
						})
					case "intercept_resume":
						integrationIntercept(t, h)
					case "edit_replay":
						integrationEditReplay(t, h)
					case "filter_save":
						integrationFilterSave(t, h)
					}
				})
			}
		})
	}
}

func integrationIntercept(t *testing.T, h *integrationHarness) {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "resumed through real origin") }))
	defer origin.Close()
	h.execute(t, "set intercept '~u intercept'")
	addresses := h.master.ProxyServer.ListenAddrs()
	if len(addresses) != 1 || addresses[0].Port == 0 {
		t.Fatalf("actual proxy listeners: %+v", addresses)
	}
	proxyURL, err := url.Parse("http://" + net.JoinHostPort(addresses[0].Host, strconv.Itoa(addresses[0].Port)))
	mustConsole(t, err)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	result := make(chan error, 1)
	go func() {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin.URL+"/intercept", nil)
		if err != nil {
			result <- err
			return
		}
		response, err := client.Do(request)
		if err != nil {
			result <- err
			return
		}
		data, readErr := io.ReadAll(response.Body)
		err = errors.Join(readErr, response.Body.Close())
		if string(data) != "resumed through real origin" {
			err = errors.Join(err, fmt.Errorf("unexpected origin body %q", data))
		}
		result <- err
	}()
	h.wait(t, func(frame integrationFrame) bool { return frame.intercepted == 1 })
	h.execute(t, "flow.resume @focus")
	h.wait(t, func(frame integrationFrame) bool { return frame.interceptedResponses == 1 })
	h.execute(t, "flow.resume @focus")
	select {
	case err := <-result:
		mustConsole(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("resumed real request did not complete")
	}
	h.wait(t, func(frame integrationFrame) bool { return frame.total == 1 && frame.intercepted == 0 })
}

func integrationEditReplay(t *testing.T, h *integrationHarness) {
	t.Helper()
	seen := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("X-Edited")
		_, _ = io.WriteString(w, "edited replay response")
	}))
	defer origin.Close()
	first, second := testflow.TFlow(), testflow.TFlow()
	first.Live = false
	mustConsole(t, first.Request.SetURL(origin.URL+"/edited"))
	first.Request.SetHostHeader(strings.TrimPrefix(origin.URL, "http://"))
	id := first.ID
	h.add(t, first, second)
	h.wait(t, func(frame integrationFrame) bool { return frame.total == 2 })
	h.execute(t, "console.edit.focus request-headers", "console.grideditor.add")
	h.wait(t, func(frame integrationFrame) bool { return len(frame.grid) > 1 })
	h.execute(t, "view.focus.next")
	h.terminal.Type("X-Edited")
	h.terminal.Send(tea.KeyPressMsg{Code: tea.KeyTab})
	h.wait(t, func(frame integrationFrame) bool {
		return len(frame.grid) > 1 && len(frame.grid[1]) > 0 && string(frame.grid[1][0].Data) == "X-Edited"
	})
	h.terminal.Type("accepted")
	h.execute(t, "console.view.pop")
	h.wait(t, func(frame integrationFrame) bool {
		w, _ := frame.state.Current("", true)
		return w.Context == "flowlist"
	})
	mustConsole(t, h.master.Do(t.Context(), func(context.Context) error {
		f := h.master.View.GetByID(id).(*flow.HTTPFlow)
		if f.Request.Headers.Get("X-Edited") != "accepted" {
			t.Fatal("commit-on-pop did not edit the originally captured flow")
		}
		return nil
	}))
	h.execute(t, "replay.client @"+id)
	select {
	case got := <-seen:
		if got != "accepted" {
			t.Fatalf("real replay header=%q, want edited value", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("archived edited flow did not reach the real replay origin")
	}
}

func integrationFilterSave(t *testing.T, h *integrationHarness) {
	t.Helper()
	var flows []flow.Flow
	for _, path := range []string{"keep-one", "drop", "keep-two"} {
		f := testflow.TFlow()
		mustConsole(t, f.Request.SetURL("http://example.test/"+path))
		flows = append(flows, f)
	}
	h.add(t, flows...)
	h.wait(t, func(frame integrationFrame) bool { return frame.total == 3 })
	h.execute(t, "set view_filter '~u keep'")
	h.wait(t, func(frame integrationFrame) bool { return frame.total == 2 })
	path := filepath.Join(t.TempDir(), "selected.mitm")
	h.execute(t, "save.file @shown "+command.Quote(path))
	file, err := os.Open(path)
	mustConsole(t, err)
	reader := flowio.NewReader(file)
	var paths []string
	for {
		f, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		mustConsole(t, err)
		paths = append(paths, f.(*flow.HTTPFlow).Request.Path)
	}
	mustConsole(t, file.Close())
	slices.Sort(paths)
	if !slices.Equal(paths, []string{"/keep-one", "/keep-two"}) {
		t.Fatalf("saved filtered flows=%q", paths)
	}
}
