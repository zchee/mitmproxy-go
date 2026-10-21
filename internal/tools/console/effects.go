// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"errors"

	tea "charm.land/bubbletea/v2"

	"github.com/zchee/mitmproxy-go/internal/tools/console/commander"
	"github.com/zchee/mitmproxy-go/internal/tools/console/external"
	"github.com/zchee/mitmproxy-go/internal/tools/console/grideditor"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

type (
	processReadyMsg    struct{ command tea.Cmd }
	processFinishedMsg struct {
		session *external.EditSession
		result  external.Result
		viewer  bool
	}
)

func (m *Model) installGrid(action contract.Action) error {
	action = action.Clone()
	request := action.Grid
	var widget contract.Widget
	if request.Flow == nil {
		widget = grideditor.NewSequence(m.bridge.Context(), m.bridge, *request)
	} else {
		session := &external.EditSession{Flow: request.Flow, Target: request.Target, Mode: request.Mode, Options: request.Detail}
		grid, err := grideditor.New(m.bridge.Context(), m.bridge, session)
		if err != nil {
			return err
		}
		widget = grid
	}
	m.widgets[m.state.Pane][action.Window.Name] = widget
	return nil
}

func (m *Model) confirmExit() tea.Cmd {
	return m.transition(commander.ConfirmPrompt("Quit", "console.exit", nil))
}

func (m *Model) commitAndPop(commit tea.Cmd, expected contract.Window) tea.Cmd {
	return func() tea.Msg {
		if commit != nil {
			if result := commit(); result != nil {
				return result
			}
		}
		ctx, finish := BeginInvocation(m.bridge.Context())
		err := m.bridge.Do(ctx, func(ctx context.Context) error {
			current, ok := m.bridge.Control.State().Current("", true)
			if !ok || current.Name != expected.Name || current.FlowID != expected.FlowID || current.Editor != expected.Editor || current.Option != expected.Option {
				return ErrEditConflict
			}
			return m.bridge.Dispatch(ctx, contract.Action{Kind: "pop"})
		})
		return resultMsg{effects: finish(), err: err}
	}
}

func (m *Model) externalCommand(action contract.Action) tea.Cmd {
	action = action.Clone()
	return func() tea.Msg {
		if action.Target == nil || action.Value != "view" && action.Value != "edit" {
			return contract.ErrorMsg{Source: "external", Err: errors.New("invalid external process target")}
		}
		var session *external.EditSession
		err := m.bridge.Do(m.bridge.Context(), func(context.Context) error {
			f := m.bridge.cfg.View.GetByID(action.Target.FlowID)
			actual, err := external.Fingerprint(f, *action.Target)
			if err != nil || actual != action.Target.Fingerprint {
				return ErrEditConflict
			}
			frontend := &ConsoleAddon{bridge: m.bridge}
			session, err = frontend.captureEdit(f, action.Text)
			if err == nil {
				session.Target = *action.Target
			}
			return err
		})
		if err != nil {
			return contract.ErrorMsg{Source: "external", Err: err}
		}
		data, err := session.Bytes()
		if err != nil {
			return contract.ErrorMsg{Source: "external", Err: err}
		}
		viewer := action.Value == "view"
		contentType := ""
		if viewer {
			_, metadata, err := messageContent(session.Flow, session.Target.Part, session.Target.Message)
			if err != nil {
				return contract.ErrorMsg{Source: "viewer", Err: err}
			}
			contentType = metadata.ContentType
		}
		process, err := external.Prepare(m.bridge.Context(), external.Request{Data: data, Viewer: viewer, ContentType: contentType})
		if err != nil {
			return contract.ErrorMsg{Source: "external", Err: err}
		}
		m.processes.Store(process, struct{}{})
		if m.bridge.Context().Err() != nil {
			m.processes.Delete(process)
			return contract.ErrorMsg{Source: "external", Err: errors.Join(m.bridge.Context().Err(), process.Close())}
		}
		return processReadyMsg{command: process.Tea(func(result external.Result) tea.Msg {
			m.processes.Delete(process)
			return processFinishedMsg{session: session, result: result, viewer: viewer}
		})}
	}
}

func (m *Model) finishProcess(message processFinishedMsg) tea.Cmd {
	return func() tea.Msg {
		if message.result.Err != nil {
			return contract.ErrorMsg{Source: "external", Err: message.result.Err}
		}
		if message.viewer {
			return nil
		}
		strip := false
		err := m.bridge.Do(m.bridge.Context(), func(context.Context) error {
			if m.bridge.cfg.Master.Options.Has("console_strip_trailing_newlines") {
				strip = m.bridge.cfg.Master.Options.Bool("console_strip_trailing_newlines")
			}
			return nil
		})
		if err != nil {
			return contract.ErrorMsg{Source: "external", Err: err}
		}
		edit, err := message.session.PrepareBytes(message.result.Data, strip)
		if err != nil {
			return contract.ErrorMsg{Source: "external", Err: err}
		}
		ctx, finish := BeginInvocation(m.bridge.Context())
		err = m.bridge.CommitEdit(ctx, edit)
		return resultMsg{effects: finish(), err: err}
	}
}

func (m *Model) closeProcesses() error {
	var err error
	m.processes.Range(func(key, _ any) bool {
		process := key.(*external.Process)
		err = errors.Join(err, process.Close())
		m.processes.Delete(process)
		return true
	})
	return err
}
