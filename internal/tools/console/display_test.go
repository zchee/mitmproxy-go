// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"errors"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

func verifyDisplayAdmission(t *testing.T) {
	t.Helper()
	b, _ := testBridge(t)
	mustConsole(t, b.cfg.Master.Addons.Add(t.Context(), &ConsoleAddon{bridge: b}))
	ctx, finish := BeginInvocation(t.Context())
	mustConsole(t, b.Do(ctx, func(ctx context.Context) error {
		err := b.Control.Apply(ctx, contract.Action{Kind: "push", Window: contract.Window{Name: "options", Context: "options"}}, func(ctx context.Context) error {
			return b.cfg.Master.Options.Update(ctx, map[string]any{"console_layout": "vertical", "console_layout_headers": false, "console_mouse": false})
		})
		if err != nil {
			return err
		}
		state := b.Control.State()
		window, ok := state.Current("options", false)
		if !ok || window.Name != "options" || state.Layout != "vertical" || state.Headers || state.Mouse {
			t.Fatalf("same-Do layout/state ownership mismatch: %+v", state)
		}
		return nil
	}))
	effects := finish()
	if len(effects) != 2 || effects[0].Sequence+1 != effects[1].Sequence || effects[0].Action.Kind != "push" || effects[1].Action.Kind != "layout" {
		t.Fatalf("command/layout effects are not ordered: %+v", effects)
	}
	if effects[0].State.Layout != "single" || effects[1].State.Layout != "vertical" || effects[1].Action.Display == nil {
		t.Fatal("layout was installed before the command or lost its typed payload")
	}
	m := NewModel(b, nil)
	m.install(effects)
	snapshot, err := b.capture(b.generation.Load())
	mustConsole(t, err)
	m.applySnapshot(snapshot)
	if m.state.Headers || m.state.Mouse || m.View().MouseMode != tea.MouseModeNone {
		t.Fatal("derived display mirrors differ from owned options")
	}
	before := b.Control.sequence
	mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error {
		return b.cfg.Master.Options.Update(ctx, map[string]any{"console_layout": "vertical", "console_layout_headers": false, "console_mouse": false})
	}))
	if b.Control.sequence != before || b.Control.pendingLayout != nil || b.Control.layoutCredit {
		t.Fatal("identical display triple emitted an effect or retained a credit")
	}
	tests := map[string]struct{ mouse bool }{"console_layout_headers": {}, "console_mouse": {mouse: true}}
	for name, test := range tests {
		ctx, finish := BeginInvocation(t.Context())
		mustConsole(t, b.Do(ctx, func(ctx context.Context) error {
			return b.cfg.Master.Options.Update(ctx, map[string]any{name: true})
		}))
		batch := finish()
		if len(batch) != 1 || batch[0].Action.Kind != "layout" {
			t.Fatalf("%s alone did not emit exactly one layout effect: %+v", name, batch)
		}
		if diff := cmp.Diff(effects[1].State.Panes, batch[0].State.Panes); diff != "" {
			t.Fatalf("boolean display change rebuilt navigation stacks: %s", diff)
		}
		m.install(batch)
		if test.mouse && !m.state.Mouse || !test.mouse && !m.state.Headers {
			t.Fatalf("%s did not update its derived mirror", name)
		}
	}
	original := contract.Action{Kind: "layout", Display: &contract.DisplayConfig{Layout: "vertical"}, Target: &contract.EditTarget{FlowID: "captured-flow", Part: "request-body", Message: -1}}
	cloned := original.Clone()
	original.Display.Layout = "single"
	original.Target.FlowID = "other-flow"
	if cloned.Target.FlowID != "captured-flow" || cloned.Target.Part != "request-body" || cloned.Target.Message != -1 {
		t.Fatal("edit target aliases its producer")
	}
	if cloned.Display.Layout != "vertical" {
		t.Fatal("display payload aliases its producer")
	}
	verifyDisplayBackpressure(t)
}

func verifyDisplayBackpressure(t *testing.T) {
	t.Helper()
	tests := map[string]struct{ inside, applyRetry bool }{
		"outside Apply, credit release": {},
		"inside Apply, credit release":  {inside: true},
		"inside Apply, next command":    {inside: true, applyRetry: true},
	}
	for name, test := range tests {
		b, _ := testBridge(t)
		frontend := &ConsoleAddon{bridge: b}
		mustConsole(t, b.cfg.Master.Addons.Add(t.Context(), frontend))
		count := EffectCapacity
		if test.inside {
			count--
		}
		mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error {
			for range count {
				if err := b.Control.Apply(ctx, contract.Action{Kind: "pane"}, nil); err != nil {
					return err
				}
			}
			return nil
		}))
		before, sequence := b.Control.State(), b.Control.sequence
		change := func(ctx context.Context) error {
			return b.cfg.Master.Options.Update(ctx, map[string]any{"console_layout": "horizontal", "console_layout_headers": false, "console_mouse": false})
		}
		err := b.Do(t.Context(), func(ctx context.Context) error {
			if test.inside {
				return b.Control.Apply(ctx, contract.Action{Kind: "push", Window: contract.Window{Name: "options", Context: "options"}}, change)
			}
			return change(ctx)
		})
		if !test.inside {
			if err != nil {
				t.Fatalf("external update changed ordinary-hook error semantics: %v", err)
			}
			err = b.Do(t.Context(), func(ctx context.Context) error {
				return frontend.Configure(ctx, map[string]struct{}{"console_layout": {}})
			})
		}
		if _, ok := errors.AsType[*BusyError](err); !ok {
			t.Fatalf("%s got %v, want BusyError", name, err)
		}
		if b.cfg.Master.Options.Str("console_layout") != "horizontal" || cmp.Diff(before, b.Control.State()) != "" || b.Control.sequence != sequence || b.Control.pendingLayout == nil {
			t.Fatalf("%s lost committed options/pending layout or changed refused control", name)
		}
		installer := NewInstaller(b.Control)
		first := <-b.Control.Mailbox()
		installer.Install(contract.EffectsMsg{first})
		if test.applyRetry {
			ctx, finish := BeginInvocation(t.Context())
			mustConsole(t, b.Do(ctx, func(ctx context.Context) error {
				return b.Control.Apply(ctx, contract.Action{Kind: "push", Window: contract.Window{Name: "options", Context: "options"}}, nil)
			}))
			batch := finish()
			if len(batch) != 2 || batch[0].Action.Kind != "push" || batch[1].Action.Kind != "layout" {
				t.Fatalf("next command did not drain pending layout in order: %+v", batch)
			}
			for range count - 1 {
				installer.Install(contract.EffectsMsg{<-b.Control.Mailbox()})
			}
			installer.Install(batch)
		} else {
			delivered := make(chan tea.Msg)
			go b.deliverEffects(func(msg tea.Msg) {
				select {
				case delivered <- msg:
				case <-b.Context().Done():
				}
			})
			for range count {
				select {
				case msg := <-delivered:
					batch, ok := msg.(contract.EffectsMsg)
					if !ok {
						t.Fatalf("credit-release retry delivered %T: %+v", msg, msg)
					}
					installer.Install(batch)
				case <-time.After(5 * time.Second):
					t.Fatalf("%s: credit release did not retry pending layout", name)
				}
			}
			b.cancel()
			awaitConsole(t, b.deliveryDone)
		}
		mustConsole(t, b.Do(t.Context(), func(context.Context) error {
			state := b.Control.State()
			if installer.State().Layout != "horizontal" || state.Layout != "horizontal" || state.Headers || state.Mouse || b.Control.pendingLayout != nil || b.Control.layoutCredit || len(b.Control.credits) != 0 {
				t.Fatalf("%s retry did not converge mirrors and retire all credits", name)
			}
			return nil
		}))
	}
}
