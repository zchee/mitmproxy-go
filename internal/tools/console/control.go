// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

// BusyError reports refusal before a command changes any control or live data.
type BusyError struct{}

// Error describes the bounded presentation queue refusal.
func (*BusyError) Error() string { return "console is busy; try again" }

// EffectCapacity is shared by invocation batches and external mailbox delivery.
const EffectCapacity = 256

type (
	invocationKey struct{}
	invocation    struct{ effects []contract.Effect }
)

// BeginInvocation collects synchronous command effects into one owned batch.
// Call finish after Do returns, on the same goroutine. Nested invocations reuse
// the parent batch; only its outer owner delivers it to the program.
func BeginInvocation(ctx context.Context) (context.Context, func() contract.EffectsMsg) {
	if _, ok := ctx.Value(invocationKey{}).(*invocation); ok {
		return ctx, func() contract.EffectsMsg { return nil }
	}
	batch := new(invocation)
	return context.WithValue(ctx, invocationKey{}, batch), func() contract.EffectsMsg {
		result := contract.EffectsMsg(batch.effects)
		batch.effects = nil
		return result
	}
}

// Controller owns command-visible state. State and Apply require dispatch;
// Retire and Mailbox may be used by the presentation goroutine without Do.
type Controller struct {
	state          contract.State
	sequence       uint64
	mailbox        chan contract.Effect
	credits        chan struct{}
	creditReleased chan struct{}
	mu             sync.Mutex
	pending        map[uint64]struct{}
	applyDepth     int
	pendingLayout  *contract.DisplayConfig
	layoutCredit   bool
}

// NewController constructs two base stacks and an empty shared admission pool.
func NewController() *Controller {
	return &Controller{state: contract.NewState(), mailbox: make(chan contract.Effect, EffectCapacity), credits: make(chan struct{}, EffectCapacity), creditReleased: make(chan struct{}, 1), pending: make(map[uint64]struct{})}
}

// State returns a detached copy of the authoritative state under dispatch.
func (c *Controller) State() contract.State { return c.state.Clone() }

// Mailbox exposes accepted external effects to the owned frontend runner.
func (c *Controller) Mailbox() <-chan contract.Effect { return c.mailbox }

// Apply validates and reserves a credit before mutation. mutate, when supplied,
// must perform its validation before writing live data, and never wait for I/O.
// An error preserves control state and does not consume a sequence.
func (c *Controller) Apply(ctx context.Context, action contract.Action, mutate func(context.Context) error) error {
	action = action.Clone()
	select {
	case c.credits <- struct{}{}:
	default:
		return &BusyError{}
	}
	next, err := reduce(c.state, action)
	if err != nil {
		<-c.credits
		return err
	}
	if c.sequence == ^uint64(0) {
		<-c.credits
		return errors.New("console effect sequence exhausted")
	}
	if err := c.reserveLayout(); err != nil {
		<-c.credits
		return err
	}
	c.applyDepth++
	defer func() { c.applyDepth-- }()
	if mutate != nil {
		if err := mutate(ctx); err != nil {
			<-c.credits
			if c.applyDepth == 1 && c.layoutCredit {
				if layoutErr := c.flushLayout(ctx); layoutErr != nil {
					return errors.Join(err, layoutErr)
				}
			}
			return err
		}
	}
	if c.pendingLayout != nil && !c.layoutCredit {
		<-c.credits
		return &BusyError{}
	}
	if c.sequence == ^uint64(0) {
		<-c.credits
		return errors.New("console effect sequence exhausted")
	}
	c.emit(ctx, action, next)
	if c.applyDepth == 1 {
		return c.flushLayout(ctx)
	}
	return nil
}

func (c *Controller) emit(ctx context.Context, action contract.Action, next contract.State) {
	c.sequence++
	c.state = next
	effect := contract.Effect{Sequence: c.sequence, Action: action.Clone(), State: next.Clone()}
	c.mu.Lock()
	c.pending[effect.Sequence] = struct{}{}
	c.mu.Unlock()
	if batch, ok := ctx.Value(invocationKey{}).(*invocation); ok {
		batch.effects = append(batch.effects, effect)
	} else {
		// Total outstanding credits bound the mailbox even with retained batches.
		c.mailbox <- effect
	}
}

func (c *Controller) clearLayout() {
	if c.layoutCredit {
		<-c.credits
	}
	c.layoutCredit, c.pendingLayout = false, nil
}

func (c *Controller) reserveLayout() error {
	if c.pendingLayout == nil {
		return nil
	}
	if *c.pendingLayout == (contract.DisplayConfig{Layout: c.state.Layout, Headers: c.state.Headers, Mouse: c.state.Mouse}) {
		c.clearLayout()
		return nil
	}
	if c.layoutCredit {
		return nil
	}
	select {
	case c.credits <- struct{}{}:
		c.layoutCredit = true
		return nil
	default:
		return &BusyError{}
	}
}

// requestLayout records option-owned values without re-entering Apply from Configure.
func (c *Controller) requestLayout(ctx context.Context, display contract.DisplayConfig) error {
	if display == (contract.DisplayConfig{Layout: c.state.Layout, Headers: c.state.Headers, Mouse: c.state.Mouse}) {
		c.clearLayout()
		return nil
	}
	if _, err := reduce(c.state, contract.Action{Kind: "layout", Display: &display}); err != nil {
		return err
	}
	c.pendingLayout = new(display)
	if c.applyDepth > 0 {
		if c.sequence >= ^uint64(0)-1 {
			return errors.New("console effect sequence exhausted")
		}
		return c.reserveLayout()
	}
	return c.flushLayout(ctx)
}

func (c *Controller) flushLayout(ctx context.Context) error {
	if err := c.reserveLayout(); err != nil || c.pendingLayout == nil {
		return err
	}
	if c.sequence == ^uint64(0) {
		<-c.credits
		c.layoutCredit = false
		return errors.New("console effect sequence exhausted")
	}
	action := contract.Action{Kind: "layout", Display: c.pendingLayout}.Clone()
	next, err := reduce(c.state, action)
	if err != nil {
		c.clearLayout()
		return err
	}
	c.pendingLayout, c.layoutCredit = nil, false
	c.emit(ctx, action, next)
	return nil
}

// Retire releases an accepted effect's credit exactly once after installation.
func (c *Controller) Retire(sequence uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.pending[sequence]; !ok {
		return false
	}
	delete(c.pending, sequence)
	<-c.credits
	// Dispatch-owned layout work is retried by the frontend runner, never here.
	select {
	case c.creditReleased <- struct{}{}:
	default:
	}
	return true
}

func reduce(state contract.State, a contract.Action) (contract.State, error) {
	next := state.Clone()
	pane := &next.Panes[next.Pane]
	current := &pane.Stack[len(pane.Stack)-1]
	switch a.Kind {
	case "push":
		if a.Window.Name == "" || a.Window.Context == "" {
			return state, errors.New("console window requires a name and context")
		}
		if current.Name != a.Window.Name {
			pane.Stack = append(pane.Stack, a.Window)
		}
		next.QuitPrompt = false
	case "pop":
		if pane.Overlay != nil {
			pane.Overlay = nil
		} else if len(pane.Stack) > 1 {
			pane.Stack = pane.Stack[:len(pane.Stack)-1]
		} else {
			next.QuitPrompt = true
		}
	case "pane":
		if next.Layout == "single" {
			next.Pane = 0
		} else {
			next.Pane = 1 - next.Pane
		}
	case "layout":
		layout := a.Value
		if a.Display != nil {
			layout = a.Display.Layout
			next.Headers, next.Mouse = a.Display.Headers, a.Display.Mouse
		}
		if layout != "single" && layout != "vertical" && layout != "horizontal" {
			return state, errors.New("invalid console layout")
		}
		// Geometry changes preserve each pane's independent navigation stack.
		next.Layout = layout
		next.Pane = min(max(next.Pane, 0), len(next.Panes)-1)
		if layout == "single" {
			next.Pane = 0
		}
	case "overlay":
		if a.Window.Context == "" {
			return state, errors.New("overlay requires a context")
		}
		pane.Overlay = new(a.Window)
		next.Choices = append([]contract.Choice(nil), a.Choices...)
	case "dismiss":
		pane.Overlay = nil
		next.Choices = nil
	case "tab", "mode":
		found := false
		for _, i := range [2]int{next.Pane, 1 - next.Pane} {
			p := &next.Panes[i]
			w := &p.Stack[len(p.Stack)-1]
			if w.Context != "flowview" {
				continue
			}
			if a.Kind == "tab" {
				w.Tab, w.Index, w.Mode = a.Value, a.Index, a.Text
			} else {
				w.Mode = a.Value
			}
			found = true
			break
		}
		if !found {
			return state, errors.New("Not viewing a flow.") //nolint:staticcheck // Preserve upstream's command error text.
		}
	case "option":
		if current.Context != "options" {
			return state, errors.New("not viewing options")
		}
		current.Option = a.Value
	case "binding":
		if current.Context != "keybindings" {
			return state, errors.New("not viewing key bindings")
		}
		current.Binding = a.Value
	case "editor":
		if current.Context != "grideditor" {
			return state, errors.New("Not in a grideditor.") //nolint:staticcheck // Preserve upstream's command error text.
		}
		current.Editor = a.Value
	case "selection":
		if a.Index < 0 || a.Column < 0 {
			return state, errors.New("invalid console selection")
		}
		current.Index, current.Column = a.Index, a.Column
	case "nav":
		switch a.Value {
		case "start", "end", "next", "select", "up", "down", "pageup", "pagedown", "left", "right":
		default:
			return state, errors.New("invalid console navigation")
		}
	case "grid":
		if current.Context != "grideditor" {
			return state, errors.New("Not in a grideditor.") //nolint:staticcheck // Preserve upstream's command error text.
		}
		switch a.Value {
		case "add", "insert", "delete", "load", "load_escaped", "save", "editor", "commit":
		default:
			return state, errors.New("invalid grid operation")
		}
	case "prompt":
		if a.Value != "command" && a.Value != "choice" && a.Value != "confirm" {
			return state, errors.New("invalid prompt kind")
		}
		next.Prompt, next.Text = a.Value, a.Text
		next.Cursor = min(max(a.Index, 0), utf8.RuneCountInString(a.Text))
		next.Recipe = a.Recipe
		next.Choices = append([]contract.Choice(nil), a.Choices...)
	case "prompt_done":
		next.Prompt, next.Text, next.Choices = "", "", nil
		next.Cursor, next.Recipe = 0, contract.Recipe{}
	case "edited", "keymap_load":
		// These effects do not change navigation state.
	default:
		return state, fmt.Errorf("unknown console transition %q", a.Kind)
	}
	return next, nil
}

// Installer buffers reordered delivery within the shared admission bound.
// It is owned by Update and never reacquires dispatch.
type Installer struct {
	controller *Controller
	sequence   uint64
	pending    map[uint64]contract.Effect
	state      contract.State
}

// NewInstaller constructs an installer for its controller's effect stream.
func NewInstaller(c *Controller) *Installer {
	return &Installer{controller: c, pending: make(map[uint64]contract.Effect), state: contract.NewState()}
}

// Install returns contiguous, newly installed accepted effects in call order.
// An effect never issued by the controller advances the cursor without changing
// presentation state. Accepted effects keep their credit until their gap closes.
func (i *Installer) Install(batch contract.EffectsMsg) []contract.Effect {
	for _, effect := range batch {
		if effect.Sequence <= i.sequence {
			continue
		}
		if _, exists := i.pending[effect.Sequence]; !exists {
			i.pending[effect.Sequence] = effect
		}
	}
	var installed []contract.Effect
	for {
		effect, ok := i.pending[i.sequence+1]
		if !ok {
			break
		}
		delete(i.pending, effect.Sequence)
		i.sequence = effect.Sequence
		if !i.controller.Retire(effect.Sequence) {
			continue
		}
		i.state = effect.State.Clone()
		installed = append(installed, effect)
	}
	return installed
}

// State returns the latest installed, detached presentation state.
func (i *Installer) State() contract.State { return i.state.Clone() }
