// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package contract defines the owned data and dispatch boundary shared by console widgets.
package contract

import (
	"context"
	"maps"
	"slices"

	tea "charm.land/bubbletea/v2"

	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

// Viewport identifies the visible rows requested by a widget.
// Revision distinguishes newer requests even when dimensions are unchanged.
type Viewport struct {
	Offset, Width, Height int
	Revision              uint64
}

// Row is a detached flow-list projection; it never contains a live flow pointer.
type Row struct {
	ID, Type, Method, URL, Host, Scheme, Path, HTTPVersion          string
	Text                                                            string
	StatusCode                                                      int
	Reason, ContentType, Error, Marked, Replay                      string
	Size                                                            int64
	Timestamp, Duration                                             float64
	Intercepted, Modified, HasResponse, ContentMissing, PushPromise bool
}

// ProjectionRequest supplies the ordered traversal's viewport and display options.
type ProjectionRequest struct {
	Viewport        Viewport
	FocusIndex      int
	FocusID, Layout string
	ShowHost        bool
}

// Projection contains only owned display rows and lightweight identifiers.
type Projection struct {
	Rows                          []Row
	IDs                           []string
	Total, FocusIndex, FirstIndex int
	FocusID                       string
}

// Projector runs inside the snapshot's dispatch hold. The flow slice and its
// members are borrowed only for this call and must never escape into its result.
// The list package supplies this function; it must not call View.Flows itself.
type Projector func([]flow.Flow, ProjectionRequest) Projection

// DetailOptions captures content rendering configuration under dispatch.
type DetailOptions struct {
	Registry            *contentviews.Registry
	DefaultContentView  string
	LineCutoff          int
	ProtobufDefinitions string
	FullContents        bool
}

// EditTarget identifies fields in one captured flow, independent of UI focus.
type EditTarget struct {
	FlowID, Part string
	Message      int
	Fingerprint  [32]byte
}

// Edit requests a prepared, non-failing mutation after its fingerprint matches.
// Fingerprint examines the named fields under dispatch. Apply receives that
// same live flow only after backup; neither callback may retain it or do I/O.
type Edit struct {
	Target      EditTarget
	Fingerprint func(flow.Flow, EditTarget) ([32]byte, error)
	Apply       func(flow.Flow, EditTarget)
}

// Snapshot is captured under dispatch. Its recipient owns all slices and the
// focused flow copy, including its identity. Widgets must not mutate another
// widget's snapshot; Clone creates an independent copy when sharing is needed.
type Snapshot struct {
	Generation                                uint64
	Viewport                                  Viewport
	Rows                                      []Row
	IDs                                       []string
	Total, StoreCount, FocusIndex, FirstIndex int
	FocusID                                   string
	Focused                                   flow.Flow
	Options                                   []options.Option
	Events                                    []eventstore.Record
	Control                                   State
	Status                                    Status
	Detail                                    DetailOptions
	Bindings                                  []Binding
	Commands                                  []Command
	ViewSettings                              map[string]string
	RegistryGeneration                        uint64
}

// Clone returns independent collection and flow storage.
func (s Snapshot) Clone() Snapshot {
	s.Rows = slices.Clone(s.Rows)
	s.IDs = slices.Clone(s.IDs)
	s.Options = slices.Clone(s.Options)
	s.Commands = slices.Clone(s.Commands)
	s.ViewSettings = maps.Clone(s.ViewSettings)
	s.Events = slices.Clone(s.Events)
	s.Control = s.Control.Clone()
	s.Status.Listeners = slices.Clone(s.Status.Listeners)
	s.Bindings = slices.Clone(s.Bindings)
	for i := range s.Bindings {
		s.Bindings[i].Contexts = slices.Clone(s.Bindings[i].Contexts)
	}
	if s.Focused != nil {
		original := s.Focused.Common()
		s.Focused = s.Focused.Copy()
		s.Focused.Common().ID = original.ID
		s.Focused.Common().Live = original.Live
	}
	return s
}

// Status contains captured values used by the information bar.
type Status struct {
	Reverse, Marked, InterceptActive                                bool
	Intercept, Filter, Order, ContentView, StickyCookie, StickyAuth string
	ClientReplay, ServerReplay                                      int
	Listeners                                                       []string
	Indicators                                                      string
}

// Command is owned command-reference metadata without executable handles.
type Command struct{ Name, Signature, Help string }

// Result is a detached display projection of a command's supported result.
type Result struct {
	// Kind distinguishes nil from a non-nil empty value: text, bytes, lines, table, flow or flows.
	Kind  string
	Text  string
	Bytes []byte
	Lines []string
	Table [][]string
	Flows []Row
}

// Recipe captures a choice or confirmation invocation without a context or callback.
// ChoiceIndices identify arguments in which every {choice} token is replaced.
type Recipe struct {
	Command       string
	Arguments     []string
	ChoiceIndices []int
}

// Choice is one immutable label/value pair in an overlay.
type Choice struct{ Label, Value string }

// TabState owns a detail tab's independent view mode, search and selection.
type TabState struct {
	Name, Mode, Search string
	Scroll, Selection  int
}

// Window identifies a pane's current view and command-visible selection.
type Window struct {
	Name, Context, FlowID, Tab, Mode, Option, Binding, Editor string
	Index, Column                                             int
	Tabs                                                      []TabState
}

// Pane owns one navigation stack and its optional overlay.
type Pane struct {
	Stack   []Window
	Overlay *Window
}

// State is authoritative under dispatch, never in a widget's Update method.
// Layout describes pane structure; Headers and Mouse mirror option-owned values
// installed by a layout action, not independent configuration owners.
type State struct {
	Panes                      [2]Pane
	Pane                       int
	Layout                     string
	Headers, Mouse, QuitPrompt bool
	Prompt, Text               string
	Cursor                     int
	Recipe                     Recipe
	Choices                    []Choice
}

// NewState returns the two upstream base views.
func NewState() State {
	return State{Panes: [2]Pane{{Stack: []Window{{Name: "flowlist", Context: "flowlist"}}}, {Stack: []Window{{Name: "eventlog", Context: "eventlog"}}}}, Layout: "single", Headers: true, Mouse: true}
}

// Clone returns a value with no shared mutable storage.
func (s State) Clone() State {
	for i := range s.Panes {
		s.Panes[i].Stack = slices.Clone(s.Panes[i].Stack)
		for j := range s.Panes[i].Stack {
			s.Panes[i].Stack[j].Tabs = slices.Clone(s.Panes[i].Stack[j].Tabs)
		}
		if s.Panes[i].Overlay != nil {
			s.Panes[i].Overlay = new(*s.Panes[i].Overlay)
			s.Panes[i].Overlay.Tabs = slices.Clone(s.Panes[i].Overlay.Tabs)
		}
	}
	s.Choices = slices.Clone(s.Choices)
	s.Recipe.Arguments = slices.Clone(s.Recipe.Arguments)
	s.Recipe.ChoiceIndices = slices.Clone(s.Recipe.ChoiceIndices)
	return s
}

// Current returns the focused matching view, then the other pane's view.
// When overlays is false, overlays are ignored, matching current_window.
func (s State) Current(keyContext string, overlays bool) (Window, bool) {
	for _, i := range [2]int{s.Pane, 1 - s.Pane} {
		p := s.Panes[i]
		if len(p.Stack) == 0 {
			continue
		}
		w := p.Stack[len(p.Stack)-1]
		if overlays && p.Overlay != nil {
			w = *p.Overlay
		}
		if keyContext == "" || w.Context == keyContext {
			return w, true
		}
	}
	return Window{}, false
}

// DisplayConfig carries the option-owned values for one derived layout effect.
type DisplayConfig struct {
	Layout         string
	Headers, Mouse bool
}

// Action requests a validated control transition. Kind is push, pop, pane,
// layout, overlay, dismiss, tab, mode, option, binding, editor, selection,
// nav, grid, prompt or prompt_done. Window and Choices are copied on admission.
type Action struct {
	Kind, Value, Text string
	Window            Window
	Index, Column     int
	Choices           []Choice
	Grid              *GridRequest
	Display           *DisplayConfig
	Recipe            Recipe
}

// Clone detaches the action's mutable payload storage.
func (a Action) Clone() Action {
	if a.Display != nil {
		a.Display = new(*a.Display)
	}
	a.Choices = slices.Clone(a.Choices)
	a.Window.Tabs = slices.Clone(a.Window.Tabs)
	a.Recipe.Arguments = slices.Clone(a.Recipe.Arguments)
	a.Recipe.ChoiceIndices = slices.Clone(a.Recipe.ChoiceIndices)
	if a.Grid != nil {
		g := *a.Grid
		g.Rows = slices.Clone(g.Rows)
		for i := range g.Rows {
			g.Rows[i] = slices.Clone(g.Rows[i])
		}
		a.Grid = &g
	}
	return a
}

// Effect is a dispatch-accepted transition with a globally ordered sequence.
// Consumers install effects in sequence order and retire each credit once.
type Effect struct {
	Sequence uint64
	Action   Action
	State    State
}

// Binding is an owned keybinding value shared with the keybindings viewer.
type Binding struct {
	Key, Command, Help string
	Contexts           []string
}

// Token is a detached parse hint, without a callable command type handle.
type Token struct {
	Value, Type string
	Valid       bool
}

// Completion combines partial parsing, argument hints and dynamic choices from one hold.
type Completion struct {
	Tokens             []Token
	Choices, Remaining []string
	Prefix, Signature  string
	Start              int
}

// GridRequest opens a sequence editor without a child importing the root package.
// Option names the registry entry committed by the existing option mutation path.
type GridRequest struct {
	Title, Option string
	Rows          [][]string
}

// Host is the console's live boundary. Widget callbacks invoke Do/Call/Dispatch
// only from tea.Cmd, never from Update, View or an observer. Invalidate and
// RequestViewport are nonblocking and may be called from Update or observers.
type Host interface {
	Do(context.Context, func(context.Context) error) error
	Call(context.Context, string, ...any) (any, error)
	Dispatch(context.Context, Action) error
	Complete(context.Context, string, string) (Completion, error)
	Execute(context.Context, string) (Result, error)
	Resolve(context.Context, Recipe, string) (Result, error)
	CommitEdit(context.Context, Edit) error
	OpenGrid(context.Context, GridRequest) error
	Invalidate()
	RequestViewport(Viewport)
}

// Widget consumes owned snapshots and delegates live work to Host from Cmd.
// Resize and Update run only on the program goroutine; View performs no I/O.
type Widget interface {
	SetSnapshot(Snapshot)
	Resize(width, height int)
	Update(tea.Msg) (tea.Cmd, bool)
	View() string
}

// ErrorMsg reports asynchronous widget failures without acknowledging a snapshot.
type ErrorMsg struct {
	Source string
	Err    error
}

// SnapshotMsg delivers an admitted snapshot after dispatch has been released.
type SnapshotMsg struct {
	Snapshot Snapshot
	Err      error
}

// EffectsMsg delivers one immutable invocation batch or mailbox entry.
type EffectsMsg []Effect
