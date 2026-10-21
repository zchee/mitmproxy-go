// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/keymap"
	"github.com/zchee/mitmproxy-go/master"
)

// FrameInterval is the minimum interval between admitted background traversals.
const FrameInterval = 16 * time.Millisecond

// BridgeConfig supplies dispatch-owned stores and a list-owned projector.
// Ticks permits deterministic admission tests; nil uses a real frame ticker.
type BridgeConfig struct {
	Master    *master.Master
	View      *view.View
	Events    *eventstore.EventStore
	Registry  *contentviews.Registry
	Project   contract.Projector
	Bindings  func() []contract.Binding
	Listeners func() []string
	Ticks     <-chan time.Time
}

// Bridge owns one snapshot worker and the nonblocking dirty generation.
// Construction/Close run outside dispatch. State-changing callbacks use Do.
type Bridge struct {
	cfg                BridgeConfig
	Control            *Controller
	Keys               *keymap.Keymap
	ctx                context.Context
	cancel             context.CancelFunc
	stopParent         func() bool
	generation         atomic.Uint64
	registryGeneration atomic.Uint64
	wake               chan struct{}
	installed          chan uint64
	started            atomic.Bool
	deliveryStarted    atomic.Bool
	done               chan struct{}
	deliveryDone       chan struct{}
	mu                 sync.Mutex
	viewport           contract.Viewport
	unsubscribe        []func()
	workMu             sync.Mutex
	work               sync.WaitGroup
	closing            bool
	workDone           chan struct{}
	joinOnce           sync.Once
}

var _ contract.Host = (*Bridge)(nil)

// NewBridge attaches invalidation callbacks without starting a goroutine.
func NewBridge(ctx context.Context, cfg BridgeConfig) (*Bridge, error) {
	if cfg.Master == nil || cfg.View == nil || cfg.Events == nil || cfg.Project == nil {
		return nil, errors.New("console bridge requires master, view, events and projector")
	}
	if cfg.Registry == nil {
		cfg.Registry = contentviews.NewRegistry()
	}
	// Never retain a dispatch-frame context for later snapshot work.
	lifetime, cancel := context.WithCancel(context.Background())
	b := &Bridge{cfg: cfg, Control: NewController(), ctx: lifetime, cancel: cancel, wake: make(chan struct{}, 1), installed: make(chan uint64, 1), done: make(chan struct{}), deliveryDone: make(chan struct{}), workDone: make(chan struct{})}
	b.Keys = keymap.NewDefault(b.Invalidate)
	if b.cfg.Bindings == nil {
		b.cfg.Bindings = b.Keys.Snapshot
	}
	b.stopParent = context.AfterFunc(ctx, cancel)
	if err := cfg.Master.Do(ctx, func(context.Context) error {
		b.unsubscribe = append(b.unsubscribe, cfg.View.Observe(func(view.Event) { b.Invalidate() }), cfg.Events.Observe(func(eventstore.Event) { b.Invalidate() }))
		b.unsubscribe = append(b.unsubscribe, cfg.Master.Options.Subscribe(func(context.Context, map[string]struct{}) error { b.Invalidate(); return nil }))
		return nil
	}); err != nil {
		b.stopParent()
		cancel()
		return nil, err
	}
	b.unsubscribe = append(b.unsubscribe, cfg.Registry.Subscribe(func(contentviews.View) { b.registryGeneration.Add(1); b.Invalidate() }))
	b.Invalidate()
	return b, nil
}

// Context is the frame-free lifetime to pass to tea.WithContext.
func (b *Bridge) Context() context.Context { return b.ctx }

// Invalidate marks dirty and wakes the drain without waiting on presentation.
func (b *Bridge) Invalidate() {
	b.generation.Add(1)
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// RequestViewport replaces older pending viewport work; it uses the same frame credit.
func (b *Bridge) RequestViewport(v contract.Viewport) {
	b.mu.Lock()
	v.Offset, v.Width, v.Height = max(0, v.Offset), max(0, v.Width), max(0, v.Height)
	v.Revision = b.viewport.Revision + 1
	b.viewport = v
	b.mu.Unlock()
	b.Invalidate()
}

// Do invokes a callback under the master dispatch hold.
func (b *Bridge) Do(ctx context.Context, fn func(context.Context) error) error {
	return b.cfg.Master.Do(ctx, fn)
}

// Call invokes the existing command registry under dispatch.
func (b *Bridge) Call(ctx context.Context, name string, args ...any) (any, error) {
	var result any
	err := b.Do(ctx, func(ctx context.Context) error {
		value, err := b.cfg.Master.Call(ctx, name, args...)
		if err != nil {
			return err
		}
		switch value := value.(type) {
		case flow.Flow:
			copy := value.Copy()
			copy.Common().ID = value.Common().ID
			copy.Common().Live = value.Common().Live
			result = copy
		case []flow.Flow:
			copies := make([]flow.Flow, len(value))
			for i, f := range value {
				copies[i] = f.Copy()
				copies[i].Common().ID = f.Common().ID
				copies[i].Common().Live = f.Common().Live
			}
			result = copies
		case []string:
			result = slices.Clone(value)
		case []byte:
			result = slices.Clone(value)
		case [][]string:
			rows := make([][]string, len(value))
			for i, row := range value {
				rows[i] = slices.Clone(row)
			}
			result = rows
		case command.Data:
			rows := make(command.Data, len(value))
			for i, row := range value {
				rows[i] = make([]any, len(row))
				for j, cell := range row {
					if data, ok := cell.([]byte); ok {
						rows[i][j] = slices.Clone(data)
					} else {
						rows[i][j] = cell
					}
				}
			}
			result = rows
		case command.CutSpec:
			result = slices.Clone(value)
		case nil, string, bool, int, int64, float64, command.Path, command.Cmd, command.CmdArgs, command.Marker:
			result = value
		default:
			return fmt.Errorf("unsupported console result type %T", value)
		}
		return nil
	})
	return result, err
}

// Dispatch accepts a control transition under the same hold as caller commands.
func (b *Bridge) Dispatch(ctx context.Context, a contract.Action) error {
	return b.Do(ctx, func(ctx context.Context) error {
		a = a.Clone()
		if a.Kind == "push" && a.Window.Context == "flowview" {
			if a.Window.FlowID == "" {
				if f := b.cfg.View.Focus.Flow(); f != nil {
					a.Window.FlowID = f.Common().ID
				}
			}
			f := b.cfg.View.GetByID(a.Window.FlowID)
			if f == nil {
				return errors.New("no flow selected")
			}
			values, err := b.cfg.View.Settings.Values(f)
			if err != nil {
				return err
			}
			b.hydrateWindow(&a.Window, f, values)
		}
		if a.Kind == "tab" {
			window, ok := b.Control.State().Current("flowview", false)
			if !ok {
				return errors.New("Not viewing a flow.") //nolint:staticcheck // Preserve upstream's command error text.
			}
			f := b.cfg.View.GetByID(window.FlowID)
			if f == nil {
				return ErrEditConflict
			}
			values, err := b.cfg.View.Settings.Values(f)
			if err != nil {
				return err
			}
			window.Tab, window.Index = a.Value, a.Index
			b.hydrateWindow(&window, f, values)
			a.Value, a.Index, a.Text = window.Tab, window.Index, window.Mode
		}
		if a.Kind == "binding" && a.Value != "" {
			if _, err := b.binding(a.Value); err != nil {
				return err
			}
		}
		var notify func(context.Context) error
		if a.Kind == "mode" {
			if !slices.Contains(b.cfg.Registry.AvailableViews(), strings.ToLower(a.Value)) {
				return errors.New("invalid flowview mode")
			}
			window, ok := b.Control.State().Current("flowview", false)
			if !ok {
				return errors.New("Not viewing a flow.") //nolint:staticcheck // Preserve upstream's command error text.
			}
			f := b.cfg.View.GetByID(window.FlowID)
			if f == nil {
				return ErrEditConflict
			}
			notify = func(ctx context.Context) error {
				_, err := b.Call(ctx, "view.settings.setval", []flow.Flow{f}, "flowview_mode_"+strconv.Itoa(window.Index), a.Value)
				return err
			}
		}
		if err := b.Control.Apply(ctx, a, nil); err != nil {
			return err
		}
		b.Invalidate()
		if notify != nil {
			return notify(ctx)
		}
		return nil
	})
}

func (b *Bridge) hydrateWindow(window *contract.Window, f flow.Flow, values map[string]string) {
	names := []string{"Request", "Response", "Detail"}
	switch f := f.(type) {
	case *flow.HTTPFlow:
		if f.WebSocket != nil {
			names = []string{"Request", "Response", "WebSocket Messages", "Detail"}
		}
	case *flow.TCPFlow:
		names = []string{"TCP Stream", "Detail"}
	case *flow.UDPFlow:
		names = []string{"UDP Stream", "Detail"}
	}
	fallback := "auto"
	if _, ok := b.cfg.Master.Options.Lookup("console_default_contentview"); ok {
		fallback = b.cfg.Master.Options.Str("console_default_contentview")
	}
	tabs := make([]contract.TabState, len(names))
	for i, name := range names {
		if i < len(window.Tabs) {
			tabs[i] = window.Tabs[i]
		}
		tabs[i].Name, tabs[i].Mode = name, values["flowview_mode_"+strconv.Itoa(i)]
		if tabs[i].Mode == "" {
			tabs[i].Mode = fallback
		}
	}
	window.Index = min(max(0, window.Index), len(tabs)-1)
	window.Tab, window.Mode, window.Tabs = names[window.Index], tabs[window.Index].Mode, tabs
}

// binding resolves a complete identity against the current dispatch-owned keymap.
func (b *Bridge) binding(identity string) (contract.Binding, error) {
	if b.cfg.Bindings != nil {
		for _, binding := range b.cfg.Bindings() {
			if binding.Key+"@"+strings.Join(binding.Contexts, ",") == identity {
				binding.Contexts = slices.Clone(binding.Contexts)
				return binding, nil
			}
		}
	}
	return contract.Binding{}, errors.New("key binding conflict: binding changed or was removed")
}

// Complete obtains parse hints and dynamic completions within one fresh hold.
func (b *Bridge) Complete(ctx context.Context, text, full string) (contract.Completion, error) {
	var result contract.Completion
	err := b.Do(ctx, func(ctx context.Context) error {
		parsed, remaining := b.cfg.Master.Commands.ParsePartial(ctx, text)
		fullParsed, _ := b.cfg.Master.Commands.ParsePartial(ctx, full)
		typ := command.CmdType
		for _, token := range fullParsed {
			result.Tokens = append(result.Tokens, contract.Token{Value: token.Value, Type: token.Type.Name(), Valid: token.Valid})
		}
		for _, parameter := range remaining {
			result.Remaining = append(result.Remaining, parameter.String())
		}
		if len(parsed) > 0 && parsed[len(parsed)-1].Type != command.SpaceType {
			last := parsed[len(parsed)-1]
			typ, result.Prefix, result.Start = last.Type, command.Unquote(last.Value), utf8.RuneCountInString(text)-utf8.RuneCountInString(last.Value)
		} else {
			result.Start = utf8.RuneCountInString(text)
			if len(remaining) > 0 {
				typ = remaining[0].Type
			}
		}
		values, err := typ.Completion(ctx, b.cfg.Master.Commands, result.Prefix)
		if err != nil {
			return err
		}
		result.Choices = slices.Clone(values)
		slices.Sort(result.Choices)
		for _, c := range b.cfg.Master.Commands.Commands() {
			if len(parsed) > 0 && c.Name == parsed[0].Value {
				result.Signature = c.SignatureHelp()
				break
			}
		}
		return nil
	})
	return result, err
}

// Execute runs a typed command line and detaches its result before releasing dispatch.
func (b *Bridge) Execute(ctx context.Context, line string) (contract.Result, error) {
	var result contract.Result
	err := b.Do(ctx, func(ctx context.Context) error {
		value, err := b.cfg.Master.Commands.Execute(ctx, line)
		if err != nil {
			return err
		}
		result, err = b.projectResult(value)
		return err
	})
	return result, err
}

// Resolve executes an immutable choice recipe under a fresh dispatch hold.
func (b *Bridge) Resolve(ctx context.Context, recipe contract.Recipe, choice string) (contract.Result, error) {
	args := slices.Clone(recipe.Arguments)
	for _, i := range recipe.ChoiceIndices {
		if i < 0 || i >= len(args) {
			return contract.Result{}, errors.New("invalid choice argument index")
		}
		args[i] = strings.ReplaceAll(args[i], "{choice}", choice)
	}
	for i := range args {
		args[i] = command.Quote(args[i])
	}
	return b.Execute(ctx, recipe.Command+" "+strings.Join(args, " "))
}

func (b *Bridge) projectResult(value any) (contract.Result, error) {
	var result contract.Result
	switch value.(type) {
	case nil:
	case []byte:
		result.Kind = "bytes"
	case command.CutSpec, []string:
		result.Kind = "lines"
	case command.Data, [][]string:
		result.Kind = "table"
	case flow.Flow:
		result.Kind = "flow"
	case []flow.Flow:
		result.Kind = "flows"
	default:
		result.Kind = "text"
	}
	switch value := value.(type) {
	case nil:
	case string:
		result.Text = value
	case []byte:
		result.Bytes = slices.Clone(value)
	case bool:
		result.Text = strconv.FormatBool(value)
	case int:
		result.Text = strconv.Itoa(value)
	case int64:
		result.Text = strconv.FormatInt(value, 10)
	case float64:
		result.Text = strconv.FormatFloat(value, 'g', -1, 64)
	case command.Path, command.Cmd, command.CmdArgs, command.Marker:
		result.Text = fmt.Sprint(value)
	case command.CutSpec:
		result.Lines = slices.Clone([]string(value))
	case command.Data:
		for _, row := range value {
			cells := make([]string, len(row))
			for i, cell := range row {
				switch cell := cell.(type) {
				case string:
					cells[i] = cell
				case []byte:
					cells[i] = strutil.BytesToEscapedStr(cell, true, false)
				default:
					return result, fmt.Errorf("unsupported console table cell %T", cell)
				}
			}
			result.Table = append(result.Table, cells)
		}
	case []string:
		result.Lines = slices.Clone(value)
	case [][]string:
		for _, row := range value {
			result.Table = append(result.Table, slices.Clone(row))
		}
	case flow.Flow:
		result.Flows = []contract.Row{{ID: value.Common().ID, Type: value.Type()}}
	case []flow.Flow:
		result.Flows = make([]contract.Row, len(value))
		for i, f := range value {
			result.Flows[i] = contract.Row{ID: f.Common().ID, Type: f.Type()}
		}
	default:
		return result, fmt.Errorf("unsupported console result type %T", value)
	}
	return result, nil
}

// ErrEditConflict means the captured target no longer exists or has changed.
var ErrEditConflict = errors.New("edit conflict: target changed or was removed")

// CommitEdit checks the captured field fingerprint in a fresh hold before backup,
// applying already validated data and publishing the existing Update hook.
func (b *Bridge) CommitEdit(ctx context.Context, edit contract.Edit) error {
	if edit.Fingerprint == nil || edit.Apply == nil {
		return errors.New("edit requires fingerprint and apply callbacks")
	}
	return b.Do(ctx, func(ctx context.Context) error {
		var edited flow.Flow
		err := b.Control.Apply(ctx, contract.Action{Kind: "edited"}, func(context.Context) error {
			f := b.cfg.View.GetByID(edit.Target.FlowID)
			if f == nil {
				return ErrEditConflict
			}
			actual, err := edit.Fingerprint(f, edit.Target)
			if err != nil {
				return err
			}
			if actual != edit.Target.Fingerprint {
				return ErrEditConflict
			}
			f.Backup()
			edit.Apply(f, edit.Target)
			edited = f
			return nil
		})
		if err != nil {
			return err
		}
		b.Invalidate()
		return b.cfg.Master.Addons.Trigger(ctx, addon.UpdateHook{Flows: []flow.Flow{edited}})
	})
}

// OpenGrid requests the sequence-grid service through the ordered effect stream.
func (b *Bridge) OpenGrid(ctx context.Context, request contract.GridRequest) error {
	return b.Dispatch(ctx, contract.Action{Kind: "push", Window: contract.Window{Name: "sequence", Context: "grideditor", Option: request.Option}, Grid: &request})
}

func (b *Bridge) capture(generation uint64) (contract.Snapshot, error) {
	b.mu.Lock()
	viewport := b.viewport
	b.mu.Unlock()
	snapshot := contract.Snapshot{Generation: generation, Viewport: viewport}
	err := b.Do(b.ctx, func(ctx context.Context) error {
		flows := b.cfg.View.Flows()
		focus := b.cfg.View.Focus.Flow()
		focusIndex, focusID := -1, ""
		if focus != nil {
			focusID = focus.Common().ID
			for index, f := range flows {
				if f.Common().ID == focusID {
					focusIndex = index
					break
				}
			}
			snapshot.Focused = focus.Copy()
			snapshot.Focused.Common().ID, snapshot.Focused.Common().Live = focusID, focus.Common().Live
		}
		opts := b.cfg.Master.Options
		layout, showHost := "default", false
		if _, ok := opts.Lookup("console_flowlist_layout"); ok {
			layout = opts.Str("console_flowlist_layout")
		}
		if _, ok := opts.Lookup("showhost"); ok {
			showHost = opts.Bool("showhost")
		}
		projected := b.cfg.Project(flows, contract.ProjectionRequest{Viewport: viewport, FocusID: focusID, FocusIndex: focusIndex, Layout: layout, ShowHost: showHost})
		snapshot.Rows, snapshot.IDs, snapshot.Total = projected.Rows, projected.IDs, projected.Total
		snapshot.FocusID, snapshot.FocusIndex, snapshot.FirstIndex = projected.FocusID, projected.FocusIndex, projected.FirstIndex
		snapshot.RegistryGeneration = b.registryGeneration.Load()
		if focus != nil {
			values, err := b.cfg.View.Settings.Values(focus)
			if err != nil {
				return err
			}
			snapshot.ViewSettings = maps.Clone(values)
		}
		for _, c := range b.cfg.Master.Commands.Commands() {
			snapshot.Commands = append(snapshot.Commands, contract.Command{Name: c.Name, Signature: c.SignatureHelp(), Help: c.Help})
		}
		slices.SortFunc(snapshot.Commands, func(a, c contract.Command) int { return strings.Compare(a.Name, c.Name) })
		snapshot.StoreCount = b.cfg.View.StoreCount()
		snapshot.Options, snapshot.Events, snapshot.Control = opts.Items(), b.cfg.Events.Records(), b.Control.State()
		for i := range snapshot.Control.Panes {
			for j := range snapshot.Control.Panes[i].Stack {
				window := &snapshot.Control.Panes[i].Stack[j]
				if window.Context != "flowview" {
					continue
				}
				selected := b.cfg.View.GetByID(window.FlowID)
				if selected == nil {
					continue
				}
				values, err := b.cfg.View.Settings.Values(selected)
				if err != nil {
					return err
				}
				b.hydrateWindow(window, selected, values)
			}
		}
		snapshot.Status = b.statusSnapshot(ctx)
		snapshot.Detail = contract.DetailOptions{Registry: b.cfg.Registry, DefaultContentView: "auto", FullContents: snapshot.ViewSettings["fullcontents"] == "true"}
		if _, ok := opts.Lookup("console_default_contentview"); ok {
			snapshot.Detail.DefaultContentView = opts.Str("console_default_contentview")
		}
		if _, ok := opts.Lookup("content_view_lines_cutoff"); ok {
			snapshot.Detail.LineCutoff = opts.Int("content_view_lines_cutoff")
		}
		if _, ok := opts.Lookup("protobuf_definitions"); ok {
			if value := opts.OptStr("protobuf_definitions"); value != nil {
				snapshot.Detail.ProtobufDefinitions = *value
			}
		}
		if b.cfg.Bindings != nil {
			snapshot.Bindings = b.cfg.Bindings()
		}
		return nil
	})
	return snapshot, err
}

// Accept acknowledges every delivered snapshot, including stale ones, and tells
// Update whether it still matches current dirty and viewport generations.
func (b *Bridge) Accept(snapshot contract.Snapshot) bool {
	b.mu.Lock()
	revision := b.viewport.Revision
	b.mu.Unlock()
	select {
	case b.installed <- snapshot.Generation:
	default:
	}
	return snapshot.Generation == b.generation.Load() && revision == snapshot.Viewport.Revision
}

// Drain is a single long-lived tea.Cmd. The program must use b.Context(), so
// cancellation unblocks Send before Close joins this worker.
func (b *Bridge) Drain(program *tea.Program) tea.Cmd {
	return func() tea.Msg { b.drain(func(msg tea.Msg) { program.Send(msg) }); return nil }
}

func (b *Bridge) drain(send func(tea.Msg)) {
	if !b.started.CompareAndSwap(false, true) {
		return
	}
	defer close(b.done)
	ticks := b.cfg.Ticks
	var timer *time.Timer
	if ticks == nil {
		timer = time.NewTimer(FrameInterval)
		defer timer.Stop()
		ticks = timer.C
	}
	var last time.Time
	var completed uint64
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-b.wake:
		case tick, ok := <-ticks:
			if !ok {
				return
			}
			generation := b.generation.Load()
			if generation == completed || (!last.IsZero() && tick.Sub(last) < FrameInterval) {
				if timer != nil {
					timer.Reset(FrameInterval)
				}
				continue
			}
			last = tick
			if timer != nil {
				// Admission is measured at traversal start, not the timer's queued time.
				last = time.Now()
			}
			snapshot, err := b.capture(generation)
			if b.ctx.Err() != nil {
				return
			}
			send(contract.SnapshotMsg{Snapshot: snapshot, Err: err})
			for {
				select {
				case <-b.ctx.Done():
					return
				case installed := <-b.installed:
					if installed == generation {
						completed = generation
						if timer != nil {
							timer.Reset(FrameInterval)
						} else {
							// Injected buffered clocks cannot accumulate traversal credits.
							for range len(ticks) {
								<-ticks
							}
						}
						goto nextFrame
					}
				}
			}
		}
	nextFrame:
	}
}

// DeliverEffects drains external command effects outside dispatch until canceled.
// Use the same program lifetime as Drain to make its blocked Send cancelable.
func (b *Bridge) DeliverEffects(program *tea.Program) tea.Cmd {
	return func() tea.Msg {
		if !b.deliveryStarted.CompareAndSwap(false, true) {
			return nil
		}
		defer close(b.deliveryDone)
		for {
			select {
			case <-b.ctx.Done():
				return nil
			case effect := <-b.Control.Mailbox():
				program.Send(contract.EffectsMsg{effect})
			}
		}
	}
}

// command joins active widget work and refuses queued work after shutdown.
func (b *Bridge) command(cmd tea.Cmd) tea.Cmd {
	if cmd == nil {
		return nil
	}
	return func() tea.Msg {
		b.workMu.Lock()
		if b.closing || b.ctx.Err() != nil {
			b.workMu.Unlock()
			return nil
		}
		b.work.Add(1)
		b.workMu.Unlock()
		defer b.work.Done()
		message := cmd()
		if batch, ok := message.(tea.BatchMsg); ok {
			for i := range batch {
				batch[i] = b.command(batch[i])
			}
		}
		return message
	}
}

// Close cancels first, detaches observers under Do, then joins owned work.
func (b *Bridge) Close(ctx context.Context) error {
	b.workMu.Lock()
	b.closing = true
	b.cancel()
	b.workMu.Unlock()
	b.joinOnce.Do(func() {
		go func() {
			b.work.Wait()
			close(b.workDone)
		}()
	})
	b.stopParent()
	if err := b.Do(ctx, func(context.Context) error {
		for _, cancel := range b.unsubscribe {
			cancel()
		}
		b.unsubscribe = nil
		return nil
	}); err != nil {
		return err
	}
	for _, worker := range []struct {
		started bool
		done    <-chan struct{}
	}{{b.started.Load(), b.done}, {b.deliveryStarted.Load(), b.deliveryDone}, {true, b.workDone}} {
		if worker.started {
			select {
			case <-worker.done:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}
