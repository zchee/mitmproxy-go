// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/options"
)

// recordHandler is a slog.Handler that keeps the records it receives.
type recordHandler struct {
	mu      sync.Mutex
	records []string // "LEVEL message addon=<name>"
}

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	// Keep the first line of the message: a panic record carries its
	// stack after it.
	msg, _, _ := strings.Cut(r.Message, "\n")
	var b strings.Builder
	b.WriteString(r.Level.String())
	b.WriteString(" ")
	b.WriteString(msg)
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "addon" {
			b.WriteString(" addon=")
			b.WriteString(a.Value.String())
		}
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, b.String())
	h.mu.Unlock()
	return nil
}

func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordHandler) got() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.records)
}

// journal is the ordered list of hook calls the test addons make.
type journal struct {
	mu    sync.Mutex
	calls []string
}

func (j *journal) add(s string) {
	j.mu.Lock()
	j.calls = append(j.calls, s)
	j.mu.Unlock()
}

func (j *journal) got() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return slices.Clone(j.calls)
}

// testEnv is a Manager with real option and command registries.
type testEnv struct {
	m    *Manager
	opts *options.Manager
	cmds *command.Manager
	log  *recordHandler
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	e := &testEnv{opts: options.NewManager(), cmds: command.NewManager(), log: &recordHandler{}}
	e.m = NewManager(e.opts, e.cmds, Config{Logger: slog.New(e.log)})
	t.Cleanup(e.m.Close)
	return e
}

// hooker records configure and running, optionally failing.
type hooker struct {
	name     string
	j        *journal
	children []any
	err      error // returned from Running
	panicMsg string
}

func (h *hooker) Name() string  { return h.name }
func (h *hooker) Addons() []any { return h.children }
func (h *hooker) Running(context.Context) error {
	h.j.add("running " + h.name)
	if h.panicMsg != "" {
		panic(h.panicMsg)
	}
	return h.err
}

func (h *hooker) Configure(_ context.Context, updated map[string]struct{}) error {
	h.j.add("configure " + h.name + " " + strings.Join(slices.Sorted(maps.Keys(updated)), ","))
	return nil
}

func (h *hooker) Done(context.Context) error {
	h.j.add("done " + h.name)
	return nil
}

func TestHookTable(t *testing.T) {
	// The order of the hook list in the specification of this package:
	// lifecycle, connection, HTTP, WebSocket, TCP, UDP, DNS, TLS, QUIC.
	want := []string{
		"load", "configure", "running", "done", "update", "add_log",
		"next_layer", "client_connected", "client_disconnected",
		"server_connect", "server_connected", "server_disconnected", "server_connect_error",
		"socks5_auth",
		"requestheaders", "request", "responseheaders", "response", "error",
		"http_connect", "http_connect_upstream", "http_connected", "http_connect_error",
		"websocket_start", "websocket_message", "websocket_end",
		"tcp_start", "tcp_message", "tcp_end", "tcp_error",
		"udp_start", "udp_message", "udp_end", "udp_error",
		"dns_request", "dns_response", "dns_error",
		"tls_clienthello", "tls_start_client", "tls_start_server",
		"tls_established_client", "tls_established_server", "tls_failed_client", "tls_failed_server",
		"quic_start_client", "quic_start_server",
	}
	if len(want) != 46 {
		t.Fatalf("the expected list has %d hooks, want mitmproxy's 46", len(want))
	}
	var got []string
	for _, s := range hookSpecs {
		got = append(got, s.hook.Name())
		if n := s.handler.NumMethod(); n != 1 {
			t.Errorf("handler %v of %s has %d methods, want 1", s.handler, s.hook.Name(), n)
		}
		if !strings.HasSuffix(s.handler.Name(), "Handler") || s.handler.Method(0).Name+"Handler" != s.handler.Name() {
			t.Errorf("handler %v of %s does not have its method's name", s.handler, s.hook.Name())
		}
		if handled, err := s.hook.invoke(t.Context(), struct{}{}); handled || err != nil {
			t.Errorf("%s handled by an addon without handlers: %v, %v", s.hook.Name(), handled, err)
		}
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("hook names (-want +got):\n%s", diff)
	}
}

func TestTriggerOrder(t *testing.T) {
	e := newEnv(t)
	j := &journal{}
	grandchild := &hooker{name: "grandchild", j: j}
	child1 := &hooker{name: "child1", j: j, children: []any{grandchild}}
	child2 := &hooker{name: "child2", j: j}
	parent := &hooker{name: "parent", j: j, children: []any{child1, child2}}
	last := &hooker{name: "last", j: j}
	if err := e.m.Add(t.Context(), parent, last); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := e.m.Trigger(t.Context(), RunningHook{}); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	want := []string{"running parent", "running child1", "running grandchild", "running child2", "running last"}
	if diff := cmp.Diff(want, j.got()); diff != "" {
		t.Errorf("hook order (-want +got):\n%s", diff)
	}
	if chain := e.m.Chain(); len(chain) != 2 || chain[0] != parent || chain[1] != last {
		t.Errorf("chain = %v, want [parent last]", chain)
	}
	for _, n := range []string{"parent", "child1", "grandchild", "child2", "last"} {
		if e.m.Get(n) == nil {
			t.Errorf("Get(%q) = nil, want the registered addon", n)
		}
	}
	if e.m.Len() != 2 {
		t.Errorf("Len() = %d, want 2", e.m.Len())
	}
}

func TestTriggerErrors(t *testing.T) {
	errBoom := errors.New("boom")
	tests := map[string]struct {
		build    func(j *journal) []any
		wantErr  bool
		wantJrnl []string
		wantLog  []string
	}{
		"error: handler error is logged and the chain continues, skipping the rest of the failing tree": {
			build: func(j *journal) []any {
				return []any{
					&hooker{name: "a", j: j, children: []any{&hooker{name: "a1", j: j, err: errBoom}, &hooker{name: "a2", j: j}}},
					&hooker{name: "b", j: j},
				}
			},
			wantJrnl: []string{"running a", "running a1", "running b"},
			wantLog:  []string{"ERROR Addon error: boom addon=a"},
		},
		"error: handler panic is logged and the chain continues": {
			build: func(j *journal) []any {
				return []any{&hooker{name: "a", j: j, panicMsg: "addon bug"}, &hooker{name: "b", j: j}}
			},
			wantJrnl: []string{"running a", "running b"},
			wantLog:  []string{"ERROR Addon error: panic: addon bug addon=a"},
		},
		"success: AddonHalt stops the chain silently": {
			build: func(j *journal) []any {
				return []any{&hooker{name: "a", j: j, err: fmt.Errorf("enough: %w", ErrAddonHalt)}, &hooker{name: "b", j: j}}
			},
			wantJrnl: []string{"running a"},
		},
		"error: OptionsError stops the chain and is returned": {
			build: func(j *journal) []any {
				return []any{&hooker{name: "a", j: j, err: options.Errorf("bad value")}, &hooker{name: "b", j: j}}
			},
			wantErr:  true,
			wantJrnl: []string{"running a"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			j := &journal{}
			if err := e.m.Add(t.Context(), tt.build(j)...); err != nil {
				t.Fatalf("Add: %v", err)
			}
			err := e.m.Trigger(t.Context(), RunningHook{})
			if _, isOpt := errors.AsType[*options.OptionsError](err); isOpt != tt.wantErr || (err != nil && !tt.wantErr) {
				t.Fatalf("Trigger error = %v, want an OptionsError: %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.wantJrnl, j.got()); diff != "" {
				t.Errorf("handlers run (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantLog, e.log.got()); diff != "" {
				t.Errorf("log records (-want +got):\n%s", diff)
			}
		})
	}
}

// optAddon adds an option and a command on load.
type optAddon struct {
	j    *journal
	help string
}

func (a *optAddon) Load(ctx context.Context, l *Loader) error {
	if err := l.AddOption(ctx, "upstream_cert", options.TypeBool, true, a.help); err != nil {
		return err
	}
	return l.AddCommand("optaddon.echo", func(s string) string { return "echo " + s }, command.WithParams("s"))
}

func (a *optAddon) Configure(_ context.Context, updated map[string]struct{}) error {
	a.j.add("configure optaddon " + strings.Join(slices.Sorted(maps.Keys(updated)), ","))
	return nil
}

func TestRegisterLoad(t *testing.T) {
	e := newEnv(t)
	j := &journal{}
	early := &hooker{name: "early", j: j}
	if err := e.m.Add(t.Context(), early); err != nil {
		t.Fatalf("Add(early): %v", err)
	}
	// A value set before the option exists is applied once an addon adds
	// the option.
	if err := e.opts.SetDeferred(t.Context(), "upstream_cert=false"); err != nil {
		t.Fatalf("SetDeferred: %v", err)
	}

	a := &optAddon{j: j, help: "Connect to upstream server to look up certificate details."}
	if err := e.m.Add(t.Context(), a); err != nil {
		t.Fatalf("Add(optAddon): %v", err)
	}
	if got := e.opts.Bool("upstream_cert"); got {
		t.Errorf("upstream_cert = %v after the deferred value was processed, want false", got)
	}
	got, err := e.cmds.Call(t.Context(), "optaddon.echo", "x")
	if err != nil || got != "echo x" {
		t.Errorf("Call(optaddon.echo) = %v, %v; want the command added on load", got, err)
	}
	// The new addon joins the chain only after it is registered, so both
	// the option added during load and the deferred value applied after it
	// fire configure on the addons already in the chain only, as in
	// mitmproxy.
	want := []string{
		"configure early upstream_cert",
		"configure early upstream_cert",
	}
	if diff := cmp.Diff(want, j.got()); diff != "" {
		t.Errorf("configure calls (-want +got):\n%s", diff)
	}
}

func TestLoaderAddOptionAgain(t *testing.T) {
	tests := map[string]struct {
		help     string
		wantWarn bool
	}{
		"success: same signature is a no-op":           {help: "Connect to upstream server to look up certificate details."},
		"success: different signature warns, replaces": {help: "Another help text.", wantWarn: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			j := &journal{}
			observer := &hooker{name: "observer", j: j}
			first := &optAddon{j: &journal{}, help: "Connect to upstream server to look up certificate details."}
			if err := e.m.Add(t.Context(), observer, first); err != nil {
				t.Fatalf("Add: %v", err)
			}
			before := len(j.got())
			err := e.m.Do(t.Context(), func(ctx context.Context) error {
				return (&Loader{m: e.m, addon: first}).AddOption(ctx, "upstream_cert", options.TypeBool, true, tt.help)
			})
			if err != nil {
				t.Fatalf("AddOption: %v", err)
			}
			reconfigured := len(j.got()) > before
			warned := slices.Contains(e.log.got(), "WARN Over-riding existing option upstream_cert addon=optaddon")
			if reconfigured != tt.wantWarn || warned != tt.wantWarn {
				t.Errorf("re-adding: configure fired %v, warned %v; want %v for both", reconfigured, warned, tt.wantWarn)
			}
			if o, _ := e.opts.Lookup("upstream_cert"); o.Help() != tt.help {
				t.Errorf("help = %q, want %q", o.Help(), tt.help)
			}
		})
	}
}

// badSig has a Configure method that takes a context but the wrong
// options argument: a near miss of the handler, which would never be
// called.
type badSig struct{}

func (badSig) Configure(context.Context, []string) error { return nil }

// noErrDone has a Done handler without the error result.
type noErrDone struct{}

func (noErrDone) Done(context.Context) {}

// uncomparable cannot be removed by identity: a slice makes the struct
// type uncomparable.
type uncomparable struct{ _ []string }

func TestRegisterRefused(t *testing.T) {
	tests := map[string]struct {
		addons  func() []any
		wantMsg string
	}{
		"error: duplicate name": {
			addons:  func() []any { return []any{&hooker{name: "x"}, &hooker{name: "x"}} },
			wantMsg: "An addon called 'x' already exists.",
		},
		"error: duplicate name in a sub-addon": {
			addons: func() []any {
				return []any{&hooker{name: "x"}, &hooker{name: "y", children: []any{&hooker{name: "x"}}}}
			},
			wantMsg: "An addon called 'x' already exists.",
		},
		"error: handler with the wrong signature": {
			addons:  func() []any { return []any{&badSig{}} },
			wantMsg: "handler Configure for the configure hook has type func(context.Context, []string) error",
		},
		"error: handler without the error result": {
			addons:  func() []any { return []any{&noErrDone{}} },
			wantMsg: "handler Done for the done hook has type func(context.Context)",
		},
		"error: uncomparable addon": {
			addons:  func() []any { return []any{uncomparable{}} },
			wantMsg: "uncomparable value of type addon.uncomparable",
		},
		"error: struct value holding an uncomparable value": {
			addons:  func() []any { return []any{holder{v: []string{"x"}}} },
			wantMsg: "uncomparable value of type addon.holder",
		},
		"error: nil addon": {
			addons:  func() []any { return []any{nil} },
			wantMsg: "nil addon",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			err := e.m.Add(t.Context(), tt.addons()...)
			if !errors.Is(err, ErrAddonManager) || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("Add error = %v, want ErrAddonManager containing %q", err, tt.wantMsg)
			}
		})
	}
}

func TestDefaultName(t *testing.T) {
	e := newEnv(t)
	a := &optAddon{j: &journal{}, help: "h"}
	if err := e.m.Add(t.Context(), a); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if e.m.Get("optaddon") != a || !e.m.Contains(&optAddon{}) {
		t.Errorf("addon without Name() is not registered as %q", "optaddon")
	}
}

func TestRemoveAndClear(t *testing.T) {
	e := newEnv(t)
	j := &journal{}
	child := &hooker{name: "child", j: j}
	a := &hooker{name: "a", j: j, children: []any{child}}
	b := &hooker{name: "b", j: j}
	if err := e.m.Add(t.Context(), a, b); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := e.m.Remove(t.Context(), a); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if e.m.Get("a") != nil || e.m.Get("child") != nil || e.m.Len() != 1 {
		t.Errorf("after Remove: a=%v child=%v len=%d, want both gone and one addon left", e.m.Get("a"), e.m.Get("child"), e.m.Len())
	}
	err := e.m.Remove(t.Context(), a)
	if !errors.Is(err, ErrAddonManager) || !strings.Contains(err.Error(), "No such addon: a") {
		t.Errorf("second Remove error = %v, want No such addon", err)
	}
	if err := e.m.Clear(t.Context()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if e.m.Len() != 0 || e.m.Get("b") != nil {
		t.Errorf("after Clear: len=%d b=%v, want none", e.m.Len(), e.m.Get("b"))
	}
	var done []string
	for _, c := range j.got() {
		if strings.HasPrefix(c, "done ") {
			done = append(done, c)
		}
	}
	if diff := cmp.Diff([]string{"done a", "done child", "done b"}, done); diff != "" {
		t.Errorf("done calls (-want +got):\n%s", diff)
	}
}

// TestDoOptionsSet changes an option from a goroutine outside the hooks
// through Do; the configure hook fired by the change re-enters the dispatch
// lock instead of deadlocking.
func TestDoOptionsSet(t *testing.T) {
	e := newEnv(t)
	j := &journal{}
	if err := e.m.Add(t.Context(), &optAddon{j: j, help: "h"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	within(t, "options.Set inside Do", func() {
		err := e.m.Do(t.Context(), func(ctx context.Context) error {
			return e.opts.Set(ctx, "upstream_cert=false")
		})
		if err != nil {
			t.Errorf("Do: %v", err)
		}
	})
	if e.opts.Bool("upstream_cert") {
		t.Error("upstream_cert is still true")
	}
	if got := j.got(); len(got) == 0 || got[len(got)-1] != "configure optaddon upstream_cert" {
		t.Errorf("configure calls = %v, want the last one for upstream_cert", got)
	}
}

// strictAddon refuses upstream_cert=false.
type strictAddon struct{ opts *options.Manager }

func (a *strictAddon) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated["upstream_cert"]; ok && !a.opts.Bool("upstream_cert") {
		return options.Errorf("upstream_cert cannot be disabled")
	}
	return nil
}

// TestConfigureRollback rejects an option change in configure; the change
// is rolled back and the error reaches the caller.
func TestConfigureRollback(t *testing.T) {
	e := newEnv(t)
	if err := e.m.Add(t.Context(), &optAddon{j: &journal{}, help: "h"}, &strictAddon{opts: e.opts}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	var err error
	within(t, "rejected option change", func() { err = e.opts.Set(t.Context(), "upstream_cert=false") })
	if _, ok := errors.AsType[*options.OptionsError](err); !ok {
		t.Fatalf("Set error = %v, want an OptionsError", err)
	}
	if !e.opts.Bool("upstream_cert") {
		t.Error("upstream_cert was not rolled back to true")
	}
}

// cmdAddon registers a command that changes an option, which fires
// configure, and calls it from its running hook.
type cmdAddon struct {
	m *Manager
	j *journal
}

func (a *cmdAddon) Load(ctx context.Context, l *Loader) error {
	if err := l.AddOption(ctx, "flag", options.TypeBool, false, "A flag."); err != nil {
		return err
	}
	return l.AddCommand("flag.set", func(ctx context.Context) error {
		return a.m.Options().Set(ctx, "flag=true")
	})
}

func (a *cmdAddon) Configure(_ context.Context, updated map[string]struct{}) error {
	a.j.add("configure " + strings.Join(slices.Sorted(maps.Keys(updated)), ","))
	return nil
}

func (a *cmdAddon) Running(ctx context.Context) error {
	_, err := a.m.Commands().Call(ctx, "flag.set")
	return err
}

// TestReentrantCommandInHook calls a command from inside a hook; the
// command fires configure through the dispatch lock the hook holds.
func TestReentrantCommandInHook(t *testing.T) {
	e := newEnv(t)
	j := &journal{}
	if err := e.m.Add(t.Context(), &cmdAddon{m: e.m, j: j}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	within(t, "command inside a hook", func() {
		if err := e.m.Trigger(t.Context(), RunningHook{}); err != nil {
			t.Errorf("Trigger: %v", err)
		}
	})
	if !e.opts.Bool("flag") {
		t.Error("the command did not set the option")
	}
	// The option added during the addon's own load does not reach it,
	// because it joins the chain after load; the command's change does.
	if diff := cmp.Diff([]string{"configure flag"}, j.got()); diff != "" {
		t.Errorf("configure calls (-want +got):\n%s", diff)
	}
	if logs := e.log.got(); len(logs) != 0 {
		t.Errorf("unexpected log records: %v", logs)
	}
}

// concurrentAddon releases the lock in its running hook.
type concurrentAddon struct {
	name string
	j    *journal
	body func(ctx context.Context) error
}

func (a *concurrentAddon) Name() string { return a.name }

func (a *concurrentAddon) Running(ctx context.Context) error {
	// The returned context is deliberately dropped: the addons after this
	// one must still get a valid frame from the chain.
	_, err := Concurrent(ctx, a.body)
	a.j.add(fmt.Sprintf("running %s err=%v", a.name, err))
	return nil
}

// usesFrame re-enters the dispatch lock with the context its hook got.
type usesFrame struct {
	m *Manager
	j *journal
}

func (a *usesFrame) Running(ctx context.Context) error {
	return a.m.Do(ctx, func(context.Context) error {
		a.j.add("running usesframe")
		return nil
	})
}

// TestConcurrentInChain releases the lock in one addon's hook; the addons
// after it in the chain get the fresh frame, and a Concurrent call from a
// nested dispatch is refused.
func TestConcurrentInChain(t *testing.T) {
	t.Run("success: later addons get a valid frame", func(t *testing.T) {
		e := newEnv(t)
		j := &journal{}
		c := &concurrentAddon{name: "c", j: j, body: func(context.Context) error { return nil }}
		if err := e.m.Add(t.Context(), c, &usesFrame{m: e.m, j: j}); err != nil {
			t.Fatalf("Add: %v", err)
		}
		within(t, "Trigger", func() {
			if err := e.m.Trigger(t.Context(), RunningHook{}); err != nil {
				t.Errorf("Trigger: %v", err)
			}
		})
		if diff := cmp.Diff([]string{"running c err=<nil>", "running usesframe"}, j.got()); diff != "" {
			t.Errorf("calls (-want +got):\n%s", diff)
		}
	})
	t.Run("error: nested dispatch refuses Concurrent", func(t *testing.T) {
		e := newEnv(t)
		j := &journal{}
		c := &concurrentAddon{name: "c", j: j, body: func(context.Context) error { return nil }}
		if err := e.m.Add(t.Context(), c); err != nil {
			t.Fatalf("Add: %v", err)
		}
		within(t, "Trigger inside Do", func() {
			err := e.m.Do(t.Context(), func(ctx context.Context) error {
				return e.m.Trigger(ctx, RunningHook{})
			})
			if err != nil {
				t.Errorf("Do: %v", err)
			}
		})
		got := j.got()
		if len(got) != 1 || !strings.Contains(got[0], "cannot be called from sync context") {
			t.Errorf("calls = %v, want one refused Concurrent", got)
		}
	})
}

func TestCloseStopsConfigure(t *testing.T) {
	e := newEnv(t)
	j := &journal{}
	if err := e.m.Add(t.Context(), &optAddon{j: j, help: "h"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	e.m.Close()
	before := len(j.got())
	if err := e.opts.Set(t.Context(), "upstream_cert=false"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(j.got()) != before {
		t.Errorf("configure fired after Close: %v", j.got()[before:])
	}
}

// echoAddon adds the command "<prefix>.echo" on load, and optionally fails
// its load afterwards.
type echoAddon struct {
	name, prefix string
	version      int
	failLoad     error
}

func (a *echoAddon) Name() string { return a.name }

func (a *echoAddon) Load(_ context.Context, l *Loader) error {
	v := a.version
	if err := l.AddCommand(a.prefix+".echo", func(s string) string { return fmt.Sprintf("v%d %s", v, s) }, command.WithParams("s")); err != nil {
		return err
	}
	return a.failLoad
}

func TestAddonCommandsFollowTheAddon(t *testing.T) {
	t.Run("success: remove then load again re-adds the commands", func(t *testing.T) {
		e := newEnv(t)
		old := &echoAddon{name: "script", prefix: "script", version: 1}
		if err := e.m.Add(t.Context(), old); err != nil {
			t.Fatalf("Add(v1): %v", err)
		}
		if err := e.m.Remove(t.Context(), old); err != nil {
			t.Fatalf("Remove(v1): %v", err)
		}
		if _, err := e.cmds.Call(t.Context(), "script.echo", "x"); !errors.Is(err, command.ErrUnknownCommand) {
			t.Fatalf("Call after Remove error = %v, want ErrUnknownCommand", err)
		}
		reloaded := &echoAddon{name: "script", prefix: "script", version: 2}
		if err := e.m.Add(t.Context(), reloaded); err != nil {
			t.Fatalf("Add(v2) after Remove: %v", err)
		}
		got, err := e.cmds.Call(t.Context(), "script.echo", "x")
		if err != nil || got != "v2 x" {
			t.Errorf("Call(script.echo) = %v, %v; want the reloaded addon's command", got, err)
		}
	})

	t.Run("error: two live addons cannot add one command", func(t *testing.T) {
		e := newEnv(t)
		if err := e.m.Add(t.Context(), &echoAddon{name: "first", prefix: "shared", version: 1}); err != nil {
			t.Fatalf("Add(first): %v", err)
		}
		err := e.m.Add(t.Context(), &echoAddon{name: "second", prefix: "shared", version: 2})
		if !errors.Is(err, command.ErrDuplicateCommand) {
			t.Fatalf("Add(second) error = %v, want ErrDuplicateCommand", err)
		}
		got, err := e.cmds.Call(t.Context(), "shared.echo", "x")
		if err != nil || got != "v1 x" {
			t.Errorf("Call(shared.echo) = %v, %v; want the first addon's command kept", got, err)
		}
		if e.m.Get("second") != nil {
			t.Error("the addon whose load failed is registered")
		}
	})

	t.Run("error: a failed load takes back the commands it added", func(t *testing.T) {
		e := newEnv(t)
		errLoad := errors.New("load failed")
		err := e.m.Add(t.Context(), &echoAddon{name: "broken", prefix: "broken", failLoad: errLoad})
		if !errors.Is(err, errLoad) {
			t.Fatalf("Add error = %v, want %v", err, errLoad)
		}
		if _, err := e.cmds.Call(t.Context(), "broken.echo", "x"); !errors.Is(err, command.ErrUnknownCommand) {
			t.Errorf("Call after a failed load error = %v, want ErrUnknownCommand", err)
		}
		if err := e.m.Add(t.Context(), &echoAddon{name: "broken", prefix: "broken", version: 2}); err != nil {
			t.Errorf("Add after the failed load: %v", err)
		}
	})

	t.Run("success: Clear unregisters every addon's commands", func(t *testing.T) {
		e := newEnv(t)
		if err := e.m.Add(t.Context(), &echoAddon{name: "a", prefix: "a"}, &echoAddon{name: "b", prefix: "b"}); err != nil {
			t.Fatalf("Add: %v", err)
		}
		if err := e.m.Clear(t.Context()); err != nil {
			t.Fatalf("Clear: %v", err)
		}
		var left []string
		for n := range e.cmds.Commands() {
			left = append(left, n)
		}
		if len(left) != 0 {
			t.Errorf("commands left after Clear: %v", left)
		}
	})
}

// TestDefaultLoggerAtLogTime installs the default logger after the
// Manager exists; handler errors still reach it.
func TestDefaultLoggerAtLogTime(t *testing.T) {
	saved := slog.Default()
	t.Cleanup(func() { slog.SetDefault(saved) })

	m := NewManager(options.NewManager(), command.NewManager(), Config{})
	t.Cleanup(m.Close)
	rec := &recordHandler{}
	slog.SetDefault(slog.New(rec))

	if err := m.Add(t.Context(), &hooker{name: "a", j: &journal{}, err: errors.New("boom")}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := m.Trigger(t.Context(), RunningHook{}); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if diff := cmp.Diff([]string{"ERROR Addon error: boom addon=a"}, rec.got()); diff != "" {
		t.Errorf("records on the default logger (-want +got):\n%s", diff)
	}
}

// keeper keeps the context of its configure hook and uses it in its
// running hook, after the lock was released in between.
type keeper struct {
	m    *Manager
	kept context.Context
}

func (k *keeper) Configure(ctx context.Context, _ map[string]struct{}) error {
	k.kept = ctx
	return nil
}

func (k *keeper) Running(context.Context) error {
	return k.m.Do(k.kept, func(context.Context) error { return nil })
}

// TestStaleFrameInHandlerIsNotSwallowed uses a stale frame inside a
// handler. In test binaries the panic must reach the caller instead of
// being logged as an addon error.
func TestStaleFrameInHandlerIsNotSwallowed(t *testing.T) {
	e := newEnv(t)
	k := &keeper{m: e.m}
	if err := e.m.Add(t.Context(), k); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := e.m.Trigger(t.Context(), ConfigureHook{Updated: map[string]struct{}{}}); err != nil {
		t.Fatalf("Trigger(configure): %v", err)
	}
	r := capturePanic(func() { _ = e.m.Trigger(t.Context(), RunningHook{}) })
	if perr, ok := r.(error); !ok || !errors.Is(perr, ErrStaleFrame) {
		t.Fatalf("recovered %v, want the stale-frame panic", r)
	}
	if logs := e.log.got(); len(logs) != 0 {
		t.Errorf("stale frame logged as an addon error: %v", logs)
	}
	// The lock was released despite the panic.
	within(t, "dispatch after the panic", func() {
		if err := e.m.Trigger(t.Context(), DoneHook{}); err != nil {
			t.Errorf("Trigger: %v", err)
		}
	})
}

// syncProbe calls Concurrent from the handler of one hook and records what
// happened, so that a test can tell whether the lock was released there.
type syncProbe struct {
	name  string
	probe string // "load", "configure" or "done"
	body  func(ctx context.Context) error
	ran   bool
	errs  []error
}

func (p *syncProbe) Name() string { return p.name }

func (p *syncProbe) try(ctx context.Context, hook string) {
	if hook != p.probe {
		return
	}
	_, err := Concurrent(ctx, func(ctx context.Context) error {
		p.ran = true
		if p.body != nil {
			return p.body(ctx)
		}
		return nil
	})
	p.errs = append(p.errs, err)
}

func (p *syncProbe) Load(ctx context.Context, l *Loader) error {
	if p.probe == "configure" {
		if err := l.AddOption(ctx, "probe_flag", options.TypeBool, false, "A flag."); err != nil {
			return err
		}
	}
	p.try(ctx, "load")
	return nil
}

func (p *syncProbe) Configure(ctx context.Context, _ map[string]struct{}) error {
	p.try(ctx, "configure")
	return nil
}

func (p *syncProbe) Done(ctx context.Context) error {
	p.try(ctx, "done")
	return nil
}

// TestConcurrentRefusedInSyncHooks calls Concurrent from the hooks that
// mitmproxy dispatches synchronously. Releasing the lock there would let
// other dispatch run in the middle of a registration, a removal or an
// option change, so Concurrent must refuse even at the outermost level.
func TestConcurrentRefusedInSyncHooks(t *testing.T) {
	tests := map[string]struct {
		probe   string
		fire    func(t *testing.T, e *testEnv, p *syncProbe) error
		wantMsg string
	}{
		"error: load of Add": {
			probe:   "load",
			fire:    func(*testing.T, *testEnv, *syncProbe) error { return nil },
			wantMsg: "load",
		},
		"error: configure fired by an option change": {
			probe: "configure",
			fire: func(t *testing.T, e *testEnv, _ *syncProbe) error {
				return e.opts.Set(t.Context(), "probe_flag=true")
			},
			wantMsg: "configure",
		},
		"error: done of Remove": {
			probe: "done",
			fire: func(t *testing.T, e *testEnv, p *syncProbe) error {
				return e.m.Remove(t.Context(), p)
			},
			wantMsg: "done",
		},
		"error: done of Clear": {
			probe: "done",
			fire: func(t *testing.T, e *testEnv, _ *syncProbe) error {
				return e.m.Clear(t.Context())
			},
			wantMsg: "done",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			p := &syncProbe{name: "probe", probe: tt.probe}
			within(t, "Add and fire", func() {
				if err := e.m.Add(t.Context(), p); err != nil {
					t.Errorf("Add: %v", err)
					return
				}
				if err := tt.fire(t, e, p); err != nil {
					t.Errorf("fire: %v", err)
				}
			})
			if p.ran {
				t.Error("the body of Concurrent ran inside a synchronous hook")
			}
			if len(p.errs) != 1 {
				t.Fatalf("Concurrent called %d times, want 1", len(p.errs))
			}
			err := p.errs[0]
			if !errors.Is(err, ErrSyncContext) || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Concurrent error = %v, want ErrSyncContext naming the %s hook", err, tt.wantMsg)
			}
		})
	}

	t.Run("success: done fired through Trigger may release the lock", func(t *testing.T) {
		// The master fires done at shutdown through Trigger, as mitmproxy
		// fires it through the asynchronous trigger_event.
		e := newEnv(t)
		p := &syncProbe{name: "probe", probe: "done"}
		within(t, "Trigger(done)", func() {
			if err := e.m.Add(t.Context(), p); err != nil {
				t.Errorf("Add: %v", err)
				return
			}
			if err := e.m.Trigger(t.Context(), DoneHook{}); err != nil {
				t.Errorf("Trigger: %v", err)
			}
		})
		if !p.ran || len(p.errs) != 1 || p.errs[0] != nil {
			t.Errorf("ran=%v errs=%v, want the body run without error", p.ran, p.errs)
		}
	})
}

// TestNoSecondAddonDuringLoad releases the lock from a load handler and
// registers a second addon of the same name in the gap. Refusing
// Concurrent in load keeps the name check and the record of the name in
// one hold of the lock.
func TestNoSecondAddonDuringLoad(t *testing.T) {
	e := newEnv(t)
	second := &hooker{name: "dup", j: &journal{}}
	var addErr error
	first := &syncProbe{name: "dup", probe: "load", body: func(context.Context) error {
		addErr = e.m.Add(t.Context(), second)
		return nil
	}}
	within(t, "Add(first)", func() {
		if err := e.m.Add(t.Context(), first); err != nil {
			t.Errorf("Add(first): %v", err)
		}
	})
	if first.ran {
		t.Errorf("the load handler released the lock; Add(second) in the gap returned %v", addErr)
	}
	if len(first.errs) != 1 || !errors.Is(first.errs[0], ErrSyncContext) {
		t.Errorf("Concurrent errors = %v, want one ErrSyncContext", first.errs)
	}
	err := e.m.Add(t.Context(), second)
	if !errors.Is(err, ErrAddonManager) || !strings.Contains(err.Error(), "An addon called 'dup' already exists.") {
		t.Errorf("Add(second) error = %v, want the duplicate name refused", err)
	}
	if got := e.m.Get("dup"); got != first || e.m.Len() != 1 {
		t.Errorf("Get(dup) = %p, Len = %d; want the first addon alone", got, e.m.Len())
	}
}

// withWaitGroup embeds a sync.WaitGroup, whose Done method shares the name
// of the done handler.
type withWaitGroup struct {
	sync.WaitGroup
	j *journal
}

func (a *withWaitGroup) Running(context.Context) error {
	a.j.add("running waitgroup")
	return nil
}

// withContext embeds a context.Context, whose Done method shares the name
// of the done handler.
type withContext struct {
	context.Context //nolint:containedctx // The embedding is what the test is about.
	j               *journal
}

func (a *withContext) Running(context.Context) error {
	a.j.add("running context")
	return nil
}

// withError implements error, whose Error method shares the name of the
// error handler.
type withError struct{ j *journal }

func (*withError) Error() string { return "an addon that is an error" }

func (a *withError) Running(context.Context) error {
	a.j.add("running error")
	return nil
}

// TestHookNamedMethodsThatAreNotHandlers registers addons whose ordinary
// Go methods share a name with a hook handler. A method whose first
// parameter is not a context.Context is not a handler: the addon
// registers, receives the hooks it does handle, and the method is never
// called. sync.WaitGroup.Done would panic on a negative counter if the
// done hook reached it.
func TestHookNamedMethodsThatAreNotHandlers(t *testing.T) {
	tests := map[string]struct {
		addon func(j *journal) any
		want  string
	}{
		"success: embeds sync.WaitGroup": {
			addon: func(j *journal) any { return &withWaitGroup{j: j} },
			want:  "running waitgroup",
		},
		"success: embeds context.Context": {
			addon: func(j *journal) any { return &withContext{Context: t.Context(), j: j} },
			want:  "running context",
		},
		"success: implements error": {
			addon: func(j *journal) any { return &withError{j: j} },
			want:  "running error",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			j := &journal{}
			a := tt.addon(j)
			if err := e.m.Add(t.Context(), a); err != nil {
				t.Fatalf("Add: %v", err)
			}
			if err := e.m.Trigger(t.Context(), RunningHook{}); err != nil {
				t.Fatalf("Trigger(running): %v", err)
			}
			if err := e.m.Remove(t.Context(), a); err != nil {
				t.Fatalf("Remove: %v", err)
			}
			if diff := cmp.Diff([]string{tt.want}, j.got()); diff != "" {
				t.Errorf("hook calls (-want +got):\n%s", diff)
			}
			if logs := e.log.got(); len(logs) != 0 {
				t.Errorf("unexpected log records: %v", logs)
			}
		})
	}
}

// holder is a comparable struct type whose values are uncomparable when
// the interface field holds a slice: comparing two such values panics.
type holder struct{ v any }

// TestRemoveUncomparableValue removes a struct value that cannot be
// compared while a comparable value of the same type is registered.
func TestRemoveUncomparableValue(t *testing.T) {
	e := newEnv(t)
	kept := holder{v: 1}
	if err := e.m.Add(t.Context(), kept); err != nil {
		t.Fatalf("Add: %v", err)
	}
	var err error
	if r := capturePanic(func() { err = e.m.Remove(t.Context(), holder{v: []string{"x"}}) }); r != nil {
		t.Fatalf("Remove panicked: %v", r)
	}
	if !errors.Is(err, ErrAddonManager) || !strings.Contains(err.Error(), "uncomparable value of type addon.holder") {
		t.Errorf("Remove error = %v, want ErrAddonManager naming the uncomparable value", err)
	}
	if got := e.m.Get("holder"); got != kept || e.m.Len() != 1 {
		t.Errorf("Get(holder) = %v, Len = %d; want the registered value kept", got, e.m.Len())
	}
}

// introspective consults the manager from its Name and Addons methods,
// which the manager calls while it registers the addon.
type introspective struct {
	m        *Manager
	children []any
}

func (a *introspective) Name() string {
	_ = a.m.Get("child")
	return "introspective"
}

func (a *introspective) Addons() []any {
	_ = a.m.Len()
	return a.children
}

// TestRegisterCallsAddonCodeUnlocked registers an addon whose Name and
// Addons methods read the manager. The manager must not hold its own lock
// while it calls them, or they deadlock.
func TestRegisterCallsAddonCodeUnlocked(t *testing.T) {
	e := newEnv(t)
	child := &hooker{name: "child", j: &journal{}}
	a := &introspective{m: e.m, children: []any{child}}
	within(t, "Add", func() {
		if err := e.m.Add(t.Context(), a); err != nil {
			t.Errorf("Add: %v", err)
		}
	})
	if e.m.Get("introspective") != a || e.m.Get("child") != child {
		t.Errorf("Get(introspective) = %v, Get(child) = %v; want both registered", e.m.Get("introspective"), e.m.Get("child"))
	}
	within(t, "Remove", func() {
		if err := e.m.Remove(t.Context(), a); err != nil {
			t.Errorf("Remove: %v", err)
		}
	})
}
