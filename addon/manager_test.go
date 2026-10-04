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

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
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
	want := []string{
		"load", "configure", "running", "done", "add_log",
		"next_layer", "client_connected", "client_disconnected",
		"server_connect", "server_connected", "server_disconnected", "server_connect_error",
		"socks5_auth",
		"tls_clienthello", "tls_start_client", "tls_start_server",
		"tls_established_client", "tls_established_server", "tls_failed_client", "tls_failed_server",
		"quic_start_client", "quic_start_server",
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

// everyHook implements every handler and records the argument each
// receives.
type everyHook struct {
	got map[string]any
}

func (a *everyHook) rec(name string, arg any) error { a.got[name] = arg; return nil }

func (a *everyHook) Load(_ context.Context, l *Loader) error { return a.rec("load", l) }
func (a *everyHook) Configure(_ context.Context, u map[string]struct{}) error {
	return a.rec("configure", u)
}
func (a *everyHook) Running(context.Context) error              { return a.rec("running", nil) }
func (a *everyHook) Done(context.Context) error                 { return a.rec("done", nil) }
func (a *everyHook) AddLog(_ context.Context, e LogEntry) error { return a.rec("add_log", e) }
func (a *everyHook) NextLayer(_ context.Context, d *hookdata.NextLayer) error {
	return a.rec("next_layer", d)
}

func (a *everyHook) ClientConnected(_ context.Context, c *connection.Client) error {
	return a.rec("client_connected", c)
}

func (a *everyHook) ClientDisconnected(_ context.Context, c *connection.Client) error {
	return a.rec("client_disconnected", c)
}

func (a *everyHook) ServerConnect(_ context.Context, d *hookdata.ServerConnection) error {
	return a.rec("server_connect", d)
}

func (a *everyHook) ServerConnected(_ context.Context, d *hookdata.ServerConnection) error {
	return a.rec("server_connected", d)
}

func (a *everyHook) ServerDisconnected(_ context.Context, d *hookdata.ServerConnection) error {
	return a.rec("server_disconnected", d)
}

func (a *everyHook) ServerConnectError(_ context.Context, d *hookdata.ServerConnection) error {
	return a.rec("server_connect_error", d)
}

func (a *everyHook) Socks5Auth(_ context.Context, d *hookdata.Socks5Auth) error {
	return a.rec("socks5_auth", d)
}

func (a *everyHook) TLSClientHello(_ context.Context, d *hookdata.ClientHello) error {
	return a.rec("tls_clienthello", d)
}

func (a *everyHook) TLSStartClient(_ context.Context, d *hookdata.TLS) error {
	return a.rec("tls_start_client", d)
}

func (a *everyHook) TLSStartServer(_ context.Context, d *hookdata.TLS) error {
	return a.rec("tls_start_server", d)
}

func (a *everyHook) TLSEstablishedClient(_ context.Context, d *hookdata.TLS) error {
	return a.rec("tls_established_client", d)
}

func (a *everyHook) TLSEstablishedServer(_ context.Context, d *hookdata.TLS) error {
	return a.rec("tls_established_server", d)
}

func (a *everyHook) TLSFailedClient(_ context.Context, d *hookdata.TLS) error {
	return a.rec("tls_failed_client", d)
}

func (a *everyHook) TLSFailedServer(_ context.Context, d *hookdata.TLS) error {
	return a.rec("tls_failed_server", d)
}

func (a *everyHook) QUICStartClient(_ context.Context, d *hookdata.QUICTLS) error {
	return a.rec("quic_start_client", d)
}

func (a *everyHook) QUICStartServer(_ context.Context, d *hookdata.QUICTLS) error {
	return a.rec("quic_start_server", d)
}

// TestHooksReachHandlers dispatches every hook through Trigger and checks
// that the handler is called once with the hook's argument.
func TestHooksReachHandlers(t *testing.T) {
	client := connection.NewClient(connection.Address{Host: "127.0.0.1", Port: 50000}, connection.Address{Host: "127.0.0.1", Port: 8080}, 1)
	hctx := &hookdata.Context{Client: client, Server: &connection.Server{}}
	tlsData := &hookdata.TLS{Conn: &hctx.Client.Connection, Context: hctx}
	quicData := &hookdata.QUICTLS{Conn: &hctx.Server.Connection, Context: hctx}
	serverConn := &hookdata.ServerConnection{Server: hctx.Server, Client: client}
	loader := &Loader{}
	updated := map[string]struct{}{"anticache": {}}
	entry := LogEntry{Msg: "hello", Level: LevelAlert}

	tests := map[string]struct {
		hook Hook
		arg  any
	}{
		"success: load":                   {hook: LoadHook{Loader: loader}, arg: loader},
		"success: configure":              {hook: ConfigureHook{Updated: updated}, arg: updated},
		"success: running":                {hook: RunningHook{}},
		"success: done":                   {hook: DoneHook{}},
		"success: add_log":                {hook: AddLogHook{Entry: entry}, arg: entry},
		"success: next_layer":             {hook: NextLayerHook{Data: &hookdata.NextLayer{Context: hctx}}},
		"success: client_connected":       {hook: ClientConnectedHook{Client: client}, arg: client},
		"success: client_disconnected":    {hook: ClientDisconnectedHook{Client: client}, arg: client},
		"success: server_connect":         {hook: ServerConnectHook{Data: serverConn}, arg: serverConn},
		"success: server_connected":       {hook: ServerConnectedHook{Data: serverConn}, arg: serverConn},
		"success: server_disconnected":    {hook: ServerDisconnectedHook{Data: serverConn}, arg: serverConn},
		"success: server_connect_error":   {hook: ServerConnectErrorHook{Data: serverConn}, arg: serverConn},
		"success: socks5_auth":            {hook: Socks5AuthHook{Data: &hookdata.Socks5Auth{Client: client, Username: "u"}}},
		"success: tls_clienthello":        {hook: TLSClientHelloHook{Data: &hookdata.ClientHello{Context: hctx}}},
		"success: tls_start_client":       {hook: TLSStartClientHook{Data: tlsData}, arg: tlsData},
		"success: tls_start_server":       {hook: TLSStartServerHook{Data: tlsData}, arg: tlsData},
		"success: tls_established_client": {hook: TLSEstablishedClientHook{Data: tlsData}, arg: tlsData},
		"success: tls_established_server": {hook: TLSEstablishedServerHook{Data: tlsData}, arg: tlsData},
		"success: tls_failed_client":      {hook: TLSFailedClientHook{Data: tlsData}, arg: tlsData},
		"success: tls_failed_server":      {hook: TLSFailedServerHook{Data: tlsData}, arg: tlsData},
		"success: quic_start_client":      {hook: QUICStartClientHook{Data: quicData}, arg: quicData},
		"success: quic_start_server":      {hook: QUICStartServerHook{Data: quicData}, arg: quicData},
	}
	if len(tests) != len(hookSpecs) {
		t.Fatalf("%d test cases for %d hooks", len(tests), len(hookSpecs))
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			a := &everyHook{got: make(map[string]any)}
			if err := e.m.Add(t.Context(), a); err != nil {
				t.Fatalf("Add: %v", err)
			}
			clear(a.got) // drop load and the configure for deferred options
			if err := e.m.Trigger(t.Context(), tt.hook); err != nil {
				t.Fatalf("Trigger: %v", err)
			}
			if diff := cmp.Diff([]string{tt.hook.Name()}, slices.Collect(maps.Keys(a.got))); diff != "" {
				t.Fatalf("handlers called (-want +got):\n%s", diff)
			}
			got := a.got[tt.hook.Name()]
			want := tt.arg
			if want == nil {
				// Pointer arguments built inline: compare with the hook's
				// own field through the hook value.
				want = argOf(tt.hook)
			}
			if !sameArg(got, want) {
				t.Errorf("%s received %#v, want %#v", tt.hook.Name(), got, want)
			}
		})
	}
}

// argOf returns the single argument a hook value carries, or nil.
func argOf(h Hook) any {
	switch h := h.(type) {
	case NextLayerHook:
		return h.Data
	case Socks5AuthHook:
		return h.Data
	case TLSClientHelloHook:
		return h.Data
	default:
		return nil
	}
}

// sameArg compares pointers by identity and other values by equality.
func sameArg(got, want any) bool {
	switch w := want.(type) {
	case map[string]struct{}:
		g, ok := got.(map[string]struct{})
		return ok && maps.Equal(g, w)
	default:
		return got == want
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

// badSig has a Configure method without the context parameter, which would
// never be called.
type badSig struct{}

func (badSig) Configure(map[string]struct{}) error { return nil }

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
			wantMsg: "handler Configure for the configure hook has type func(map[string]struct {}) error",
		},
		"error: uncomparable addon": {
			addons:  func() []any { return []any{uncomparable{}} },
			wantMsg: "uncomparable type",
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
	a := &everyHook{got: make(map[string]any)}
	if err := e.m.Add(t.Context(), a); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if e.m.Get("everyhook") != a || !e.m.Contains(&everyHook{}) {
		t.Errorf("addon without Name() is not registered as %q", "everyhook")
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
