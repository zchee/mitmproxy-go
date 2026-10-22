// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package acceptance_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/internal/tools/dump"
	"github.com/zchee/mitmproxy-go/websocket"
)

type assembled struct {
	m    *dump.Master
	logs *observedLog
}

func assembledDump(t *testing.T) *assembled {
	t.Helper()
	logs := newLog()
	m, err := dump.New(t.Context(), dump.Config{Stdout: logs, Stderr: logs, WithTermlog: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	a := &assembled{m, logs}
	a.update(t, map[string]any{"server": false, "termlog_verbosity": "debug"})
	return a
}

func (a *assembled) update(t *testing.T, values map[string]any) {
	t.Helper()
	if err := a.m.Do(t.Context(), func(ctx context.Context) error { return a.m.Options.Update(ctx, values) }); err != nil {
		t.Fatal(err)
	}
}

func (a *assembled) load(t *testing.T, source string) string {
	t.Helper()
	path := scriptFile(t, source)
	a.update(t, map[string]any{"scripts": []string{path}})
	return path
}

func (a *assembled) hook(t *testing.T, hook addon.Hook) {
	t.Helper()
	if err := a.m.Addons.Hook(t.Context(), hook); err != nil {
		t.Fatal(err)
	}
}

func asyncHook(t *testing.T, a *assembled, hook addon.Hook) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() { defer close(joined); done <- a.m.Addons.Hook(t.Context(), hook) }()
	t.Cleanup(func() {
		// Closing the master cancels and joins script work if an assertion aborts.
		if err := a.m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
		<-joined
	})
	return done
}

func barrierOrigin(t *testing.T) (string, <-chan struct{}, func()) {
	t.Helper()
	entered := make(chan struct{}, 32)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
			_, _ = w.Write([]byte("released"))
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { unblock(); origin.Close() })
	return origin.URL, entered, unblock
}

func TestScriptAcceptance(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"dict_counter":          {dictCounter},
			"sleep_other_flow":      {func(t *testing.T) { otherFlow(t, false, false) }},
			"concurrent_other_flow": {func(t *testing.T) { otherFlow(t, true, false) }},
			"five_parallel":         {func(t *testing.T) { fiveParallel(t, false) }},
			"frozen_dict":           {frozenDict},
			"init_counts":           {initCounts},
			"state_visibility":      {stateVisibility},
			"option_aliases":        {optionAliases},
			"worker_services":       {workerServices},
			"direct_call":           {directCall},
			"reload_inflight":       {func(t *testing.T) { reloadInflight(t, false) }},
			"comment_merge":         {commentMerge},
			"websocket_append":      {websocketAppend},
			"connection_read_only":  {connectionReadOnly},
			"kill_live":             {killLive},
			"invalid_bindings":      {invalidBindings},
			"reassign_error":        {reassignError},
			"run_depths":            {runDepths},
			"run_load_error":        {runLoadError},
			"nonblocking_parallel":  {func(t *testing.T) { nonblockingParallel(t, false) }},
			"mtime_reload":          {func(t *testing.T) { mtimeReload(t, false) }},
			"error_once":            {errorOnce},
			"steps_abort":           {stepsAbort},
			"dump_replay":           {dumpReplay},
			"options_metadata":      {optionsMetadata},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func dictCounter(t *testing.T) {
	origin, seen := ownedOrigin(t, "counter")
	path := scriptFile(t, `state = {"count": 0}
def request(f):
    state["count"] += 1
    f.request.headers["x-dict-counter"] = str(state["count"])
`)
	p := startProxy(t, origin.URL, []string{path})
	for _, want := range []string{"1", "2"} {
		send(t, proxyClient(t, p), "GET", origin.URL, "", nil)
		equal(t, want, receive(t, seen).headers.Get("X-Dict-Counter"))
	}
}

func frozenDict(t *testing.T) {
	origin, seen := ownedOrigin(t, "resumed")
	path := scriptFile(t, `state = {"count": 0}
def _request(f):
    state["count"] += 1
request = concurrent(_request)
`)
	p := startProxy(t, origin.URL, []string{path})
	p.wantHookErrors = 1
	got := send(t, proxyClient(t, p), "GET", origin.URL, "", nil)
	equal(t, "resumed", got.body)
	receive(t, seen)
	p.logs.contains(t, "cannot insert into frozen hash table")
	equal(t, 1, strings.Count(p.logs.text(), "Addon error:"))
}

func initCounts(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		a := assembledDump(t)
		source := "ctx.log('initialization-marker')\ndef _request(f):\n    f.comment = 'called'\n"
		if concurrent {
			source += "request = concurrent(_request)\n"
		} else {
			source += "request = _request\n"
		}
		path := a.load(t, source)
		want := 1
		if concurrent {
			want = 2
		}
		equal(t, want, strings.Count(a.logs.text(), "initialization-marker"))
		before := strings.Count(a.logs.text(), "initialization-marker")
		if _, err := a.m.Call(t.Context(), "script.run", []flow.Flow{testflow.TFlow()}, command.Path(path)); err != nil {
			t.Fatal(err)
		}
		equal(t, before+1, strings.Count(a.logs.text(), "initialization-marker"))
	}
}

func stateVisibility(t *testing.T) {
	origin, seen := ownedOrigin(t, "state")
	path := scriptFile(t, `state = {"counter": 0}
def requestheaders(f):
    state["counter"] += 1
def _request(f):
    f.request.headers["x-worker-state"] = str(state["counter"])
def response(f):
    f.response.headers["x-ordinary-state"] = str(state["counter"])
request = concurrent(_request)
`)
	p := startProxy(t, origin.URL, []string{path})
	for _, want := range []string{"1", "2"} {
		got := send(t, proxyClient(t, p), "GET", origin.URL, "", nil)
		equal(t, want, got.headers.Get("X-Ordinary-State"))
		equal(t, "0", receive(t, seen).headers.Get("X-Worker-State"))
	}
}

func optionAliases(t *testing.T) {
	origin, seen := ownedOrigin(t, "aliases")
	path := scriptFile(t, `o = ctx.options
def requestheaders(f):
    o.showhost = True
def _request(f):
    o.showhost = False
    ctx.options.showhost = True
    f.request.headers["x-worker-option"] = str(o.showhost)
def response(f):
    o.showhost = False
    f.response.headers["x-ordinary-option"] = str(o.showhost)
request = concurrent(_request)
`)
	p := startProxy(t, origin.URL, []string{path})
	got := send(t, proxyClient(t, p), "GET", origin.URL, "", nil)
	equal(t, "False", got.headers.Get("X-Ordinary-Option"))
	equal(t, "True", receive(t, seen).headers.Get("X-Worker-Option"))
}

type eventObserver struct{ store *eventstore.EventStore }

func (o *eventObserver) AddLog(ctx context.Context, entry addon.LogEntry) error {
	return o.store.Add(ctx, entry)
}

func workerServices(t *testing.T) {
	a := assembledDump(t)
	store, err := eventstore.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.m.Addons.Add(t.Context(), store, &eventObserver{store: store}); err != nil {
		t.Fatal(err)
	}
	if err := a.m.Commands.Register("acceptance.read", func(context.Context) string { return a.m.Options.Str("onboarding_host") }); err != nil {
		t.Fatal(err)
	}
	url, entered, release := barrierOrigin(t)
	a.load(t, fmt.Sprintf(`def _request(f):
    ctx.http_get(%q)
    f.comment = str(ctx.options.showhost)
    f.request.headers["x-command"] = ctx.master.commands.call("acceptance.read")
    ctx.log("worker-service-record")
request = concurrent(_request)
`, url))
	f := testflow.TFlow()
	done := asyncHook(t, a, addon.RequestHook{Flow: f})
	receive(t, entered)
	a.update(t, map[string]any{"showhost": true})
	release()
	if err := receive(t, done); err != nil {
		t.Fatal(err)
	}
	if f.Comment != "True" && f.Comment != "False" {
		t.Fatalf("invalid copied option read %q", f.Comment)
	}
	equal(t, "mitm.it", f.Request.Headers.Get("X-Command"))
	if err := a.m.LogHandler().Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	found := false
	if err := a.m.Do(t.Context(), func(context.Context) error {
		for _, entry := range store.Entries() {
			if strings.Contains(entry.Msg, "worker-service-record") {
				found = true
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("worker log absent from real eventstore: %s", a.logs.text())
	}
}

func directCall(t *testing.T) {
	origin, seen := ownedOrigin(t, "direct")
	path := scriptFile(t, `def _request(f):
    ctx.log("worker-was-invoked")
request = concurrent(_request)
def response(f):
    request(f)
`)
	p := startProxy(t, origin.URL, []string{path})
	p.wantHookErrors = 1
	got := send(t, proxyClient(t, p), "GET", origin.URL, "", nil)
	equal(t, "direct", got.body)
	receive(t, seen)
	p.logs.contains(t, "concurrent(_request) cannot be called directly; it runs only when invoked as a hook")
	equal(t, 1, strings.Count(p.logs.text(), "worker-was-invoked"))
	equal(t, 1, strings.Count(p.logs.text(), "Addon error:"))
}

func commentMerge(t *testing.T) {
	a := assembledDump(t)
	url, entered, release := barrierOrigin(t)
	a.load(t, fmt.Sprintf("def _request(f):\n    ctx.http_get(%q)\n    f.request.headers['x-worker'] = 'merged'\nrequest = concurrent(_request)\n", url))
	f := testflow.TFlow()
	done := asyncHook(t, a, addon.RequestHook{Flow: f})
	receive(t, entered)
	if err := a.m.Do(t.Context(), func(context.Context) error { f.Comment = "live concurrent comment"; return nil }); err != nil {
		t.Fatal(err)
	}
	release()
	if err := receive(t, done); err != nil {
		t.Fatal(err)
	}
	equal(t, "live concurrent comment", f.Comment)
	equal(t, "merged", f.Request.Headers.Get("X-Worker"))
}

func websocketAppend(t *testing.T) {
	a := assembledDump(t)
	url, entered, release := barrierOrigin(t)
	a.load(t, fmt.Sprintf(`def _message(f):
    f.websocket.messages[0].content = b"worker edited"
    ctx.http_get(%q)
websocket_message = concurrent(_message)
`, url))
	f := testflow.TFlow()
	f.WebSocket = &websocket.Data{Messages: []*websocket.Message{websocket.NewMessage(websocket.OpBinary, true, []byte("original"))}}
	done := asyncHook(t, a, addon.WebSocketMessageHook{Flow: f})
	receive(t, entered)
	if err := a.m.Do(t.Context(), func(context.Context) error {
		f.WebSocket.Messages = append(f.WebSocket.Messages, websocket.NewMessage(websocket.OpBinary, false, []byte("other direction")))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	release()
	if err := receive(t, done); err != nil {
		t.Fatal(err)
	}
	equal(t, 2, len(f.WebSocket.Messages))
	equal(t, "worker edited", string(f.WebSocket.Messages[0].Content))
	equal(t, "other direction", string(f.WebSocket.Messages[1].Content))
	equal(t, false, f.WebSocket.Messages[1].FromClient)
}

func connectionReadOnly(t *testing.T) {
	origin, seen := ownedOrigin(t, "continued")
	path := scriptFile(t, `def _request(f):
    f.server_conn.address = ("127.0.0.1", 1)
request = concurrent(_request)
`)
	p := startProxy(t, origin.URL, []string{path})
	p.wantHookErrors = 1
	equal(t, "continued", send(t, proxyClient(t, p), "GET", origin.URL, "", nil).body)
	receive(t, seen)
	p.logs.contains(t, "read-only")
	equal(t, 1, strings.Count(p.logs.text(), "Addon error:"))
}

func killLive(t *testing.T) {
	origin, seen := ownedOrigin(t, "must not forward")
	path := scriptFile(t, "def _request(f):\n    f.kill()\nrequest = concurrent(_request)\ndef error(f):\n    ctx.log(f.error.msg)\n")
	p := startProxy(t, origin.URL, []string{path})
	client := proxyClient(t, p)
	r, err := http.NewRequestWithContext(t.Context(), "GET", origin.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(r)
	if res != nil {
		_ = res.Body.Close()
	}
	if err == nil {
		t.Fatal("killed flow returned a response instead of closing transport")
	}
	p.logs.contains(t, "Connection killed.")
	select {
	case r := <-seen:
		t.Fatalf("killed flow reached origin: %+v", r)
	default:
	}
}

func invalidBindings(t *testing.T) {
	for _, name := range []string{"on_load", "configure", "tls_clienthello", "helper"} {
		a := assembledDump(t)
		a.load(t, "def _hook(*args):\n    ctx.log('must-not-run')\n"+name+" = concurrent(_hook)\n")
		want := fmt.Sprintf("Concurrent decorator not supported for '%s' method.", name)
		a.logs.contains(t, want)
		equal(t, 1, strings.Count(a.logs.text(), "error in script"))
		equal(t, 0, strings.Count(a.logs.text(), "must-not-run"))
	}
}

func reassignError(t *testing.T) {
	a := assembledDump(t)
	a.load(t, "def request(f):\n    pass\nrequest = concurrent(request)\n")
	a.logs.contains(t, "cannot reassign global request")
	equal(t, 1, strings.Count(a.logs.text(), "error in script"))
}

func errorOnce(t *testing.T) {
	origin, seen := ownedOrigin(t, "alive")
	path := scriptFile(t, "def request(f):\n    fail('deliberate hook failure')\n")
	p := startProxy(t, origin.URL, []string{path})
	p.wantHookErrors = 1
	equal(t, "alive", send(t, proxyClient(t, p), "GET", origin.URL, "", nil).body)
	receive(t, seen)
	p.logs.contains(t, "deliberate hook failure")
	equal(t, 1, strings.Count(p.logs.text(), "Addon error:"))
}

func stepsAbort(t *testing.T) {
	origin, seen := ownedOrigin(t, "survived budget")
	path := scriptFile(t, "def request(f):\n    for i in range(100000):\n        f.comment = str(i)\n")
	p := startProxy(t, origin.URL, []string{path}, "--set", "script_max_steps=1000")
	p.wantHookErrors = 1
	equal(t, "survived budget", send(t, proxyClient(t, p), "GET", origin.URL, "", nil).body)
	receive(t, seen)
	p.logs.contains(t, "too many steps")
	equal(t, 1, strings.Count(p.logs.text(), "Addon error:"))
}
