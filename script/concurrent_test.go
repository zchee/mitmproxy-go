// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

func awaitConcurrent[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case value := <-ch:
		return value
	case <-timer.C:
		stack := make([]byte, 1<<20)
		t.Fatalf("concurrent event hung:\n%s", stack[:runtime.Stack(stack, true)])
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	var zero T
	return zero
}

func startConcurrent(t *testing.T, f *scriptFixture, ctx context.Context, hook addon.Hook) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- f.master.Addons.Hook(ctx, hook) }()
	return done
}

func concurrentBarrier(t *testing.T, f *scriptFixture) (<-chan time.Duration, func()) {
	t.Helper()
	entered := make(chan time.Duration, 64)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	f.loader.sleepWait = func(ctx context.Context, d time.Duration) error {
		entered <- d
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return entered, unblock
}

func loadConcurrent(f *scriptFixture, body string) string {
	return f.file("worker.star", "def _request(f):\n"+indentStarlark(body)+"\nrequest = concurrent(_request)\n")
}

func indentStarlark(body string) string {
	return "    " + strings.ReplaceAll(strings.TrimSpace(body), "\n", "\n    ")
}

func TestScriptConcurrent(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"worker_and_merge":           {testWorkerAndMerge},
		"five_parallel":              {testFiveParallel},
		"frozen_dict":                {testFrozenDict},
		"init_twice":                 {func(t *testing.T) { testInitCount(t, true) }},
		"init_once":                  {func(t *testing.T) { testInitCount(t, false) }},
		"state_isolation":            {testStateIsolation},
		"option_alias":               {func(t *testing.T) { testOptionAlias(t, false) }},
		"worker_services":            {testWorkerServices},
		"read_after_change":          {func(t *testing.T) { testWorkerRead(t, false) }},
		"read_after_rollback":        {func(t *testing.T) { testWorkerRead(t, true) }},
		"direct_call":                {func(t *testing.T) { testDirectCall(t, false) }},
		"reload_retire":              {func(t *testing.T) { testRetireWorker(t, true, false) }},
		"remove_retire":              {func(t *testing.T) { testRetireWorker(t, false, false) }},
		"comment_survives":           {testCommentSurvives},
		"field_merge":                {testFieldMerge},
		"websocket_append":           {func(t *testing.T) { testMessageMerge(t, "websocket") }},
		"tcp_append":                 {func(t *testing.T) { testMessageMerge(t, "tcp") }},
		"udp_append":                 {func(t *testing.T) { testMessageMerge(t, "udp") }},
		"connection_read_only":       {testConnectionReadOnly},
		"kill_actions":               {func(t *testing.T) { testKillActions(t, false) }},
		"action_order":               {func(t *testing.T) { testKillActions(t, true) }},
		"semaphore":                  {func(t *testing.T) { testWorkerCapacity(t, false) }},
		"cancel_no_merge":            {testCancelNoMerge},
		"init_direct_mode":           {testInitDirectMode},
		"alias_freeze":               {func(t *testing.T) { testOptionAlias(t, true) }},
		"reload_same_path":           {func(t *testing.T) { testRetireWorker(t, true, true) }},
		"waiter_cancel":              {func(t *testing.T) { testWorkerCapacity(t, true) }},
		"reentrant_command":          {testReentrantWorkerCommand},
		"retained_copy_command":      {testRetainedCopyCommand},
		"global_reassign":            {testGlobalReassign},
		"direct_call_init":           {func(t *testing.T) { testDirectCall(t, true) }},
		"backup_order":               {testBackupOrder},
		"kill_precedence":            {testKillPrecedence},
		"command_copyback":           {testCommandCopyback},
		"command_argument_aliases":   {testCommandAliases},
		"child_invalid_binding":      {testChildInvalidBinding},
		"child_frozen_path_mismatch": {testChildFrozenPathMismatch},
		"child_topology_drift":       {testChildTopologyDrift},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, test := range tests {
			t.Run(name, test.run)
		}
	})
}

func testWorkerAndMerge(t *testing.T) {
	f := newFixture(t)
	entered, release := concurrentBarrier(t, f)
	f.load(loadConcurrent(f, "f.request.headers['x-before'] = '1'\nctx.sleep(1)\nf.request.headers['x-concurrent'] = '1'\nif not f.live:\n    fail('invocation lost live state')\nf.comment = f.id"))
	x := f.request()
	done := startConcurrent(t, f, t.Context(), addon.RequestHook{Flow: x})
	if got := awaitConcurrent(t, entered); got != time.Second {
		t.Fatalf("sleep=%s", got)
	}
	if err := f.master.Do(t.Context(), func(context.Context) error {
		if f.loader.current.Load() != nil {
			return errors.New("ordinary scope leaked during worker")
		}
		if x.Request.Headers.Get("x-before") != "" || x.Intercepted() {
			return errors.New("worker touched live state or intercepted it")
		}
		x.Request.Path = "/intervening"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	release()
	if err := awaitConcurrent(t, done); err != nil {
		t.Fatal(err)
	}
	if x.Comment != x.ID || x.Request.Path != "/intervening" || x.Request.Headers.Get("x-concurrent") != "1" || x.Request.Headers.Get("x-before") != "1" {
		t.Fatalf("merge: %s %s %v; %s", x.Comment, x.Request.Path, x.Request.Headers, f.logs.String())
	}
	f.wantLog("Addon error:", 0)
}

func testFiveParallel(t *testing.T) {
	f := newFixture(t)
	entered, release := concurrentBarrier(t, f)
	f.load(loadConcurrent(f, "ctx.sleep(1)\nf.comment = 'parallel'"))
	flows := make([]*flow.HTTPFlow, 5)
	dones := make([]<-chan error, 5)
	for n := range flows {
		flows[n] = f.request()
		dones[n] = startConcurrent(t, f, t.Context(), addon.RequestHook{Flow: flows[n]})
	}
	for range 5 {
		if awaitConcurrent(t, entered) != time.Second {
			t.Fatal("sleep changed")
		}
	}
	release()
	for n, done := range dones {
		if err := awaitConcurrent(t, done); err != nil {
			t.Fatal(err)
		}
		if flows[n].Comment != "parallel" {
			t.Fatalf("worker %d did not merge: %s", n, f.logs.String())
		}
	}
}

func testFrozenDict(t *testing.T) {
	f := newFixture(t)
	f.load(f.file("frozen.star", "state = {}\ndef _request(f):\n    f.comment = 'before-error'\n    state['x'] = 1\nrequest = concurrent(_request)\n"))
	x := f.request()
	f.hook(addon.RequestHook{Flow: x})
	f.wantLog("cannot insert into frozen hash table", 1)
	f.wantLog("Addon error:", 1)
	if x.Comment != "before-error" || x.Intercepted() {
		t.Fatalf("error lost mutations or stranded flow: %q", x.Comment)
	}
}

func testInitCount(t *testing.T, concurrent bool) {
	f := newFixture(t)
	text := "ctx.log('top-init')\ndef _request(f):\n    f.comment = 'ran'\n"
	want := 1
	if concurrent {
		text += "request = concurrent(_request)\n"
		want = 2
	} else {
		text += "request = _request\n"
	}
	f.load(f.file("init.star", text))
	for range 2 {
		x := f.request()
		f.hook(addon.RequestHook{Flow: x})
		if x.Comment != "ran" {
			t.Fatalf("handler failed: %s", f.logs.String())
		}
	}
	f.wantLog("top-init", want)
}

func testStateIsolation(t *testing.T) {
	f := newFixture(t)
	f.load(f.file("state.star", "state = {'n': 0}\ndef requestheaders(f):\n    state['n'] += 1\n    f.marked = str(state['n'])\ndef _request(f):\n    f.comment = str(state['n'])\nrequest = concurrent(_request)\n"))
	for n := range 2 {
		x := f.request()
		f.hook(addon.RequestHeadersHook{Flow: x})
		f.hook(addon.RequestHook{Flow: x})
		if x.Marked != fmt.Sprint(n+1) || x.Comment != "0" {
			t.Fatalf("shared module state: marked=%q comment=%q logs=%s", x.Marked, x.Comment, f.logs.String())
		}
	}
}

func testOptionAlias(t *testing.T, freeze bool) {
	f := newFixture(t)
	head := "o = ctx.options\n"
	if freeze {
		head += "aliases = [o, ctx.master, ctx.log]\n"
	}
	f.load(f.file("alias.star", head+"def requestheaders(f):\n    o.listen_host = 'ordinary'\ndef _request(f):\n    o.listen_host = 'worker'\n    ctx.options.listen_port = 12345\n    f.comment = o.listen_host\nrequest = concurrent(_request)\n"))
	x := f.request()
	f.hook(addon.RequestHeadersHook{Flow: x})
	if f.master.Options.Str("listen_host") != "ordinary" {
		t.Fatal("main alias was frozen")
	}
	f.hook(addon.RequestHook{Flow: x})
	if x.Comment != "worker" || f.master.Options.Str("listen_host") != "worker" || *f.master.Options.OptInt("listen_port") != 12345 {
		t.Fatalf("worker alias: %s", f.logs.String())
	}
	f.wantLog("Addon error:", 0)
}

func testWorkerServices(t *testing.T) {
	f := newFixture(t)
	store, err := eventstore.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.master.Addons.Add(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	handler := store.LogHandler(f.master.Addons)
	t.Cleanup(func() {
		if err := handler.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	f.loader.cfg.Logger = slog.New(handler)
	if err := f.master.Commands.Register("worker.read", func(ctx context.Context) (string, error) {
		return f.master.Options.Str("listen_host"), f.master.Do(ctx, func(context.Context) error { return nil })
	}); err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("service")) }))
	t.Cleanup(origin.Close)
	f.load(loadConcurrent(f, fmt.Sprintf("ctx.options.listen_host = 'service'\nf.comment = ctx.master.commands.call('worker.read')\nctx.log('worker-service-line')\nf.request.content = ctx.http_get(%q).content", origin.URL)))
	x := f.request()
	f.hook(addon.RequestHook{Flow: x})
	if err := handler.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	seen := false
	if err := f.master.Do(t.Context(), func(context.Context) error {
		for _, entry := range store.Entries() {
			if strings.Contains(entry.Msg, "worker-service-line") {
				seen = true
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !seen || x.Comment != "service" || string(x.Request.RawContent) != "service" {
		t.Fatalf("worker shared services failed: seen=%v comment=%q body=%q logs=%s", seen, x.Comment, x.Request.RawContent, f.logs.String())
	}
}

func testWorkerRead(t *testing.T, rollback bool) {
	f := newFixture(t)
	entered, release := concurrentBarrier(t, f)
	if rollback {
		f.master.Options.Subscribe(func(_ context.Context, updated map[string]struct{}) error {
			if _, ok := updated["listen_host"]; ok {
				return &options.OptionsError{Msg: "reject both update and rollback notification"}
			}
			return nil
		})
	}
	f.load(loadConcurrent(f, "ctx.sleep(1)\nf.comment = ctx.options.listen_host"))
	x := f.request()
	old := f.master.Options.Str("listen_host")
	done := startConcurrent(t, f, t.Context(), addon.RequestHook{Flow: x})
	awaitConcurrent(t, entered)
	err := f.master.Do(t.Context(), func(ctx context.Context) error {
		return f.master.Options.Update(ctx, map[string]any{"listen_host": "new-value"})
	})
	if rollback != (err != nil) {
		t.Fatalf("rollback=%v update=%v", rollback, err)
	}
	release()
	if err := awaitConcurrent(t, done); err != nil {
		t.Fatal(err)
	}
	want := "new-value"
	if rollback {
		want = old
	}
	if diff := gocmp.Diff(want, x.Comment); diff != "" {
		t.Fatal(diff)
	}
}

func testDirectCall(t *testing.T, init bool) {
	f := newFixture(t)
	text := "def _request(f):\n    ctx.log('unexpected-worker')\nrequest = concurrent(_request)\n"
	if init {
		text += "request(None)\n"
	} else {
		text += "def response(f):\n    request(f)\n"
	}
	f.load(f.file("direct.star", text))
	if !init {
		f.hook(addon.ResponseHook{Flow: f.request()})
	}
	f.wantLog("concurrent(_request) cannot be called directly; it runs only when invoked as a hook", 1)
	f.wantLog("unexpected-worker", 0)
	if init && f.loader.entries[0].module != nil {
		t.Fatal("direct-call init registered")
	}
}

func testRetireWorker(t *testing.T, reload, samePath bool) {
	f := newFixture(t)
	entered, release := concurrentBarrier(t, f)
	path := loadConcurrent(f, "ctx.sleep(1)\nctx.log('retired-worker-finished')\nf.request.headers['x-retired'] = 'old'")
	f.load(path)
	old := f.loader.entries[0].module
	x := f.request()
	done := startConcurrent(t, f, t.Context(), addon.RequestHook{Flow: x})
	awaitConcurrent(t, entered)
	var queued <-chan error
	var queuedFlow *flow.HTTPFlow
	occupied := 0
	if reload && !samePath {
		if err := f.master.Do(t.Context(), func(context.Context) error {
			occupied = cap(old.concurrent.slots) - len(old.concurrent.slots)
			for range occupied {
				old.concurrent.slots <- struct{}{}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		started := make(chan struct{})
		completed := make(chan error, 1)
		queued = completed
		queuedFlow = f.request()
		go func() {
			completed <- f.master.Do(t.Context(), func(ctx context.Context) error {
				close(started)
				return old.flowHook(ctx, "request", queuedFlow)
			})
		}()
		awaitConcurrent(t, started)
		// This acquisition completes only after the queued call yields its
		// dispatch frame while every worker permit remains occupied.
		if err := f.master.Do(t.Context(), func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if reload {
		replacement := "def request(f):\n    f.comment = 'new-instance'\n"
		if !samePath {
			hits := make(chan struct{}, 2)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits <- struct{}{}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer origin.Close()
			initializations := 0
			if err := f.master.Commands.Register("init.second", func(context.Context) bool {
				initializations++
				return initializations == 2
			}); err != nil {
				t.Fatal(err)
			}
			replacement = fmt.Sprintf("def initialize():\n    if ctx.master.commands.call('init.second'):\n        ctx.http_get(%q)\n        ctx.log('second-init-returned')\ninitialize()\ndef _request(f):\n    f.comment = 'new-instance'\nrequest = concurrent(_request)\n", origin.URL)
			f.updateSource(path, replacement, time.Second)
			f.poll()
			if err := f.master.Do(t.Context(), func(context.Context) error {
				module := f.loader.entries[0].module
				if initializations != 2 || len(hits) != 1 || module == nil || module.concurrent == nil {
					return fmt.Errorf("second init failed: inits=%d HTTP calls=%d; logs=%s", initializations, len(hits), f.logs.String())
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			f.wantLog("second-init-returned", 1)
			f.wantLog("error in script", 0)
			f.wantLog("dispatch frame used after", 0)
		} else {
			f.updateSource(path, replacement, time.Second)
			f.poll()
		}
	} else {
		f.load()
	}
	if queued != nil {
		for range occupied {
			<-old.concurrent.slots
		}
		if err := awaitConcurrent(t, queued); err != nil {
			t.Errorf("queued delivery to retired instance was not a silent no-op: %v", err)
		}
		if queuedFlow.Request.Headers.Get("x-retired") != "" || queuedFlow.Comment != "" {
			t.Error("queued delivery admitted work after retirement")
		}
	}
	if !old.retired {
		t.Fatal("old instance not retired")
	}
	if samePath && f.loader.entries[0].module == old {
		t.Fatal("same path reused old worker instance")
	}
	late := f.request()
	if err := old.flowHook(t.Context(), "request", late); err != nil {
		t.Errorf("retired hook delivery was not a silent no-op: %v", err)
	}
	if late.Comment != "" || late.Request.Headers.Get("x-retired") != "" {
		t.Fatal("retirement admitted new worker")
	}
	if reload {
		fresh := f.request()
		f.hook(addon.RequestHook{Flow: fresh})
		if fresh.Comment != "new-instance" {
			t.Fatal("replacement not live")
		}
	}
	release()
	if err := awaitConcurrent(t, done); err != nil {
		t.Fatal(err)
	}
	if x.Request.Headers.Get("x-retired") != "old" {
		t.Fatalf("retired merge lost: %s", f.logs.String())
	}
	f.wantLog("retired-worker-finished", 1)
	if err := f.loader.Close(); err != nil {
		t.Fatal(err)
	}
	if reload && !samePath {
		testRetiredChildDelivery(t)
	}
}

func testCommentSurvives(t *testing.T) {
	f := newFixture(t)
	entered, release := concurrentBarrier(t, f)
	f.load(loadConcurrent(f, "ctx.sleep(1)\nf.request.headers['x-worker'] = '1'"))
	x := f.request()
	done := startConcurrent(t, f, t.Context(), addon.RequestHook{Flow: x})
	awaitConcurrent(t, entered)
	if err := f.master.Do(t.Context(), func(context.Context) error { x.Comment = "live-edit"; return nil }); err != nil {
		t.Fatal(err)
	}
	release()
	if err := awaitConcurrent(t, done); err != nil {
		t.Fatal(err)
	}
	if x.Comment != "live-edit" || x.Request.Headers.Get("x-worker") != "1" {
		t.Fatalf("untouched comment overwritten: %s", f.logs.String())
	}
}

func testConnectionReadOnly(t *testing.T) {
	for _, assignment := range []string{"f.server_conn.address = ('wrong', 7)", "f.server_conn.sni = 'wrong'", "f.client_conn.error = 'wrong'", "f.server_conn = None"} {
		f := newFixture(t)
		f.load(loadConcurrent(f, "f.comment = f.server_conn.address[0]\n"+assignment))
		x := f.request()
		f.hook(addon.RequestHook{Flow: x})
		if x.Comment != "example.test" || x.ServerConn.Address.Host != "example.test" || x.ClientConn.Error != nil || x.Intercepted() {
			t.Fatalf("connection escaped read-only snapshot: %s", f.logs.String())
		}
		f.wantLog("read-only", 1)
	}
}

func testCancelNoMerge(t *testing.T) {
	f := newFixture(t)
	entered, release := concurrentBarrier(t, f)
	f.load(loadConcurrent(f, "f.comment = 'must-not-merge'\nctx.sleep(1)"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	x := f.request()
	done := startConcurrent(t, f, ctx, addon.RequestHook{Flow: x})
	awaitConcurrent(t, entered)
	cancel()
	release()
	if err := awaitConcurrent(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel result=%v", err)
	}
	if x.Comment != "" {
		t.Fatal("canceled stream merged")
	}
	if len(f.loader.entries[0].module.concurrent.slots) != 0 {
		t.Fatal("cancellation leaked capacity")
	}
	if err := f.loader.Close(); err != nil {
		t.Fatal(err)
	}
}

func testInitDirectMode(t *testing.T) {
	f := newFixture(t)
	f.load(f.file("direct-init.star", "ctx.options.listen_host = 'init'\nctx.log('direct-second-init')\ndef _request(f):\n    f.comment = ctx.options.listen_host\nrequest = concurrent(_request)\n"))
	x := f.request()
	f.hook(addon.RequestHook{Flow: x})
	f.wantLog("direct-second-init", 2)
	if x.Comment != "init" {
		t.Fatalf("second init entered worker mode early: %s", f.logs.String())
	}
}

func testGlobalReassign(t *testing.T) {
	f := newFixture(t)
	f.load(f.file("reassign.star", "def request(f):\n    pass\nrequest = concurrent(request)\n"))
	f.wantLog("cannot reassign global request declared at", 1)
	if f.loader.entries[0].module != nil {
		t.Fatal("GlobalReassign unexpectedly enabled")
	}
}

func testReentrantWorkerCommand(t *testing.T) {
	f := newFixture(t)
	if err := f.master.Commands.Register("worker.reenter", func(ctx context.Context) (string, error) {
		return "reentered", f.master.Do(ctx, func(ctx context.Context) error {
			return f.master.Options.Update(ctx, map[string]any{"listen_host": "nested"})
		})
	}); err != nil {
		t.Fatal(err)
	}
	f.load(f.file("reenter.star", "def local():\n    ctx.options.listen_host = 'local'\ndef on_load(loader):\n    loader.add_command('worker.local', local)\ndef _request(f):\n    f.comment = ctx.master.commands.call('worker.reenter')\n    ctx.master.commands.call('worker.local')\n    f.marked = ctx.options.listen_host\nrequest = concurrent(_request)\n"))
	x := f.request()
	f.hook(addon.RequestHook{Flow: x})
	if x.Comment != "reentered" || x.Marked != "local" {
		t.Fatalf("worker reentry or ordinary scope restoration failed: %s", f.logs.String())
	}
	f.wantLog("Addon error:", 0)
}
