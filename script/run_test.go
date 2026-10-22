// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

type runHookCaller struct {
	commands *command.Manager
	flows    []flow.Flow
	path     command.Path
}

func (*runHookCaller) Name() string { return "script-run-caller" }
func (c *runHookCaller) Request(ctx context.Context, _ *flow.HTTPFlow) error {
	_, err := c.commands.Call(ctx, "script.run", c.flows, c.path)
	return err
}

func invokeRun(t *testing.T, f *scriptFixture, path string, flows []flow.Flow, nested bool) {
	t.Helper()
	if nested {
		caller := &runHookCaller{commands: f.master.Commands, flows: flows, path: command.Path(path)}
		if err := f.master.Addons.Add(t.Context(), caller); err != nil {
			t.Fatal(err)
		}
		f.hook(addon.RequestHook{Flow: f.request()})
		return
	}
	if err := f.master.Do(t.Context(), func(ctx context.Context) error {
		_, err := f.master.Commands.Call(ctx, "script.run", flows, command.Path(path))
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func runRecorder(t *testing.T, f *scriptFixture) *[]string {
	t.Helper()
	events := new([]string)
	if err := f.master.Commands.Register("run.record", func(_ context.Context, text string) { *events = append(*events, text) }); err != nil {
		t.Fatal(err)
	}
	return events
}

func runRecordingSource(names ...string) string {
	var source strings.Builder
	for _, name := range names {
		argument := "f"
		switch name {
		case "configure":
			argument = "updated"
		case "running":
			argument = ""
		}
		fmt.Fprintf(&source, "def %s(%s):\n    ctx.master.commands.call('run.record', %q)\n", name, argument, name)
	}
	return source.String()
}

func TestScriptRun(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"depth_one":          {func(t *testing.T) { testRunRefusal(t, false, false); testRunInline(t, false) }},
		"depth_two":          {func(t *testing.T) { testRunRefusal(t, true, false); testRunInline(t, true); testRunDepthLimit(t) }},
		"child_depth_one":    {func(t *testing.T) { testRunRefusal(t, false, true) }},
		"child_depth_two":    {func(t *testing.T) { testRunRefusal(t, true, true) }},
		"invalid_binding":    {testRunInvalidBinding},
		"no_other_addons":    {testRunModuleOnly},
		"init_once":          {testRunInitOnce},
		"first_error_stops":  {testRunFirstError},
		"http_sequence":      {func(t *testing.T) { testRunSequence(t, "http") }},
		"websocket_sequence": {func(t *testing.T) { testRunSequence(t, "websocket") }},
		"tcp_sequence":       {func(t *testing.T) { testRunSequence(t, "tcp") }},
		"udp_sequence":       {func(t *testing.T) { testRunSequence(t, "udp") }},
		"dns_sequence":       {func(t *testing.T) { testRunSequence(t, "dns") }},
		"dump_replay":        {testRunDumpReplay},
		"missing_path":       {testRunMissingPath},
		"nested_addons":      {testRunNestedAddons},
		"no_on_load":         {testRunNoLoad},
	}
	t.Run("contracts", func(t *testing.T) {
		for name, test := range tests {
			t.Run(name, test.run)
		}
	})
}

func testRunDepthLimit(t *testing.T) {
	for _, mode := range []string{"master", "hook", "worker", "parallel"} {
		f := newFixture(t)
		events := runRecorder(t, f)
		path := filepath.Join(f.dir, "recursive.star")
		f.file("recursive.star", fmt.Sprintf("ctx.master.commands.call('run.record', 'init')\ndef running():\n    ctx.master.commands.call('run.record', 'running')\n    ctx.master.commands.call('script.run', [], %q)\n    ctx.master.commands.call('run.record', 'after-running')\ndef request(f):\n    ctx.master.commands.call('run.record', 'later-request')\n", path))
		runs := 1
		switch mode {
		case "master":
			invokeRun(t, f, path, []flow.Flow{f.request()}, false)
		case "hook":
			invokeRun(t, f, path, []flow.Flow{f.request()}, true)
		case "worker":
			caller := f.file("worker-caller.star", fmt.Sprintf("def _request(f):\n    ctx.master.commands.call('script.run', [], %q)\n    f.comment = 'worker-returned'\nrequest = concurrent(_request)\n", path))
			f.load(caller)
			x := f.request()
			f.hook(addon.RequestHook{Flow: x})
			if x.Comment != "worker-returned" {
				t.Fatalf("worker command did not receive outer success: %s", f.logs.String())
			}
		case "parallel":
			runs = 4
			var callers sync.WaitGroup
			errs := make(chan error, runs)
			for range runs {
				callers.Go(func() {
					_, err := f.master.Commands.Call(t.Context(), "script.run", []flow.Flow{f.request()}, command.Path(path))
					errs <- err
				})
			}
			callers.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("outer concurrent caller received failure: %v", err)
				}
			}
		}
		var want []string
		for range runs * maxScriptRunDepth {
			want = append(want, "init", "running")
		}
		if diff := gocmp.Diff(want, *events); diff != "" {
			t.Fatalf("%s: depth boundary launched extra init/hooks or continued after failure: %s", mode, diff)
		}
		if depth := f.loader.syncRunDepth.Load(); depth != 0 {
			t.Fatalf("%s: nesting permits leaked: %d", mode, depth)
		}
		f.wantLog("Addon error:", runs)
		f.wantLog(errScriptRunDepth.Error(), runs)
		f.wantLog("panic", 0)
	}
	f := newFixture(t)
	events := runRecorder(t, f)
	inner := f.file("ordinary-error.star", "def running():\n    fail('ordinary-nested-error')\n")
	outer := f.file("ordinary-caller.star", fmt.Sprintf("def running():\n    ctx.master.commands.call('script.run', [], %q)\n    ctx.master.commands.call('run.record', 'after-inner')\ndef request(f):\n    f.comment = 'outer-continued'\n", inner))
	x := f.request()
	invokeRun(t, f, outer, []flow.Flow{x}, false)
	if diff := gocmp.Diff([]string{"after-inner"}, *events); diff != "" {
		t.Fatal(diff)
	}
	if x.Comment != "outer-continued" || f.loader.syncRunDepth.Load() != 0 {
		t.Fatal("ordinary nested error changed per-run success or leaked admission")
	}
	f.wantLog("Addon error:", 1)
	f.wantLog("ordinary-nested-error", 1)
	f.wantLog(errScriptRunDepth.Error(), 0)
	limit := newFixture(t)
	if err := limit.master.Do(t.Context(), func(ctx context.Context) error {
		limit.loader.syncRunDepth.Store(maxScriptRunDepth)
		defer limit.loader.syncRunDepth.Store(0)
		_, err := limit.master.Commands.Call(ctx, "script.run", []flow.Flow{}, command.Path(filepath.Join(limit.dir, "does-not-exist.star")))
		if !errors.Is(err, errScriptRunDepth) || limit.loader.syncRunDepth.Load() != maxScriptRunDepth {
			return fmt.Errorf("admission did not fail before path processing or unwind: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	limit.wantLog("No such script:", 0)
	limit.wantLog("Addon error:", 0)
}

func testRunRefusal(t *testing.T, nested, child bool) {
	f := newFixture(t)
	events := runRecorder(t, f)
	resident := f.file("resident.star", "def configure(updated):\n    ctx.log('other-configure')\ndef running():\n    ctx.log('other-running')\ndef requestheaders(f):\n    ctx.log('other-requestheaders')\ndef request(f):\n    ctx.log('other-request')\n")
	f.load(resident)
	before := f.logs.String()
	source := "ctx.master.commands.call('run.record', 'init')\n" + runRecordingSource("configure", "running") + "def _request(f):\n    ctx.master.commands.call('run.record', 'launched')\n    f.comment = 'worker-mutated'\n"
	want := []string{"init", "configure", "running"}
	if child {
		source += "def request(f):\n    ctx.master.commands.call('run.record', 'root-request')\ndef tail(f):\n    ctx.master.commands.call('run.record', 'later-child')\naddons = [module('worker', request=concurrent(_request)), module('tail', request=tail)]\n"
		want = append(want, "root-request")
	} else {
		source += "request = concurrent(_request)\n"
	}
	path := f.file("refused.star", source)
	first, second := f.request(), f.request()
	invokeRun(t, f, path, []flow.Flow{first, second}, nested)
	if diff := gocmp.Diff(want, *events); diff != "" {
		t.Fatal(diff)
	}
	if first.Comment != "" || second.Comment != "" || len(f.loader.entries) != 1 || f.master.Addons.Get("script:"+path) != nil {
		t.Fatalf("sync refusal launched or registered a worker: %s", f.logs.String())
	}
	otherRequests := 0
	if nested {
		otherRequests = 1
	}
	added := strings.TrimPrefix(f.logs.String(), before)
	if strings.Count(added, "other-request") != otherRequests || strings.Contains(added, "other-configure") || strings.Contains(added, "other-running") || strings.Contains(added, "other-requestheaders") {
		t.Fatalf("refusal invoked unrelated hooks: %s", added)
	}
	f.wantLog("Addon error:", 1)
	f.wantLog("Async handler request ("+path+") cannot be called from sync context", 1)
}

func testRunInline(t *testing.T, nested bool) {
	f := newFixture(t)
	calls := 0
	f.loader.sleepWait = func(ctx context.Context, _ time.Duration) error {
		calls++
		launched := false
		_, err := addon.Concurrent(ctx, func(context.Context) error { launched = true; return nil })
		if !errors.Is(err, addon.ErrSyncContext) || launched {
			return fmt.Errorf("blocking builtin released synchronous dispatch: launched=%v err=%v", launched, err)
		}
		return nil
	}
	path := f.file("inline.star", "ctx.sleep(0)\ndef request(f):\n    ctx.sleep(0)\n    f.comment = 'inline'\n")
	x := f.request()
	invokeRun(t, f, path, []flow.Flow{x}, nested)
	if calls != 2 || x.Comment != "inline" {
		t.Fatalf("synchronous blocking calls=%d comment=%q logs=%s", calls, x.Comment, f.logs.String())
	}
	registered := maps.Collect(f.master.Commands.Commands())["script.run"]
	if registered == nil || registered.SignatureHelp() != "script.run flows path" || registered.Return != nil || len(registered.Params) != 2 || registered.Params[0].Type != command.FlowsType || registered.Params[1].Type != command.PathType || !strings.Contains(registered.Help, "load event is not invoked") {
		t.Fatalf("script.run command metadata=%+v", registered)
	}
	f.wantLog("Addon error:", 0)
}

func testRunInvalidBinding(t *testing.T) {
	tests := map[string]struct{ source, diagnostic string }{
		"root helper":  {"def f(x):\n    pass\nhelper = concurrent(f)\n", "Concurrent decorator not supported for 'helper' method."},
		"child helper": {"def f(x):\n    pass\naddons = [module('child', helper=concurrent(f))]\n", "Concurrent decorator not supported for 'helper' method."},
		"reassign":     {"def request(f):\n    pass\nrequest = concurrent(request)\n", "cannot reassign"},
		"direct init":  {"def _request(f):\n    pass\nrequest = concurrent(_request)\nrequest(None)\n", "cannot be called directly"},
	}
	for label, test := range tests {
		f := newFixture(t)
		path := f.file("invalid.star", test.source)
		invokeRun(t, f, path, []flow.Flow{f.request()}, false)
		f.wantLog("error in script "+path, 1)
		f.wantLog(test.diagnostic, 1)
		f.wantLog("Addon error:", 0)
		if len(f.loader.Addons()) != 0 {
			t.Fatalf("%s registered an invalid temporary module", label)
		}
	}
	f := newFixture(t)
	path := f.file("direct.star", "def _request(f):\n    pass\nrequest = concurrent(_request)\ndef response(f):\n    request(f)\n")
	x := f.request()
	x.Request = nil
	x.Response, _ = httpmsg.MakeResponse(200, nil, nil)
	invokeRun(t, f, path, []flow.Flow{x}, false)
	f.wantLog("cannot be called directly", 1)
	f.wantLog("Addon error:", 1)
}

func testRunModuleOnly(t *testing.T) {
	f := newFixture(t)
	resident := f.file("resident.star", "def configure(updated):\n    ctx.log('resident-configure')\ndef running():\n    ctx.log('resident-running')\ndef request(f):\n    ctx.log('resident-request')\n")
	f.load(resident)
	before := f.logs.String()
	path := f.file("temporary.star", "def request(f):\n    f.comment = 'temporary-only'\n")
	x := f.request()
	invokeRun(t, f, path, []flow.Flow{x}, false)
	if strings.Contains(strings.TrimPrefix(f.logs.String(), before), "resident-") || x.Comment != "temporary-only" || f.master.Addons.Get("script:"+path) != nil || len(f.loader.entries) != 1 {
		t.Fatalf("run escaped its temporary module: %s", f.logs.String())
	}
}

func testRunInitOnce(t *testing.T) {
	f := newFixture(t)
	events := runRecorder(t, f)
	path := f.file("once.star", "ctx.master.commands.call('run.record', 'init')\n"+runRecordingSource("configure", "running", "request"))
	invokeRun(t, f, path, []flow.Flow{f.request(), f.request()}, false)
	if diff := gocmp.Diff([]string{"init", "configure", "running", "request", "request"}, *events); diff != "" {
		t.Fatal(diff)
	}
	f.wantLog("Addon error:", 0)
}

func testRunFirstError(t *testing.T) {
	tests := map[string]struct{ at string }{"configure": {"configure"}, "running": {"running"}, "request": {"request"}}
	for _, test := range tests {
		f := newFixture(t)
		events := runRecorder(t, f)
		names := []string{"configure", "running", "requestheaders", "request", "responseheaders", "response"}
		source := runRecordingSource(names...)
		needle := fmt.Sprintf("ctx.master.commands.call('run.record', %q)", test.at)
		source = strings.Replace(source, needle, needle+"\n    fail('stop-first')", 1)
		first, second := f.request(), f.request()
		first.Response, _ = httpmsg.MakeResponse(200, nil, nil)
		invokeRun(t, f, f.file("first-error.star", source), []flow.Flow{first, second}, false)
		var want []string
		for _, name := range names {
			want = append(want, name)
			if name == test.at {
				break
			}
		}
		if diff := gocmp.Diff(want, *events); diff != "" {
			t.Fatal(diff)
		}
		f.wantLog("Addon error:", 1)
		f.wantLog("stop-first", 1)
	}
	f := newFixture(t)
	events := runRecorder(t, f)
	h := f.request()
	x := flow.NewTCPFlow(h.ClientConn, h.ServerConn, false)
	x.Messages = []*tcp.Message{tcp.NewMessage(true, []byte("one")), tcp.NewMessage(false, []byte("two"))}
	path := f.file("partial.star", "def tcp_message(f):\n    ctx.master.commands.call('run.record', str(len(f.messages)))\n    fail('stop-message')\n")
	invokeRun(t, f, path, []flow.Flow{x, f.request()}, false)
	if diff := gocmp.Diff([]string{"1"}, *events); diff != "" {
		t.Fatal(diff)
	}
	if len(x.Messages) != 1 || string(x.Messages[0].Content) != "one" {
		t.Fatal("early termination restored unrevealed messages")
	}
	f.wantLog("Addon error:", 1)
}

func testRunSequence(t *testing.T, kind string) {
	for _, failed := range []bool{false, true} {
		f := newFixture(t)
		events := runRecorder(t, f)
		h := f.request()
		var model flow.Flow = h
		names := []string{"configure", "running"}
		want := []string{"configure", "running"}
		switch kind {
		case "http":
			h.Response, _ = httpmsg.MakeResponse(200, nil, nil)
			names = append(names, "requestheaders", "request", "responseheaders", "response")
			want = append(want, "requestheaders", "request", "responseheaders", "response")
		case "websocket":
			h.WebSocket = &websocket.Data{Messages: []*websocket.Message{websocket.NewMessage(websocket.OpText, true, []byte("one")), websocket.NewMessage(websocket.OpText, false, []byte("two"))}}
			names = append(names, "requestheaders", "request", "websocket_start", "websocket_end")
			want = append(want, "requestheaders", "request", "websocket_start", "1", "2", "websocket_end")
		case "tcp":
			x := flow.NewTCPFlow(h.ClientConn, h.ServerConn, false)
			x.Messages = []*tcp.Message{tcp.NewMessage(true, []byte("one")), tcp.NewMessage(false, []byte("two"))}
			model = x
		case "udp":
			x := flow.NewUDPFlow(h.ClientConn, h.ServerConn, false)
			x.Messages = []*udp.Message{udp.NewMessage(true, []byte("one")), udp.NewMessage(false, []byte("two"))}
			model = x
		case "dns":
			x := flow.NewDNSFlow(h.ClientConn, h.ServerConn, false)
			x.Request = &dns.Message{ID: 1, Query: true}
			x.Response = x.Request.Succeed(nil)
			model = x
			names = append(names, "dns_request", "dns_response")
			want = append(want, "dns_request", "dns_response")
		}
		if failed {
			model.Common().Error = flow.NewError("transport-error")
		}
		if kind == "tcp" || kind == "udp" {
			end := kind + "_end"
			if failed {
				end = kind + "_error"
			}
			names = append(names, kind+"_start", end)
			want = append(want, kind+"_start", "1", "2", end)
		} else if failed && kind != "websocket" {
			errHook := "error"
			if kind == "dns" {
				errHook = "dns_error"
			}
			names = append(names, errHook)
			want = append(want, errHook)
		}
		source := runRecordingSource(names...)
		if kind == "tcp" || kind == "udp" || kind == "websocket" {
			messages := "f.messages"
			if kind == "websocket" {
				messages = "f.websocket.messages"
			}
			source += fmt.Sprintf("def %s_message(f):\n    ctx.master.commands.call('run.record', str(len(%s)))\n", kind, messages)
		}
		invokeRun(t, f, f.file("sequence.star", source), []flow.Flow{model}, false)
		if diff := gocmp.Diff(want, *events); diff != "" {
			t.Fatal(diff)
		}
		f.wantLog("Addon error:", 0)
	}
}

func testRunDumpReplay(t *testing.T) {
	f := newFixture(t)
	x := f.request()
	x.Response, _ = httpmsg.MakeResponse(200, []byte("before"), nil)
	var recorded bytes.Buffer
	if err := flowio.NewWriter(&recorded).Add(x); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, "recorded.flow")
	if err := os.WriteFile(path, recorded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := flowio.NewReader(bytes.NewReader(data)).Next()
	if err != nil {
		t.Fatal(err)
	}
	script := f.file("replay.star", "def response(f):\n    f.response.content = b'after'\n    f.comment = 'replayed'\n")
	invokeRun(t, f, script, []flow.Flow{loaded}, false)
	var transformed bytes.Buffer
	if err := flowio.NewWriter(&transformed).Add(loaded); err != nil {
		t.Fatal(err)
	}
	result, err := flowio.NewReader(&transformed).Next()
	if err != nil {
		t.Fatal(err)
	}
	if result.Common().ID != x.ID || result.Common().Comment != "replayed" || string(result.(*flow.HTTPFlow).Response.RawContent) != "after" {
		t.Fatalf("recorded replay output=%v logs=%s", result, f.logs.String())
	}
}

func testRunMissingPath(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{filepath.Join(f.dir, "missing.star"), f.dir} {
		before := f.logs.String()
		invokeRun(t, f, path, []flow.Flow{f.request()}, false)
		added := strings.TrimPrefix(f.logs.String(), before)
		if strings.Count(added, "No such script:") != 1 || !strings.Contains(added, "No such script: "+path) {
			t.Fatalf("missing/nonregular path diagnostic: %s", added)
		}
	}
	f.wantLog("Addon error:", 0)
	f.wantLog("error in script", 0)
}

func testRunNestedAddons(t *testing.T) {
	f := newFixture(t)
	events := runRecorder(t, f)
	source := runRecordingSource("configure", "running", "request") + "def child_configure(updated):\n    ctx.master.commands.call('run.record', 'child-configure')\ndef child_running():\n    ctx.master.commands.call('run.record', 'child-running')\ndef child_request(f):\n    ctx.master.commands.call('run.record', 'child-request')\ndef leaf_request(f):\n    ctx.master.commands.call('run.record', 'leaf-request')\naddons = [module('child', configure=child_configure, running=child_running, request=child_request, addons=[module('leaf', request=leaf_request)])]\n"
	invokeRun(t, f, f.file("nested.star", source), []flow.Flow{f.request()}, false)
	want := []string{"configure", "child-configure", "running", "child-running", "request", "child-request", "leaf-request"}
	if diff := gocmp.Diff(want, *events); diff != "" {
		t.Fatal(diff)
	}
	if len(f.loader.entries) != 0 || f.master.Addons.Len() != 1 {
		t.Fatal("nested temporary addon registered in master")
	}
	f.wantLog("Addon error:", 0)
}

func testRunNoLoad(t *testing.T) {
	f := newFixture(t)
	path := f.file("owned.star", "def keep():\n    ctx.log('keep-called')\ndef on_load(loader):\n    loader.add_command('kept.command', keep)\ndef child_load(loader):\n    fail('child-load-invoked')\ndef request(f):\n    f.comment = 'run-without-load'\naddons = []\n")
	f.load(path)
	f.updateSource(path, "def on_load(loader):\n    fail('root-load-invoked')\ndef child_load(loader):\n    fail('child-load-invoked')\ndef request(f):\n    f.comment = 'run-without-load'\naddons = [module('child', on_load=child_load)]\n", time.Second)
	x := f.request()
	invokeRun(t, f, path, []flow.Flow{x}, false)
	if x.Comment != "run-without-load" {
		t.Fatal(f.logs.String())
	}
	value, err := f.master.Commands.Call(t.Context(), "kept.command")
	if err != nil || value != nil || maps.Collect(f.master.Commands.Commands())["script.run"] == nil {
		t.Fatalf("temporary command cleanup removed a loaded command: %v %v", value, err)
	}
	f.wantLog("keep-called", 1)
	f.wantLog("load-invoked", 0)
	f.wantLog("Addon error:", 0)
	if err := f.master.Addons.Remove(t.Context(), f.loader); err != nil {
		t.Fatal(err)
	}
	if maps.Collect(f.master.Commands.Commands())["script.run"] != nil || maps.Collect(f.master.Commands.Commands())["kept.command"] != nil {
		t.Fatal("registered command ownership survived loader removal")
	}
}
