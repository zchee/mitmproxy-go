// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/clientplayback"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
)

func testWorkerCapacity(t *testing.T, cancelWaiter bool) {
	f := newFixture(t)
	entered, release := concurrentBarrier(t, f)
	f.load(loadConcurrent(f, "ctx.sleep(1)\nf.comment = 'admitted'"))
	instance := f.loader.entries[0].module.concurrent
	capacity := cap(instance.slots)
	if capacity < 5 || capacity > 32 {
		t.Fatalf("capacity=%d", capacity)
	}
	var dones []<-chan error
	for range capacity {
		dones = append(dones, startConcurrent(t, f, t.Context(), addon.RequestHook{Flow: f.request()}))
	}
	for range capacity {
		awaitConcurrent(t, entered)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waiting := f.request()
	done := startConcurrent(t, f, ctx, addon.RequestHook{Flow: waiting})
	// Independent dispatch admission must remain possible at saturation.
	if err := f.master.Do(t.Context(), func(context.Context) error {
		if len(instance.slots) != capacity {
			return errors.New("capacity not saturated")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if cancelWaiter {
		cancel()
		if err := awaitConcurrent(t, done); !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter cancellation=%v", err)
		}
		if waiting.Comment != "" {
			t.Fatal("canceled waiter ran")
		}
		select {
		case <-entered:
			t.Fatal("canceled waiter started worker")
		default:
		}
		release()
	} else {
		release()
		awaitConcurrent(t, entered)
		if err := awaitConcurrent(t, done); err != nil {
			t.Fatal(err)
		}
		if waiting.Comment != "admitted" {
			t.Fatalf("queued caller did not resume: %s", f.logs.String())
		}
	}
	for _, done := range dones {
		if err := awaitConcurrent(t, done); err != nil {
			t.Fatal(err)
		}
	}
	if len(instance.slots) != 0 {
		t.Fatal("worker capacity leaked")
	}
}

func testCommandCopyback(t *testing.T) {
	cycle := make([]any, 1)
	cycle[0] = cycle
	tests := map[string]struct{ value any }{
		"unsupported pointer":     {new(struct{ Data []byte })},
		"unsupported nested cell": {command.Data{{new(struct{ Data []byte })}}},
		"cyclic result":           {cycle},
	}
	for name, test := range tests {
		if value, err := new(commandOwnership).argument(test.value, 0); err == nil || value != nil {
			t.Fatalf("%s escaped command ownership: value=%T err=%v", name, value, err)
		}
	}
	f := newFixture(t)
	var retained *flow.HTTPFlow
	if err := f.master.Commands.Register("worker.mutate", func(_ context.Context, g flow.Flow) error {
		retained = g.(*flow.HTTPFlow)
		retained.Request.Path = "/immediate"
		retained.Comment = "command"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.master.Commands.Register("worker.later", func(context.Context) error { retained.Request.Path = "/late"; retained.Comment = "late"; return nil }); err != nil {
		t.Fatal(err)
	}
	f.load(loadConcurrent(f, "g = f.copy()\nr = g.request\nctx.master.commands.call('worker.mutate', g)\nif g.request.path != '/immediate' or r.path != '/immediate' or g.comment != 'command':\n    fail('immediate mutation missing')\nctx.master.commands.call('worker.later')\nif r.path != '/immediate' or g.request.path != '/immediate' or g.comment != 'command':\n    fail('retained mutation leaked')\nf.comment = 'copyback'"))
	x := f.request()
	f.hook(addon.RequestHook{Flow: x})
	if x.Comment != "copyback" || x.Request.Path != "/start" || retained == x {
		t.Fatalf("command ownership: %s", f.logs.String())
	}
	f.wantLog("Addon error:", 0)
}

func testCommandAliases(t *testing.T) {
	f := newFixture(t)
	if err := f.master.Commands.Register("worker.aliases", func(_ context.Context, a flow.Flow, values []flow.Flow, b flow.Flow) error {
		if a != b || len(values) != 2 || values[0] != a || values[1] != a {
			return errors.New("repeated command references lost")
		}
		a.(*flow.HTTPFlow).Request.Path = "/alias"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.master.Commands.Register("worker.listaliases", func(_ context.Context, a, b []flow.Flow) error {
		if len(a) != 2 || len(b) != 2 || &a[0] != &b[0] {
			return errors.New("repeated sequence references lost")
		}
		a[0] = a[1]
		if a[0] != b[0] {
			return errors.New("command-owned sequences do not alias")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.load(loadConcurrent(f, "g = f.copy()\nalias = g\nctx.master.commands.call('worker.aliases', g, [g, alias], alias)\nif alias.request.path != '/alias' or g.request.path != '/alias':\n    fail('alias copyback missing')\nvalues = [g, f.copy()]\nctx.master.commands.call('worker.listaliases', values, values)\nif values[0] != g:\n    fail('command retained argument storage')\nf.comment = 'aliases'"))
	x := f.request()
	f.hook(addon.RequestHook{Flow: x})
	if x.Comment != "aliases" {
		t.Fatalf("argument aliases: %s", f.logs.String())
	}
	f.wantLog("Addon error:", 0)
}

type replayCapture struct{ value *flow.HTTPFlow }

func (*replayCapture) Name() string { return "script-replay-capture" }
func (c *replayCapture) Update(_ context.Context, flows []flow.Flow) error {
	for _, f := range flows {
		if h, ok := f.(*flow.HTTPFlow); ok && h.IsReplay != nil && *h.IsReplay == "request" {
			c.value = h
		}
	}
	return nil
}

func testRetainedCopyCommand(t *testing.T) {
	f := newFixture(t)
	replay := clientplayback.New(f.master)
	capture := new(replayCapture)
	if err := f.master.Addons.Add(t.Context(), replay, capture); err != nil {
		t.Fatal(err)
	}
	if err := f.master.Commands.Register("queue.path", func(context.Context) string {
		if capture.value == nil {
			return "missing"
		}
		return capture.value.Request.Path
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.master.Commands.Register("queue.edit", func(context.Context) error {
		if capture.value == nil {
			return errors.New("queue not observed")
		}
		capture.value.Request.Path = "/queue-late"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.load(loadConcurrent(f, "g = f.copy()\nctx.master.commands.call('replay.client', [g])\nif g.is_replay != 'request':\n    fail('replay immediate mutation missing')\ng.request.path = '/worker-late'\nif ctx.master.commands.call('queue.path') != '/start':\n    fail('worker changed replay queue')\nctx.master.commands.call('queue.edit')\nif g.request.path != '/worker-late':\n    fail('replay queue changed worker')\nctx.master.commands.call('replay.client.stop')\nif g.is_replay != 'request' or g.request.path != '/worker-late':\n    fail('queue stop/revert changed worker')\nf.comment = 'retained-isolated'"))
	x := f.request()
	f.hook(addon.RequestHook{Flow: x})
	if x.Comment != "retained-isolated" || capture.value == nil || capture.value == x {
		t.Fatalf("real replay retention failed: %s", f.logs.String())
	}
	count, err := f.master.Call(t.Context(), "replay.client.count")
	if err != nil || count != 0 {
		t.Fatalf("replay queue not stopped: %v %v", count, err)
	}
	f.wantLog("Addon error:", 0)
}

func testChildInvalidBinding(t *testing.T) {
	f := newFixture(t)
	f.load(f.file("child-invalid.star", "def _request(f):\n    pass\naddons = [module('child', helper=concurrent(_request))]\n"))
	f.wantLog("Concurrent decorator not supported for 'helper' method.", 1)
	if f.loader.entries[0].module != nil {
		t.Fatal("child invalid binding registered")
	}
}

func testChildFrozenPathMismatch(t *testing.T) {
	for _, variant := range []string{"missing", "name", "arity", "extra"} {
		f := newFixture(t)
		if err := f.master.Commands.Register("init.next", func(ctx context.Context) bool {
			first := f.master.Options.Str("listen_host") == ""
			if err := f.master.Options.Update(ctx, map[string]any{"listen_host": "initialized"}); err != nil {
				t.Error(err)
			}
			return first
		}); err != nil {
			t.Fatal(err)
		}
		second := "addons = []"
		switch variant {
		case "name":
			second = "addons = [module('other', request=concurrent(_one))]"
		case "arity":
			second = "addons = [module('child', request=concurrent(_two))]"
		case "extra":
			second = "addons = [module('child', request=concurrent(_one), response=concurrent(_one))]"
		}
		second = strings.TrimPrefix(second, "addons = ")
		text := "def _one(f):\n    pass\ndef _two(f, other):\n    pass\ndef build():\n    if ctx.master.commands.call('init.next'):\n        return [module('child', request=concurrent(_one))]\n    return " + second + "\naddons = build()\n"
		f.load(f.file("mismatch.star", text))
		if f.loader.entries[0].module != nil {
			t.Fatalf("%s mismatch registered", variant)
		}
		f.wantLog("error in script", 1)
		if !strings.Contains(f.logs.String(), "concurrent") {
			t.Fatalf("%s missing path diagnostic: %s", variant, f.logs.String())
		}
	}
}

func testChildTopologyDrift(t *testing.T) {
	for _, operation := range []string{"clear", "replace", "reorder"} {
		f := newFixture(t)
		entered, release := concurrentBarrier(t, f)
		mutation := "children.clear()"
		switch operation {
		case "replace":
			mutation = "children[0] = module('replacement')"
		case "reorder":
			mutation = "children[0], children[1] = children[1], children[0]"
		}
		text := fmt.Sprintf("ctx.log('child-init')\nchildren = []\ndef work_a():\n    ctx.log('command-a')\ndef work_b():\n    ctx.log('command-b')\ndef load_a(loader):\n    loader.add_command('child.a', work_a)\ndef load_b(loader):\n    loader.add_command('child.b', work_b)\ndef done_a():\n    ctx.log('done-a')\ndef done_b():\n    ctx.log('done-b')\ndef _request(f):\n    ctx.sleep(1)\n    f.comment += 'child'\nchildren.append(module('a', on_load=load_a, done=done_a, request=concurrent(_request)))\nchildren.append(module('b', on_load=load_b, done=done_b))\naddons = children\ndef response(f):\n    %s\n", mutation)
		path := f.file("topology.star", text)
		f.load(path)
		root := f.loader.entries[0].module
		if root == nil {
			t.Fatalf("%s load: %s", operation, f.logs.String())
		}
		registered := []string{root.Name(), root.children[0].Name(), root.children[1].Name()}
		x := f.request()
		inflight := startConcurrent(t, f, t.Context(), addon.RequestHook{Flow: x})
		awaitConcurrent(t, entered)
		f.hook(addon.ResponseHook{Flow: f.request()})
		blocked := f.request()
		f.hook(addon.RequestHook{Flow: blocked})
		if blocked.Comment != "" || blocked.Intercepted() {
			t.Fatalf("%s wrong frozen mapping or stuck flow", operation)
		}
		if !strings.Contains(f.logs.String(), "changed") {
			t.Fatalf("%s drift not diagnosed: %s", operation, f.logs.String())
		}
		f.load()
		for _, name := range registered {
			if f.master.Addons.Get(name) != nil {
				t.Fatalf("%s stale lookup %s", operation, name)
			}
		}
		for _, name := range []string{"child.a", "child.b"} {
			if _, err := f.master.Call(t.Context(), name); err == nil {
				t.Fatalf("%s stale command %s", operation, name)
			}
		}
		f.wantLog("done-a", 1)
		f.wantLog("done-b", 1)
		release()
		if err := awaitConcurrent(t, inflight); err != nil {
			t.Fatal(err)
		}
		if x.Comment != "child" {
			t.Fatalf("%s retired worker did not merge", operation)
		}
		f.load(path)
		for _, name := range registered {
			if f.master.Addons.Get(name) == nil {
				t.Fatalf("%s same-name reload absent %s; %s", operation, name, f.logs.String())
			}
		}
		for _, name := range []string{"child.a", "child.b"} {
			if _, err := f.master.Call(t.Context(), name); err != nil {
				t.Fatalf("%s command re-registration %s: %v", operation, name, err)
			}
		}
		f.wantLog("command-a", 1)
		f.wantLog("command-b", 1)
		f.load()
		f.wantLog("done-a", 2)
		f.wantLog("done-b", 2)
		if err := f.loader.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
