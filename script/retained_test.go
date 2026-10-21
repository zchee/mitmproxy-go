// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/websocket"
)

func testRetainedHandleLifetime(t *testing.T) {
	t.Helper()
	f := newFixture(t)
	if err := f.master.Commands.Register("native.retained", func(ctx context.Context, value flow.Flow) error {
		value.Common().Comment = "retained-command"
		return f.master.Options.Update(ctx, map[string]any{"listen_host": "retained-scope"})
	}); err != nil {
		t.Fatal(err)
	}
	f.load(f.file("retained.star", `state = {}
def on_load(loader):
    state["loader"] = loader
def request(f):
    if "request" not in state:
        state["flow"] = f
        state["request"] = f.request
        state["response"] = f.response
        state["headers"] = f.request.headers
        state["message"] = f.websocket.messages[0]
        state["connection"] = f.server_conn
    else:
        state["request"].path = "/reused"
        state["response"].reason = "retained"
        state["headers"]["X-Retained"] = "yes"
        state["message"].content = b"retained"
        state["connection"].error = "retained"
        ctx.master.commands.call("native.retained", state["flow"])
        f.comment = "complete"
`))
	first := f.request()
	var err error
	first.Response, err = httpmsg.MakeResponse(200, []byte{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	first.WebSocket = &websocket.Data{Messages: []*websocket.Message{{Content: []byte("before")}}}
	f.hook(addon.RequestHook{Flow: first})
	module := f.loader.entries[0].module
	fields := map[string]string{"flow": "comment", "request": "path", "response": "reason", "headers": "get_all", "message": "content", "connection": "error"}
	handles := make(map[string]starlark.HasAttrs)
	var loader starlark.HasAttrs
	if err := f.master.Do(t.Context(), func(context.Context) error {
		state := module.members["state"].(*starlark.Dict)
		for name := range fields {
			value, _, err := state.Get(starlark.String(name))
			if err != nil {
				return err
			}
			handles[name] = value.(starlark.HasAttrs)
		}
		value, _, err := state.Get(starlark.String("loader"))
		if err != nil {
			return err
		}
		loader = value.(starlark.HasAttrs)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	second := f.request()
	f.hook(addon.RequestHook{Flow: second})
	if first.Request.Path != "/reused" || first.Response.Reason != "retained" || first.Request.Headers.Get("X-Retained") != "yes" || string(first.WebSocket.Messages[0].Content) != "retained" || first.ServerConn.Error == nil || first.Comment != "retained-command" || second.Comment != "complete" || f.master.Options.Str("listen_host") != "retained-scope" {
		t.Fatalf("later ordinary scope could not reuse retained models: %s", f.logs.String())
	}
	outside := make(chan error, 1)
	for name, handle := range handles {
		go func() { _, err := handle.Attr(fields[name]); outside <- err }()
		if err := <-outside; err == nil {
			t.Fatalf("outside-dispatch goroutine accessed retained %s", name)
		}
	}
	foreign := &capabilities{entry: &scriptEntry{owner: f.loader, path: "other-instance"}}
	if err := f.master.Do(t.Context(), func(ctx context.Context) error {
		return foreign.evaluate(ctx, "foreign", func(*starlark.Thread, *invocation) error {
			for name, handle := range handles {
				if _, err := handle.Attr(fields[name]); err == nil {
					return fmt.Errorf("another script accessed retained %s", name)
				}
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.master.Do(t.Context(), func(ctx context.Context) error {
		return module.graph.evaluate(ctx, "expired-loader", func(*starlark.Thread, *invocation) error {
			_, err := loader.Attr("add_option")
			if err == nil {
				return errors.New("on_load loader survived its invocation")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	_, program, err := starlark.SourceProgramOptions(&syntax.FileOptions{}, "isolated-worker.star", "def inspect(handle):\n    return handle.path\n", func(string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	var frozen starlark.StringDict
	if err := f.master.Do(t.Context(), func(context.Context) error {
		var err error
		frozen, err = program.Init(&starlark.Thread{}, nil)
		frozen.Freeze()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := starlark.Call(&starlark.Thread{Name: "isolated-worker"}, frozen["inspect"], starlark.Tuple{handles["request"]}, nil)
		outside <- err
	}()
	if err := <-outside; err == nil {
		t.Fatal("frozen worker accessed an ordinary model handle")
	}
	f.load()
	if err := f.master.Do(t.Context(), func(ctx context.Context) error {
		return module.graph.evaluate(ctx, "retired-probe", func(*starlark.Thread, *invocation) error {
			for name, handle := range handles {
				if _, err := handle.Attr(fields[name]); err == nil {
					return fmt.Errorf("retired instance accessed retained %s", name)
				}
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
}
