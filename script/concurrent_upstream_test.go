// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
)

func TestScriptConcurrentUpstream(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		t.Run("TestConcurrent", func(t *testing.T) {
			t.Run("test_concurrent", func(t *testing.T) {
				tests := map[string]struct{ child bool }{"module": {}, "child_module": {true}}
				for name, test := range tests {
					t.Run(name, func(t *testing.T) {
						f := newFixture(t)
						entered, release := concurrentBarrier(t, f)
						source := "ctx.log('source-init')\nstate = {}\ndef _headers(f):\n    ctx.sleep(0.25)\n    f.comment += 'headers'\ndef _request(f):\n    ctx.sleep(0.25)\n    f.comment += 'request'\n"
						if test.child {
							source += "addons = [module('child', request=concurrent(_request), requestheaders=concurrent(_headers))]\n"
						} else {
							source += "request = concurrent(_request)\nrequestheaders = concurrent(_headers)\n"
						}
						f.load(f.file("upstream.star", source))
						f.wantLog("source-init", 2)
						flows := []*flow.HTTPFlow{f.request(), f.request()}
						dones := make([]<-chan error, len(flows))
						for n, x := range flows {
							done := make(chan error, 1)
							dones[n] = done
							go func() {
								if err := f.master.Addons.Hook(t.Context(), addon.RequestHeadersHook{Flow: x}); err != nil {
									done <- err
									return
								}
								done <- f.master.Addons.Hook(t.Context(), addon.RequestHook{Flow: x})
							}()
						}
						// Both source cycles enter their first worker before either can
						// finish. The real deadline criterion lives in tagged acceptance.
						for range 2 {
							if awaitConcurrent(t, entered) != 250*time.Millisecond {
								t.Fatal("upstream wait reduced")
							}
						}
						release()
						for _, done := range dones {
							if err := awaitConcurrent(t, done); err != nil {
								t.Fatal(err)
							}
						}
						for _, x := range flows {
							if x.Comment != "headersrequest" {
								t.Fatalf("child-only/source invocation wrong: %q %s", x.Comment, f.logs.String())
							}
						}
						f.wantLog("Addon error:", 0)
						// Child-only wrappers also freeze their own module globals; no
						// root wrapper may accidentally supply this second instance.
						if test.child {
							if err := f.master.Do(t.Context(), func(context.Context) error {
								root := f.loader.entries[0].module
								if len(root.liveNode.wrappers) != 0 || len(root.children) != 1 || len(root.children[0].workerNode.wrappers) != 2 {
									t.Fatal("not a child-only worker instance")
								}
								return nil
							}); err != nil {
								t.Fatal(err)
							}
							f.load()
							source = strings.Replace(source, "f.comment += 'request'", "f.comment += 'request'\n    state['write'] = 1", 1)
							f.load(f.file("upstream.star", source))
							x := f.request()
							f.hook(addon.RequestHook{Flow: x})
							if x.Comment != "request" {
								t.Fatal("failed child worker edits not merged")
							}
							f.wantLog("cannot insert into frozen hash table", 1)
						}
					})
				}
			})
			t.Run("test_concurrent_err", func(t *testing.T) {
				f := newFixture(t)
				f.load(f.file("invalid.star", "def _load(v):\n    pass\non_load = concurrent(_load)\n"))
				f.wantLog("Concurrent decorator not supported for 'on_load' method.", 1)
				if f.loader.entries[0].module != nil {
					t.Fatal("invalid upstream decorator registered")
				}
			})
		})
	})
}
