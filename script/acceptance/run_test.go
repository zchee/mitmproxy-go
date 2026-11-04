// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package acceptance_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

type runObserver struct {
	commands *command.Manager
	flows    []flow.Flow
	path     command.Path
	headers  int
}

func (o *runObserver) RequestHeaders(context.Context, *flow.HTTPFlow) error { o.headers++; return nil }

func (o *runObserver) Request(ctx context.Context, _ *flow.HTTPFlow) error {
	if o.path == "" {
		return nil
	}
	_, err := o.commands.Call(ctx, "script.run", o.flows, o.path)
	return err
}

func runDepths(t *testing.T) {
	for _, nested := range []bool{false, true} {
		for _, child := range []bool{false, true} {
			a := assembledDump(t)
			source := `def _headers(f):
    f.comment = "requestheaders called"
def _request(f):
    ctx.log("wrapper must not run")
def response(f):
    ctx.log("response must not run")
`
			if child {
				source += "addons = [module('child', requestheaders=_headers, request=concurrent(_request))]\n"
			} else {
				source += "requestheaders = _headers\nrequest = concurrent(_request)\n"
			}
			path := scriptFile(t, source)
			first, second := testflow.TFlow(), testflow.TFlow()
			first.Comment, second.Comment = "", ""
			observer := &runObserver{commands: a.m.Commands, flows: []flow.Flow{first, second}}
			if nested {
				observer.path = command.Path(path)
			}
			if err := a.m.Addons.Add(t.Context(), observer); err != nil {
				t.Fatal(err)
			}
			if nested {
				a.hook(t, addon.RequestHook{Flow: testflow.TFlow()})
			} else if _, err := a.m.Call(t.Context(), "script.run", observer.flows, command.Path(path)); err != nil {
				t.Fatal(err)
			}
			equal(t, "requestheaders called", first.Comment)
			equal(t, "", second.Comment)
			equal(t, 0, observer.headers)
			equal(t, 0, strings.Count(a.logs.text(), "wrapper must not run"))
			equal(t, 0, strings.Count(a.logs.text(), "response must not run"))
			equal(t, 1, strings.Count(a.logs.text(), "Addon error:"))
			a.logs.contains(t, "Async handler request (")
			a.logs.contains(t, "cannot be called from sync context")
			t.Logf("module-only first-error isolation: nested=%v child=%v", nested, child)
		}
	}
}

func runLoadError(t *testing.T) {
	a := assembledDump(t)
	path := scriptFile(t, "def _load(loader):\n    ctx.log('unexpected load')\non_load = concurrent(_load)\ndef running():\n    ctx.log('unexpected running')\n")
	if _, err := a.m.Call(t.Context(), "script.run", []flow.Flow{testflow.TFlow()}, command.Path(path)); err != nil {
		t.Fatal(err)
	}
	a.logs.contains(t, "error in script "+path)
	a.logs.contains(t, "Concurrent decorator not supported for 'on_load' method.")
	equal(t, 0, strings.Count(a.logs.text(), "unexpected"))
}

func dumpReplay(t *testing.T) {
	origin, seen := ownedOrigin(t, "replayed")
	transform := scriptFile(t, "def request(f):\n    f.request.path = '/transformed'\n    f.request.headers['x-script-run'] = 'recorded-flow'\n")
	driver := scriptFile(t, fmt.Sprintf("def request(f):\n    ctx.master.commands.call('script.run', [f], %q)\n", transform))
	f := testflow.TFlow()
	var err error
	f.Request, err = httpmsg.MakeRequest("GET", origin.URL+"/recorded", nil, httpmsg.Headers{{Name: []byte("Host"), Value: []byte(strings.TrimPrefix(origin.URL, "http://"))}})
	if err != nil {
		t.Fatal(err)
	}
	f.Response = nil
	f.Live = false
	path := filepath.Join(t.TempDir(), "recorded.mitm")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := flowio.NewWriter(file).Add(f); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	p := startProcess(t, origin.URL, "-n", "-C", path, "-s", driver)
	p.wait(t)
	r := receive(t, seen)
	equal(t, "/transformed", r.path)
	equal(t, "recorded-flow", r.headers.Get("X-Script-Run"))
	equal(t, 1, len(p.route.destinations()))
	if strings.Contains(p.logs.text(), "Addon error:") {
		t.Fatalf("script.run replay failed:\n%s", p.logs.text())
	}
}

func optionsMetadata(t *testing.T) {
	p := startProcess(t, "", "-n", "--options")
	p.wait(t)
	metadata := strings.ReplaceAll(p.logs.text(), "\n# ", " ")
	for _, text := range []string{"Execute a script. Type sequence of str.", "scripts: []", "script_max_steps: 0", "0 means no limit. Type int."} {
		if !strings.Contains(metadata, text) {
			t.Errorf("missing exact option metadata %q", text)
		}
	}
	custom := startProcess(t, "", "-n", "-s", examplePath("options-simple"), "--options")
	custom.wait(t)
	if !strings.Contains(custom.logs.text(), "addheader: false") {
		t.Fatal("script custom option missing from assembled metadata")
	}
}
