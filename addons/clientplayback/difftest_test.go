// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package clientplayback

import (
	json "encoding/json/v2"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestUpstreamOptions(t *testing.T) {
	m, _ := setup(t)
	var reference map[string]struct {
		Type    string
		Default any
		Help    string
	}
	output := difftest.Python(t, `
import json
from mitmproxy import ctx, options
from mitmproxy.addons.clientplayback import ClientPlayback
ctx.options = options.Options()
class Loader:
    def add_option(self, *args, **kwargs):
        ctx.options.add_option(*args, **kwargs)
ClientPlayback().load(Loader())
result = {}
for name in ctx.options.keys():
    if name.startswith('client_replay'):
        o = ctx.options._options[name]
        result[name] = {'Type': 'int' if o.typespec is int else 'sequence of str', 'Default': o.default, 'Help': o.help}
print(json.dumps(result))
`, nil)
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	for name, want := range reference {
		o, ok := m.Options.Lookup(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		var def any
		encoded, err := json.Marshal(o.Default())
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &def); err != nil {
			t.Fatal(err)
		}
		got := struct {
			Type    string
			Default any
			Help    string
		}{o.Type().String(), def, o.Help()}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("%s: %s", name, diff)
		}
	}
}
