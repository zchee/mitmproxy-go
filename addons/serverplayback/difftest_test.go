// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package serverplayback

import (
	"encoding/hex"
	json "encoding/json/v2"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestUpstreamOptionsAndHash(t *testing.T) {
	m, s := setup(t)
	var reference struct {
		Options map[string]struct {
			Type    string
			Default any
			Help    string
			Choices []string
		}
		Hash string
	}
	output := difftest.Python(t, `
import json
from mitmproxy import ctx, options
from mitmproxy.addons.serverplayback import ServerPlayback
from mitmproxy.test import tflow
ctx.options = options.Options()
class Loader:
    def add_option(self, *args, **kwargs):
        ctx.options.add_option(*args, **kwargs)
s = ServerPlayback()
s.load(Loader())
result = {}
for name in ctx.options.keys():
    if name.startswith('server_replay'):
        o = ctx.options._options[name]
        typ = {bool:'bool',str:'str'}.get(o.typespec, 'sequence of str')
        result[name] = {'Type':typ,'Default':o.default,'Help':o.help,'Choices':o.choices}
print(json.dumps({'Options':result,'Hash':s._hash(tflow.tflow()).hex()}))
`, nil)
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	for name, want := range reference.Options {
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
			Choices []string
		}{o.Type().String(), def, o.Help(), o.Choices()}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("%s: %s", name, diff)
		}
	}
	if got := hex.EncodeToString([]byte(s.hash(testflow.TFlow()))); got != reference.Hash {
		t.Fatalf("hash=%s upstream=%s", got, reference.Hash)
	}
}
