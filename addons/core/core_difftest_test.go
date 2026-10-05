// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package core_test

import (
	json "encoding/json/v2"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestDifferentialCommandMetadata(t *testing.T) {
	type metadata struct {
		Signature string   `json:"signature"`
		Help      string   `json:"help"`
		Types     []string `json:"types"`
		Return    string   `json:"return"`
	}
	var want map[string]metadata
	if err := json.Unmarshal(difftest.Python(t, `
import json
from mitmproxy import command
from mitmproxy.addons import core
manager = command.CommandManager(None)
manager.collect_commands(core.Core())
print(json.dumps({name: {
    "signature": cmd.signature_help(),
    "help": cmd.help or "",
    "types": [command.typename(param.type) for param in cmd.parameters],
    "return": command.typename(cmd.return_type) if cmd.return_type else "",
} for name, cmd in manager.commands.items()}))
`, nil), &want); err != nil {
		t.Fatal(err)
	}
	h := setup(t)
	got := make(map[string]metadata)
	for name, cmd := range h.manager.Commands().Commands() {
		m := metadata{Signature: cmd.SignatureHelp(), Help: cmd.Help, Types: []string{}}
		for _, p := range cmd.Params {
			m.Types = append(m.Types, p.Type.Display())
		}
		if cmd.Return != nil {
			m.Return = cmd.Return.Display()
		}
		got[name] = m
	}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Fatalf("core command metadata (-Python +Go):\n%s", diff)
	}
}
