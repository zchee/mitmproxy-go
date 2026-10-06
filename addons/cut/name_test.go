// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package cut_test

import (
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/cut"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/options"
)

// Addon occupies the default name of a type with no explicit addon name.
type Addon struct{}

func TestRegistrationName(t *testing.T) {
	tests := map[string]struct{ namedFirst bool }{
		"success: unnamed addon first": {},
		"success: named addon first":   {namedFirst: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
			t.Cleanup(m.Close)
			a := cut.New()
			addons := []any{&Addon{}, a}
			if tt.namedFirst {
				addons = []any{a, &Addon{}}
			}
			if err := m.Add(t.Context(), addons...); err != nil {
				t.Fatal(err)
			}
			namer, ok := any(a).(addon.Namer)
			if !ok || namer.Name() != "cut" {
				t.Fatal("addon must explicitly use upstream's cut name")
			}
			if m.Get("cut") != a {
				t.Fatal("registered addon cannot be found by its upstream name")
			}
		})
	}
}
