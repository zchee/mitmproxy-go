// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowview

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

func verifyBodyCache(t *testing.T) {
	t.Helper()
	calls := 0
	registry := &contentviews.Registry{}
	registry.Register(contentviews.Raw{})
	registry.Register(customView{text: strings.Repeat("x", 64<<10), renders: &calls})
	f := fixture(t)
	m := New(t.Context(), nil)
	m.Resize(40, 8)
	snapshot := contract.Snapshot{Focused: f, Detail: contract.DetailOptions{Registry: registry, DefaultContentView: "custom", LineCutoff: 512}}
	m.SetSnapshot(snapshot)
	first := m.View()
	if calls != 1 {
		t.Fatalf("initial render walked body %d times, want 1", calls)
	}
	bodyIndex := len(m.lines) - 1
	wrapped := m.wrapped[bodyIndex]
	if len(wrapped) == 0 {
		t.Fatal("body hard-wrap was not retained")
	}
	m.Resize(40, 8)
	if diff := gocmp.Diff(first, m.View()); diff != "" {
		t.Fatalf("unchanged render changed frame: %s", diff)
	}
	if calls != 1 || &wrapped[0] != &m.wrapped[bodyIndex][0] {
		t.Fatalf("unchanged render repeated content formatting or hard-wrap: calls=%d", calls)
	}
	m.search[m.tab].Matched = true
	m.search[m.tab].Focus = bodyIndex
	matched := m.View()
	if !strings.Contains(matched, "\x1b[") || &wrapped[0] != &m.wrapped[bodyIndex][0] {
		t.Fatal("search highlighting did not reuse wrapped body lines")
	}
	m.search[m.tab].Matched = false
	m.search[m.tab].Focus = 0
	tests := map[string]struct{ change func() }{
		"body identity":       {func() { m.snapshot.Focused = f.Copy() }},
		"body generation":     {func() { m.snapshot.Generation++ }},
		"width":               {func() { m.width++ }},
		"height":              {func() { m.height++ }},
		"cutoff":              {func() { m.snapshot.Detail.LineCutoff++ }},
		"full contents":       {func() { m.snapshot.Detail.FullContents = !m.snapshot.Detail.FullContents }},
		"registry generation": {func() { m.snapshot.RegistryGeneration++ }},
		"definitions":         {func() { m.snapshot.Detail.ProtobufDefinitions = "other.proto" }},
		"palette":             {func() { m.palette, _ = style.NewPalette("light", true) }},
		"tab":                 {func() { m.tab = 1 - m.tab }},
	}
	for name, test := range tests {
		before := calls
		test.change()
		m.render()
		m.View()
		if calls != before+1 {
			t.Fatalf("%s did not invalidate content cache: before=%d after=%d", name, before, calls)
		}
		m.render()
		m.View()
		if calls != before+1 {
			t.Fatalf("%s did not cache the refreshed body: %d", name, calls)
		}
	}
	before := calls
	m.tab = 0
	m.SetSnapshot(snapshot)
	if calls != before+1 {
		t.Fatal("fresh snapshot did not invalidate the detached body generation")
	}
	m.snapshot.Detail.DefaultContentView = "raw"
	m.render()
	if got := ansi.Strip(m.View()); strings.Contains(got, "xxxxxxxx") || !strings.Contains(got, "body") {
		t.Fatalf("content mode change reused stale formatted body: %q", got)
	}
	m.snapshot.Detail.DefaultContentView = "custom"
	m.render()
	if calls != before+2 {
		t.Fatal("returning to custom mode reused a different contentview")
	}
}
