// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package view

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

// Upstream test_marker belongs to the console renderer, not this addon.
// Upstream intercept/resume/kill methods have no Go hook counterpart: core
// dispatches Update instead. WebSocket changes also reach Update, as upstream
// view.py has no websocket_* handlers.
func TestUpstreamView(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T, *View) }{
		"test_order_refresh": {func(t *testing.T, v *View) {
			f := testflow.TFlow(testflow.WithResponse)
			must(t, v.setOrder(t.Context(), "time"))
			v.Add(t.Context(), []flow.Flow{f})
			events, cancel := v.Subscribe(10)
			defer cancel()
			f.TimestampCreated = 10
			if len(events) != 0 {
				t.Fatal("unsignalled mutation caused event")
			}
			must(t, v.Update(t.Context(), []flow.Flow{f}))
			if e := <-events; e.Kind != "view_refresh" {
				t.Fatalf("%+v", e)
			}
		}},
		"test_order_generators_http": {func(t *testing.T, v *View) {
			f := testflow.TFlow(testflow.WithResponse)
			checkKey(t, f, 946681200, "GET", "http://address:22/path", 14)
		}},
		"test_order_generators_dns": {func(t *testing.T, v *View) {
			f := testflow.TDNSFlow(testflow.WithResponse)
			checkKey(t, f, 946681200, "QUERY", "dns.google", 8)
			f.Response = nil
			if generate("size", f).number != 0 {
				t.Fatal("DNS without response has size")
			}
		}},
		"test_order_generators_tcp": {func(t *testing.T, v *View) { checkKey(t, testflow.TTCPFlow(), 946681200, "TCP", "address:22", 12) }},
		"test_order_generators_udp": {func(t *testing.T, v *View) { checkKey(t, testflow.TUDPFlow(), 946681200, "UDP", "address:22", 12) }},
		"test_simple": {func(t *testing.T, v *View) {
			f, f2, f3 := fixture("GET", 1), fixture("GET", 3), fixture("GET", 2)
			if v.StoreCount() != 0 {
				t.Fatal("initial count")
			}
			must(t, v.RequestHeaders(t.Context(), f))
			if v.GetByID(f.ID) != f || v.GetByID("nonexistent") != nil {
				t.Fatal("ID lookup")
			}
			for _, hook := range []func(context.Context, *flow.HTTPFlow) error{v.Error, v.Response} {
				must(t, hook(t.Context(), f))
			}
			must(t, v.Intercept(t.Context(), f))
			must(t, v.Resume(t.Context(), f))
			must(t, v.Kill(t.Context(), f))
			must(t, v.RequestHeaders(t.Context(), f))
			must(t, v.RequestHeaders(t.Context(), f2))
			must(t, v.RequestHeaders(t.Context(), f2))
			must(t, v.RequestHeaders(t.Context(), f3))
			must(t, v.RequestHeaders(t.Context(), f3))
			equalFlows(t, []flow.Flow{f, f3, f2}, v.Flows())
			if v.StoreCount() != 3 || !v.inbounds(t.Context(), 0) || v.inbounds(t.Context(), -1) || v.inbounds(t.Context(), 100) {
				t.Fatal("counts or bounds")
			}
			f.Marked = "x"
			f2.Marked = "x"
			v.clearUnmarked(t.Context())
			equalFlows(t, []flow.Flow{f, f2}, v.Flows())
			v.clear(t.Context())
			if v.Len() != 0 || v.StoreCount() != 0 {
				t.Fatal("clear")
			}
		}},
		"test_simple_tcp": {func(t *testing.T, v *View) {
			f := testflow.TTCPFlow()
			must(t, v.TCPStart(t.Context(), f))
			must(t, v.TCPStart(t.Context(), f))
			must(t, v.TCPMessage(t.Context(), f))
			must(t, v.TCPError(t.Context(), f))
			must(t, v.TCPEnd(t.Context(), f))
			equalFlows(t, []flow.Flow{f}, v.Flows())
		}},
		"test_simple_udp": {func(t *testing.T, v *View) {
			f := testflow.TUDPFlow()
			must(t, v.UDPStart(t.Context(), f))
			must(t, v.UDPStart(t.Context(), f))
			must(t, v.UDPMessage(t.Context(), f))
			must(t, v.UDPError(t.Context(), f))
			must(t, v.UDPEnd(t.Context(), f))
			equalFlows(t, []flow.Flow{f}, v.Flows())
		}},
		"test_simple_dns": {func(t *testing.T, v *View) {
			f := testflow.TDNSFlow(testflow.WithResponse, testflow.WithError)
			must(t, v.DNSRequest(t.Context(), f))
			must(t, v.DNSRequest(t.Context(), f))
			must(t, v.DNSResponse(t.Context(), f))
			must(t, v.DNSError(t.Context(), f))
			equalFlows(t, []flow.Flow{f}, v.Flows())
		}},
		"test_filter": {func(t *testing.T, v *View) {
			v.Add(t.Context(), []flow.Flow{fixture("GET", 0), fixture("PUT", 0), fixture("GET", 0), fixture("PUT", 0)})
			if err := v.setFilterCommand(t.Context(), "~m get"); err != nil {
				t.Fatal(err)
			}
			if v.Len() != 2 || v.StoreCount() != 4 {
				t.Fatal("filter changed store")
			}
			v.SetFilter(nil)
			v.toggleMarked(t.Context())
			if v.Len() != 0 {
				t.Fatal("unmarked visible")
			}
			v.toggleMarked(t.Context())
			if err := v.setFilterCommand(t.Context(), "~notafilter regex"); err == nil {
				t.Fatal("invalid filter accepted")
			}
			v.Flows()[1].Common().Marked = "x"
			v.toggleMarked(t.Context())
			if v.Len() != 1 {
				t.Fatal("marked filter")
			}
			v.toggleMarked(t.Context())
			if v.Len() != 4 {
				t.Fatal("unfilter")
			}
		}},
		"test_create": {func(t *testing.T, v *View) {
			for range 2 {
				if err := v.create(t.Context(), "get", "http://foo.com"); err != nil {
					t.Fatal(err)
				}
			}
			if v.Len() != 2 || v.Flows()[0].(*flow.HTTPFlow).Request.URL() != "http://foo.com/" {
				t.Fatal("created URL")
			}
			for _, url := range []string{"http://foo.com\\", "http://"} {
				if err := v.create(t.Context(), "get", url); err == nil || !strings.Contains(err.Error(), "Invalid URL") {
					t.Fatalf("url %q: %v", url, err)
				}
			}
		}},
		"test_orders": {func(t *testing.T, v *View) {
			if diff := cmp.Diff([]string{"method", "size", "time", "url"}, v.orderOptions(t.Context())); diff != "" {
				t.Fatal(diff)
			}
		}},
		"test_load": {func(t *testing.T, v *View) {
			var logs []string
			handler := addon.NewLogHandler(func(_ context.Context, entry addon.LogEntry) { logs = append(logs, entry.Msg) }, addon.LogHandlerOptions{})
			previous := slog.Default()
			slog.SetDefault(slog.New(handler))
			defer slog.SetDefault(previous)
			defer func() { must(t, handler.Close(t.Context())) }()
			path := filepath.Join(t.TempDir(), "flows")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			w := flowio.NewWriter(f)
			for range 2 {
				if err := w.Add(testflow.TFlow(testflow.WithResponse)); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			v.loadFile(t.Context(), command.Path(path))
			v.loadFile(t.Context(), command.Path(path))
			if v.Len() != 4 {
				t.Fatal("load does not copy IDs")
			}
			v.loadFile(t.Context(), command.Path(path+"missing"))
			if err := os.WriteFile(path, []byte("invalidflows"), 0o600); err != nil {
				t.Fatal(err)
			}
			v.loadFile(t.Context(), command.Path(path))
			must(t, handler.Flush(t.Context()))
			if len(logs) != 2 || !strings.HasSuffix(logs[1], "Invalid data format.") {
				t.Fatal(logs)
			}
			if v.Len() != 4 {
				t.Fatal("invalid file added flows")
			}
		}},
		"test_resolve": {func(t *testing.T, v *View) {
			f := fixture("GET", 0)
			for _, spec := range []string{"@all", "@focus", "@shown", "@hidden", "@marked", "@unmarked", "@" + f.ID, "~m get"} {
				got, err := v.resolve(t.Context(), spec)
				if err != nil || len(got) != 0 {
					t.Fatalf("%s: %v %v", spec, got, err)
				}
			}
			fs := []flow.Flow{f, fixture("PUT", 0), fixture("GET", 0), fixture("PUT", 0)}
			v.Add(t.Context(), fs)
			must(t, v.setFilterCommand(t.Context(), "~m get"))
			f.Marked = "x"
			cases := map[string][]flow.Flow{"~m get": {fs[0], fs[2]}, "~m put": {fs[1], fs[3]}, "@shown": {fs[0], fs[2]}, "@hidden": {fs[1], fs[3]}, "@marked": {fs[0]}, "@unmarked": {fs[1], fs[2], fs[3]}, "@all": fs, "@focus": {fs[0]}, "@" + f.ID: {fs[0]}, "@" + fs[3].Common().ID + "," + f.ID: {fs[0], fs[3]}}
			for spec, want := range cases {
				got, err := v.resolve(t.Context(), spec)
				if err != nil {
					t.Fatal(err)
				}
				equalFlows(t, want, got)
			}
			if _, err := v.resolve(t.Context(), "~"); err == nil || !strings.Contains(err.Error(), "Invalid filter expression") {
				t.Fatal(err)
			}
		}},
		"test_movement": {func(t *testing.T, v *View) {
			v.goFocus(t.Context(), 0)
			for range 5 {
				v.Add(t.Context(), []flow.Flow{fixture("GET", 0)})
			}
			for offset, want := range map[int]int{-1: 4, 0: 0, 1: 1, 999: 4, -999: 0} {
				v.goFocus(t.Context(), offset)
				if v.Focus.Index() != want {
					t.Fatalf("%d: %d", offset, v.Focus.Index())
				}
			}
			v.goFocus(t.Context(), 0)
			v.focusNext(t.Context())
			if v.Focus.Index() != 1 {
				t.Fatal("next")
			}
			v.focusPrev(t.Context())
			if v.Focus.Index() != 0 {
				t.Fatal("prev")
			}
			v.clear(t.Context())
			v.focusNext(t.Context())
			v.focusPrev(t.Context())
			if v.Focus.Index() != -1 {
				t.Fatal("empty focus")
			}
		}},
		"test_duplicate": {func(t *testing.T, v *View) {
			fs := []flow.Flow{fixture("GET", 0), fixture("GET", 0)}
			v.Add(t.Context(), fs)
			if err := v.duplicate(t.Context(), fs); err != nil {
				t.Fatal(err)
			}
			if v.Len() != 4 || v.Focus.Index() != 2 {
				t.Fatal("duplicate focus")
			}
		}},
		"test_remove": {func(t *testing.T, v *View) {
			fs := []flow.Flow{fixture("GET", 0), fixture("GET", 0)}
			v.Add(t.Context(), fs)
			must(t, v.remove(t.Context(), fs))
			if v.Len() != 0 || v.StoreCount() != 0 {
				t.Fatal("remove")
			}
		}},
		"test_setgetval": {func(t *testing.T, v *View) {
			f := fixture("GET", 0)
			fs := []flow.Flow{f}
			v.Add(t.Context(), fs)
			must(t, v.setValue(t.Context(), fs, "key", "value"))
			got, err := v.getValue(t.Context(), f, "key", "default")
			if err != nil || got != "value" {
				t.Fatal(got, err)
			}
			got, _ = v.getValue(t.Context(), f, "unknown", "default")
			if got != "default" {
				t.Fatal(got)
			}
			for _, key := range []string{"key", "custom_setting"} {
				must(t, v.setValue(t.Context(), fs, key, "true"))
				for _, want := range []string{"false", "true"} {
					must(t, v.toggleValue(t.Context(), fs, key))
					got, _ = v.getValue(t.Context(), f, key, "default")
					if got != want {
						t.Fatal(got)
					}
				}
			}
		}},
		"test_order": {func(t *testing.T, v *View) {
			v.Add(t.Context(), []flow.Flow{fixture("GET", 1), fixture("PUT", 2), fixture("GET", 3), fixture("PUT", 4)})
			if err := v.setOrder(t.Context(), "method"); err != nil {
				t.Fatal(err)
			}
			if v.getOrder(t.Context()) != "method" {
				t.Fatal("order")
			}
			v.setReversed(t.Context(), true)
			must(t, v.setOrder(t.Context(), "time"))
			var got []float64
			for _, f := range v.Flows() {
				got = append(got, f.Common().TimestampCreated)
			}
			if diff := cmp.Diff([]float64{4, 3, 2, 1}, got); diff != "" {
				t.Fatal(diff)
			}
			v.setReversed(t.Context(), false)
			if err := v.setOrder(t.Context(), "not_an_order"); err == nil {
				t.Fatal("invalid order")
			}
		}},
		"test_reversed": {func(t *testing.T, v *View) {
			for _, start := range []float64{1, 2, 3} {
				v.Add(t.Context(), []flow.Flow{fixture("GET", start)})
			}
			v.setReversed(t.Context(), true)
			for index, want := range map[int]float64{0: 3, -1: 1, 2: 1} {
				f, err := v.At(index)
				if err != nil || f.Common().TimestampCreated != want {
					t.Fatal(index, f, err)
				}
			}
			for _, index := range []int{5, -5} {
				if _, err := v.At(index); err == nil {
					t.Fatal("index accepted")
				}
			}
			if v.bisect(v.Flows()[0]) != 1 || v.bisect(v.Flows()[2]) != 3 {
				t.Fatal("bisect")
			}
		}},
		"test_update": {func(t *testing.T, v *View) {
			must(t, v.setFilterCommand(t.Context(), "~m get"))
			f := fixture("GET", 0)
			v.Add(t.Context(), []flow.Flow{f})
			f.Request.Method = "PUT"
			must(t, v.Update(t.Context(), []flow.Flow{f}))
			if v.Contains(f) {
				t.Fatal("filter removal")
			}
			f.Request.Method = "GET"
			must(t, v.Update(t.Context(), []flow.Flow{f}))
			must(t, v.Update(t.Context(), []flow.Flow{f}))
			if !v.Contains(f) {
				t.Fatal("filter addition")
			}
			must(t, v.Update(t.Context(), []flow.Flow{fixture("GET", 0)}))
			if v.StoreCount() != 1 {
				t.Fatal("unknown update")
			}
		}},
		"test_signals": {func(t *testing.T, v *View) {
			events, cancel := v.Subscribe(100)
			defer cancel()
			f := fixture("GET", 0)
			v.Add(t.Context(), []flow.Flow{f})
			drain := func() []string {
				var kinds []string
				for len(events) > 0 {
					e := <-events
					if strings.HasPrefix(e.Kind, "view_") {
						kinds = append(kinds, e.Kind)
					}
				}
				return kinds
			}
			if diff := cmp.Diff([]string{"view_add"}, drain()); diff != "" {
				t.Fatal(diff)
			}
			must(t, v.setFilterCommand(t.Context(), "~m put"))
			if diff := cmp.Diff([]string{"view_refresh"}, drain()); diff != "" {
				t.Fatal(diff)
			}
			must(t, v.setFilterCommand(t.Context(), "~m get"))
			drain()
			f.Request.Method = "PUT"
			must(t, v.Update(t.Context(), []flow.Flow{f}))
			if diff := cmp.Diff([]string{"view_remove"}, drain()); diff != "" {
				t.Fatal(diff)
			}
			must(t, v.setFilterCommand(t.Context(), "~m put"))
			drain()
			must(t, v.Update(t.Context(), []flow.Flow{f}))
			if diff := cmp.Diff([]string{"view_update"}, drain()); diff != "" {
				t.Fatal(diff)
			}
			must(t, v.setFilterCommand(t.Context(), "~m get"))
			drain()
			must(t, v.Update(t.Context(), []flow.Flow{f}))
			if len(drain()) != 0 {
				t.Fatal("hidden update signalled")
			}
		}},
		"test_focus_follow": {func(t *testing.T, v *View) {
			v.follow = true
			must(t, v.setFilterCommand(t.Context(), "~m get"))
			for _, start := range []float64{5, 4, 7} {
				f := fixture("GET", start)
				v.Add(t.Context(), []flow.Flow{f})
				if v.Focus.Flow() != f {
					t.Fatal("follow")
				}
			}
			f := fixture("PUT", 6)
			v.Add(t.Context(), []flow.Flow{f})
			if v.Focus.Flow().Common().TimestampCreated != 7 {
				t.Fatal("hidden follow")
			}
			f.Request.Method = "GET"
			must(t, v.Update(t.Context(), []flow.Flow{f}))
			if v.Focus.Flow() != f || v.Focus.Index() != 2 {
				t.Fatal("update follow")
			}
		}},
		"test_focus": {func(t *testing.T, v *View) {
			if v.Focus.Flow() != nil || v.Focus.Index() != -1 {
				t.Fatal("initial focus")
			}
			f := fixture("GET", 1)
			v.Add(t.Context(), []flow.Flow{f})
			if v.Focus.Flow() != f {
				t.Fatal("first focus")
			}
			if err := v.Focus.Set(fixture("GET", 0)); err == nil {
				t.Fatal("invalid focus")
			}
			if err := v.Focus.SetIndex(99); err == nil {
				t.Fatal("invalid index")
			}
			v.Add(t.Context(), []flow.Flow{fixture("GET", 0), fixture("GET", 2)})
			if v.Focus.Index() != 1 {
				t.Fatal("retained focus")
			}
			must(t, v.Focus.SetIndex(0))
			must(t, v.Focus.SetIndex(1))
			must(t, v.remove(t.Context(), []flow.Flow{v.Focus.Flow()}))
			if v.Focus.Index() != 1 {
				t.Fatal("successor focus")
			}
			must(t, v.remove(t.Context(), []flow.Flow{v.Focus.Flow()}))
			if v.Focus.Index() != 0 {
				t.Fatal("previous focus")
			}
			must(t, v.remove(t.Context(), v.Flows()))
			if v.Focus.Flow() != nil {
				t.Fatal("empty focus")
			}
		}},
		"test_settings": {func(t *testing.T, v *View) {
			f := fixture("GET", 0)
			if _, err := v.Settings.Values(f); err == nil {
				t.Fatal("unknown settings")
			}
			v.Add(t.Context(), []flow.Flow{f})
			values, _ := v.Settings.Values(f)
			values["foo"] = "bar"
			if len(v.Settings.IDs()) != 1 {
				t.Fatal("settings IDs")
			}
			must(t, v.remove(t.Context(), []flow.Flow{f}))
			if len(v.Settings.IDs()) != 0 {
				t.Fatal("expired settings")
			}
			v.Add(t.Context(), []flow.Flow{f})
			values, _ = v.Settings.Values(f)
			values["foo"] = "bar"
			v.clear(t.Context())
			if len(v.Settings.IDs()) != 0 {
				t.Fatal("cleared settings")
			}
		}},
		"test_properties": {func(t *testing.T, v *View) {
			v.Add(t.Context(), []flow.Flow{fixture("GET", 0)})
			if v.getLength(t.Context()) != 1 || v.getMarked(t.Context()) {
				t.Fatal("properties")
			}
			v.toggleMarked(t.Context())
			if v.getLength(t.Context()) != 0 || !v.getMarked(t.Context()) {
				t.Fatal("marked properties")
			}
		}},
		"test_configure": {func(t *testing.T, _ *View) {
			m := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{})
			defer m.Close()
			v := New(m)
			if err := m.Add(t.Context(), v); err != nil {
				t.Fatal(err)
			}
			for _, spec := range []string{"view_filter=~q", "view_order=method", "view_order_reversed=true", "console_focus_follow=true"} {
				if err := m.Options().Set(t.Context(), spec); err != nil {
					t.Fatal(err)
				}
			}
			for _, spec := range []string{"view_filter=~~", "view_order=no"} {
				if err := m.Options().Set(t.Context(), spec); err == nil {
					t.Fatal("invalid configure accepted")
				}
			}
			if !v.follow || !v.reversed || v.order != "method" {
				t.Fatal("configured fields")
			}
		}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) { tt.run(t, New(nil)) })
	}
}

func equalFlows(t *testing.T, want, got []flow.Flow) {
	t.Helper()
	ids := func(fs []flow.Flow) []string {
		result := make([]string, 0, len(fs))
		for _, f := range fs {
			result = append(result, f.Common().ID)
		}
		return result
	}
	if diff := cmp.Diff(ids(want), ids(got)); diff != "" {
		t.Fatal(diff)
	}
}

func checkKey(t *testing.T, f flow.Flow, start float64, method, url string, size int) {
	t.Helper()
	if generate("time", f).number != start || generate("method", f).text != method || generate("url", f).text != url || generate("size", f).number != float64(size) {
		t.Fatalf("keys: time=%v method=%v url=%v size=%v", generate("time", f), generate("method", f), generate("url", f), generate("size", f))
	}
}

func TestDispatchSubscriptions(t *testing.T) {
	inDispatch := false
	m := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{OnDispatchStart: func() { inDispatch = true }, OnDispatchEnd: func() { inDispatch = false }})
	defer m.Close()
	v := New(m)
	if err := m.Add(t.Context(), v); err != nil {
		t.Fatal(err)
	}
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		slow, _ := v.Subscribe(1)
		fast, cancel := v.Subscribe(10)
		defer cancel()
		v.Add(ctx, []flow.Flow{fixture("GET", 0)})
		if !inDispatch {
			t.Fatal("not in dispatch")
		}
		for len(fast) > 0 {
			<-fast
		}
		if len(v.subscribers) != 1 {
			t.Fatal("overflowing subscriber retained")
		}
		if _, ok := <-slow; !ok {
			t.Fatal("queued event discarded")
		}
		if _, ok := <-slow; ok {
			t.Fatal("slow channel not closed")
		}
		v.Add(ctx, []flow.Flow{fixture("GET", 1)})
		if len(fast) == 0 {
			t.Fatal("healthy subscriber lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			f := fixture("GET", 0)
			if err := m.Do(t.Context(), func(ctx context.Context) error { v.Add(ctx, []flow.Flow{f}); return nil }); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if err := m.Do(t.Context(), func(context.Context) error {
		if v.StoreCount() != 52 {
			t.Fatal(v.StoreCount())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
