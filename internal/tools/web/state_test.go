// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"log/slog"
	"maps"
	"os"
	"runtime"
	"slices"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/internal/local"
	"github.com/zchee/mitmproxy-go/internal/version"
)

func testWebState(t *testing.T) {
	tests := map[string]struct{ start bool }{"shape": {}, "actual_listener": {start: true}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h := newRouteHarness(t)
			if test.start {
				h.do(t, func(ctx context.Context) error {
					return h.app.master.Options.Update(ctx, map[string]any{"mode": []string{"regular@127.0.0.1:0"}})
				})
				if err := h.app.proxyserver.SetupServers(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			var body map[string]jsontext.Value
			if err := json.Unmarshal(h.status(t, "GET", "/state.json", nil, "", 200), &body); err != nil {
				t.Fatal(err)
			}
			wantKeys := []string{"contentViews", "localModeUnavailable", "platform", "servers", "version"}
			if diff := gocmp.Diff(wantKeys, slices.Sorted(maps.Keys(body))); diff != "" {
				t.Fatal(diff)
			}
			var reportedVersion, platform string
			if err := json.Unmarshal(body["version"], &reportedVersion); err != nil {
				t.Fatal(err)
			}
			if reportedVersion != version.Version {
				t.Fatalf("version=%q", reportedVersion)
			}
			if err := json.Unmarshal(body["platform"], &platform); err != nil {
				t.Fatal(err)
			}
			wantPlatform := runtime.GOOS
			if wantPlatform == "windows" {
				wantPlatform = "win32"
			}
			if platform != wantPlatform {
				t.Fatalf("platform=%q want=%q", platform, wantPlatform)
			}
			var views []string
			if err := json.Unmarshal(body["contentViews"], &views); err != nil {
				t.Fatal(err)
			}
			wantViews := slices.DeleteFunc(contentviews.DefaultRegistry.AvailableViews(), func(name string) bool { return name == "query" })
			if diff := gocmp.Diff(wantViews, views); diff != "" {
				t.Fatal(diff)
			}
			var unavailable any
			if err := json.Unmarshal(body["localModeUnavailable"], &unavailable); err != nil {
				t.Fatal(err)
			}
			var wantUnavailable any
			if runtime.GOOS == "linux" && os.Geteuid() != 0 {
				wantUnavailable = "mitmproxy is not running as root."
			} else if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
				wantUnavailable = "Local redirect mode is not supported on " + runtime.GOOS
			}
			if diff := gocmp.Diff(wantUnavailable, unavailable); diff != "" {
				t.Fatal(diff)
			}
			var servers map[string]jsontext.Value
			if err := json.Unmarshal(body["servers"], &servers); err != nil {
				t.Fatal("invalid server JSON")
			}
			snapshot := h.app.proxyserver.ServerSnapshot()
			expected, err := json.Marshal(snapshot.Servers, json.Deterministic(true))
			if err != nil {
				t.Fatal("could not encode server snapshot")
			}
			actual, err := json.Marshal(servers, json.Deterministic(true))
			if err != nil || !bytes.Equal(expected, actual) {
				t.Fatal("HTTP state differs from the coherent server publication")
			}
			if !test.start {
				if len(servers) != 0 {
					t.Fatal("desired but unstarted listener was presented as running")
				}
				return
			}
			addresses := h.app.proxyserver.ListenAddrs()
			if len(addresses) != 1 || addresses[0].Port == 0 || len(servers) != 1 {
				t.Fatal("actual owned listener tuple missing")
			}
			var value struct {
				Running bool    `json:"is_running"`
				Listen  [][]any `json:"listen_addrs"`
			}
			if err := json.Unmarshal(servers["regular@127.0.0.1:0"], &value); err != nil {
				t.Fatal("invalid regular listener presentation")
			}
			if !value.Running {
				t.Fatal("bound listener not marked running")
			}
			want := [][]any{{addresses[0].Host, float64(addresses[0].Port)}}
			if diff := gocmp.Diff(want, value.Listen); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func testWebLocalPolicy(t *testing.T) {
	tests := map[string]struct {
		platform string
		uid      int
		want     string
	}{
		"linux_root":    {platform: "linux"},
		"linux_nonroot": {platform: "linux", uid: 1000, want: "mitmproxy is not running as root."},
		"darwin":        {platform: "darwin", uid: 501},
		"windows":       {platform: "windows", uid: -1},
		"freebsd":       {platform: "freebsd", uid: 1000, want: "Local redirect mode is not supported on freebsd"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(test.want, local.UnavailableReason(test.platform, test.uid)); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

type testEvent struct {
	ID      uint64 `json:"id"`
	Message string `json:"message"`
	Level   string `json:"level"`
}

func testWebEventIDs(t *testing.T) {
	h := newRouteHarness(t, 2)
	var observed []uint64
	h.do(t, func(context.Context) error {
		h.app.events.Observe(func(event eventstore.Event) {
			if event.Kind == "add" {
				observed = append(observed, event.ID)
			}
		})
		return nil
	})
	h.do(t, func(ctx context.Context) error {
		for range 2 {
			if err := h.app.events.Add(ctx, addon.LogEntry{Msg: "identical entry", Level: slog.LevelInfo}); err != nil {
				return err
			}
		}
		return nil
	})
	var before []testEvent
	if err := json.Unmarshal(h.status(t, "GET", "/events", nil, "", 200), &before); err != nil {
		t.Fatal(err)
	}
	if len(before) != 2 || before[0].ID == before[1].ID || before[0].ID <= 1 {
		t.Fatal("duplicate entries reused identity or eviction was not reflected")
	}
	if diff := gocmp.Diff(observed, []uint64{before[0].ID, before[1].ID}); diff != "" {
		t.Fatal(diff)
	}
	var repeated []testEvent
	if err := json.Unmarshal(h.status(t, "GET", "/events.json", nil, "", 200), &repeated); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(before, repeated); diff != "" {
		t.Fatal(diff)
	}
	h.status(t, "POST", "/clear", nil, "", 200)
	h.do(t, func(ctx context.Context) error {
		return h.app.events.Add(ctx, addon.LogEntry{Msg: "after clear", Level: slog.LevelInfo})
	})
	var after []testEvent
	if err := json.Unmarshal(h.status(t, "GET", "/events", nil, "", 200), &after); err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].ID <= before[1].ID {
		t.Fatal("clear reset or reused the event identity")
	}
	h.do(t, func(context.Context) error {
		if after[0].ID != h.app.events.Records()[0].ID {
			t.Fatal("HTTP event identity differs from Records")
		}
		return nil
	})
}
