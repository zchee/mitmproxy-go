// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowlist

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
	"github.com/zchee/mitmproxy-go/options"
)

func TestConsoleFlowList(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"virtualized":       {testVirtualized},
			"layout_default":    {testLayoutDefault},
			"layout_table":      {testLayoutTable},
			"layout_list":       {testLayoutList},
			"follow_focus":      {testFollowFocus},
			"order_filter_mark": {testOrderFilterMark},
		}
		for name, test := range tests {
			t.Run(name, test.run)
		}
	})
}

func sampleFlows(count int) []flow.Flow {
	flows := make([]flow.Flow, count)
	for index := range flows {
		f := testflow.TFlow(testflow.WithResponse)
		f.ID = fmt.Sprintf("flow-%05d", index)
		f.Request.Path = fmt.Sprintf("/row/%d", index)
		f.TimestampCreated = float64(index)
		flows[index] = f
	}
	return flows
}

func requestFor(flows []flow.Flow, index, width, height int, layout string) contract.ProjectionRequest {
	request := contract.ProjectionRequest{Viewport: contract.Viewport{Offset: index, Width: width, Height: height}, Layout: layout, FocusIndex: index}
	if index >= 0 && index < len(flows) {
		request.FocusID = flows[index].Common().ID
	}
	return request
}

func testVirtualized(t *testing.T) {
	flows := sampleFlows(10000)
	request := requestFor(flows, 8765, 200, 12, "table")
	calls := 0
	projection := project(flows, request, func(f flow.Flow, r contract.ProjectionRequest, focused bool) contract.Row {
		calls++
		return formatRow(f, r, focused)
	})
	if calls != 12 || len(projection.Rows) != 12 || projection.Total != 10000 || len(projection.IDs) != 10000 {
		t.Fatalf("projection calls=%d visible=%d total=%d IDs=%d", calls, len(projection.Rows), projection.Total, len(projection.IDs))
	}
	if projection.FirstIndex != 8765 || projection.Rows[0].ID != "flow-08765" || projection.Rows[11].ID != "flow-08776" {
		t.Fatalf("deep viewport: %+v", projection)
	}
	f := flows[8765].(*flow.HTTPFlow)
	before := projection.Rows[0]
	f.Request.Path, f.Request.Host = "/changed", "changed.test"
	f.Response.RawContent = []byte("changed body")
	if diff := cmp.Diff(before, projection.Rows[0]); diff != "" {
		t.Fatalf("borrowed flow retained: %s", diff)
	}
	host := &recordingHost{}
	model := New(t.Context(), host)
	model.Resize(200, 12)
	model.SetSnapshot(contract.Snapshot{Rows: projection.Rows, IDs: projection.IDs, Total: projection.Total, FirstIndex: projection.FirstIndex, FocusIndex: projection.FocusIndex, Control: contract.NewState()})
	if len(model.rows) != 12 || model.rows[0].index != 8765 {
		t.Fatalf("deep row hit map: %+v", model.rows)
	}
	cmd, consumed := model.Update(tea.MouseClickMsg{X: 5, Y: 7, Button: tea.MouseLeft})
	if !consumed || cmd == nil {
		t.Fatal("deep click did not select visible row")
	}
	if index, ok := model.hit(5, 7); !ok || index != 8772 {
		t.Fatalf("deep click selected index %d, want 8772", index)
	}
	if host.viewports[0].Width != 200 || host.viewports[0].Height != 12 {
		t.Fatal("resize did not request physical viewport")
	}
	request.Viewport.Height = 0
	if got := Project(flows, request); len(got.Rows) != 0 || got.Total != 10000 {
		t.Fatal("zero-height projection formatted rows")
	}
}

func testLayoutDefault(t *testing.T) {
	flows := sampleFlows(12)
	for width, want := range map[int]int{80: 3, 99: 3, 100: 6, 200: 6} {
		got := Project(flows, requestFor(flows, 0, width, 6, "default"))
		if len(got.Rows) != want {
			t.Fatalf("width %d visible=%d, want %d", width, len(got.Rows), want)
		}
		lines := strings.Split(got.Rows[0].Text, "\n")
		wantLines := 1
		if width < 100 {
			wantLines = 2
		}
		if len(lines) != wantLines {
			t.Fatalf("width %d line count=%d, want %d", width, len(lines), wantLines)
		}
	}
}

func testLayoutTable(t *testing.T) {
	flows := []flow.Flow{testflow.TFlow(testflow.WithResponse), testflow.TWebSocketFlow(), testflow.TTCPFlow(), testflow.TUDPFlow(), testflow.TDNSFlow(testflow.WithResponse)}
	flows[0].(*flow.HTTPFlow).Request.Path = "/ＦＵＬＬ－ＷＩＤＴＨ/" + strings.Repeat("wide", 50)
	for _, actualWidth := range []int{60, 200} {
		got := Project(flows, requestFor(flows, 0, actualWidth, 10, "table"))
		if len(got.Rows) != len(flows) {
			t.Fatalf("table omitted protocol rows: %d", len(got.Rows))
		}
		for _, row := range got.Rows {
			if strings.Contains(row.Text, "\n") {
				t.Fatalf("table row wrapped: %q", row.Text)
			}
			if style.Width(row.Text) > actualWidth {
				t.Fatalf("table row exceeds width %d: %q", actualWidth, row.Text)
			}
		}
	}
}

func testLayoutList(t *testing.T) {
	flows := []flow.Flow{testflow.TFlow(testflow.WithResponse), testflow.TTCPFlow(), testflow.TUDPFlow(), testflow.TDNSFlow()}
	got := Project(flows, requestFor(flows, 0, 200, 5, "list"))
	if len(got.Rows) != 4 || len(strings.Split(got.Rows[0].Text, "\n")) != 2 {
		t.Fatal("wide list override or mixed physical heights lost")
	}
	host := &recordingHost{}
	model := New(t.Context(), host)
	model.Resize(200, 5)
	model.SetSnapshot(contract.Snapshot{Rows: got.Rows, Total: got.Total, FirstIndex: got.FirstIndex, FocusIndex: got.FocusIndex, Control: contract.NewState()})
	if diff := cmp.Diff([]visibleRow{{index: 0, first: 0, height: 2}, {index: 1, first: 2, height: 1}, {index: 2, first: 3, height: 1}, {index: 3, first: 4, height: 1}}, model.rows); diff != "" {
		t.Fatalf("physical hit map (-want +got): %s", diff)
	}
	for y, want := range map[int]int{0: 0, 1: 0, 2: 1, 4: 3} {
		cmd, consumed := model.Update(tea.MouseClickMsg{X: 1, Y: y, Button: tea.MouseLeft})
		if !consumed || cmd == nil {
			t.Fatalf("mouse row %d not handled", y)
		}
		if row, ok := model.hit(1, y); !ok || row != want {
			t.Fatalf("mouse row %d selected %d, want %d", y, row, want)
		}
	}
	state := contract.NewState()
	state.Mouse = false
	model.SetSnapshot(contract.Snapshot{Rows: got.Rows, Total: got.Total, Control: state})
	if _, consumed := model.Update(tea.MouseClickMsg{X: 1, Y: 1, Button: tea.MouseLeft}); consumed {
		t.Fatal("disabled mouse intercepted click")
	}
}

func setupView(t *testing.T) (*view.View, *addon.Manager) {
	t.Helper()
	manager := addon.NewManager(options.NewManager(), command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	v := view.New(manager)
	if err := manager.Add(t.Context(), v); err != nil {
		t.Fatal(err)
	}
	return v, manager
}

func snapshotView(t *testing.T, v *view.View, manager *addon.Manager, request contract.ProjectionRequest) contract.Projection {
	t.Helper()
	var result contract.Projection
	if err := manager.Do(t.Context(), func(context.Context) error {
		request.FocusIndex = v.Focus.Index()
		request.FocusID = ""
		if f := v.Focus.Flow(); f != nil {
			request.FocusID = f.Common().ID
		}
		result = Project(v.Flows(), request)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func testFollowFocus(t *testing.T) {
	v, manager := setupView(t)
	flows := sampleFlows(30)
	if err := manager.Options().Update(t.Context(), map[string]any{"console_focus_follow": true}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Do(t.Context(), func(ctx context.Context) error { v.Add(ctx, flows); return nil }); err != nil {
		t.Fatal(err)
	}
	request := requestFor(flows, 0, 80, 6, "list")
	got := snapshotView(t, v, manager, request)
	if got.FocusIndex != 29 || got.FirstIndex != 27 {
		t.Fatalf("follow did not expose last flow: first=%d focus=%d", got.FirstIndex, got.FocusIndex)
	}
	if err := manager.Options().Update(t.Context(), map[string]any{"console_focus_follow": false}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Do(t.Context(), func(ctx context.Context) error {
		_, err := manager.Commands().Call(ctx, "view.focus.go", 1)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	request.Viewport.Offset = 27
	got = snapshotView(t, v, manager, request)
	if got.FirstIndex != 1 || got.FocusIndex != 1 {
		t.Fatal("backward focus remained outside viewport")
	}
	if err := manager.Do(t.Context(), func(ctx context.Context) error {
		_, err := manager.Commands().Call(ctx, "view.flows.remove", []flow.Flow{flows[1]})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got = snapshotView(t, v, manager, request)
	if got.FocusID == flows[1].Common().ID || got.FocusIndex < got.FirstIndex {
		t.Fatal("removed focus retained")
	}
}

func testOrderFilterMark(t *testing.T) {
	v, manager := setupView(t)
	flows := sampleFlows(4)
	flows[1].Common().Marked = ":smile:"
	flows[3].Common().Marked = "*"
	if err := manager.Do(t.Context(), func(ctx context.Context) error { v.Add(ctx, flows); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := manager.Options().Update(t.Context(), map[string]any{"view_order_reversed": true, "view_filter": new("~u /row/[13]$")}); err != nil {
		t.Fatal(err)
	}
	request := requestFor(flows, 0, 200, 10, "table")
	got := snapshotView(t, v, manager, request)
	if diff := cmp.Diff([]string{flows[3].Common().ID, flows[1].Common().ID}, got.IDs); diff != "" {
		t.Fatalf("existing order/filter (-want +got): %s", diff)
	}
	if got.Rows[0].Marked != "*" || got.Rows[1].Marked != ":smile:" {
		t.Fatal("mark projection lost")
	}
	if err := manager.Options().Update(t.Context(), map[string]any{"view_filter": (*string)(nil)}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Do(t.Context(), func(ctx context.Context) error {
		_, err := manager.Commands().Call(ctx, "view.properties.marked.toggle")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got = snapshotView(t, v, manager, request)
	if diff := cmp.Diff([]string{flows[3].Common().ID, flows[1].Common().ID}, got.IDs); diff != "" {
		t.Fatalf("marked-only view (-want +got): %s", diff)
	}
	if err := manager.Options().Update(t.Context(), map[string]any{"view_order": "url", "view_order_reversed": false}); err != nil {
		t.Fatal(err)
	}
	got = snapshotView(t, v, manager, request)
	if !slices.IsSorted(got.IDs) {
		t.Fatal("existing ordering was not consumed")
	}
}

type recordingHost struct {
	contract.Host
	viewports []contract.Viewport
}

func (h *recordingHost) RequestViewport(viewport contract.Viewport) {
	h.viewports = append(h.viewports, viewport)
}
