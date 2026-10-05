// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package view

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func fixture(method string, start float64) *flow.HTTPFlow {
	f := testflow.TFlow()
	f.Request.Method = method
	f.TimestampCreated = start
	return f
}

func TestOrderAndReversed(t *testing.T) {
	tests := map[string]struct {
		order    string
		reversed bool
		want     []float64
	}{
		"time":               {"time", false, []float64{1, 2, 3, 4}},
		"method":             {"method", false, []float64{1, 3, 2, 4}},
		"reverse equal keys": {"method", true, []float64{4, 2, 3, 1}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			v := New(nil)
			v.Add(t.Context(), []flow.Flow{fixture("GET", 1), fixture("PUT", 2), fixture("GET", 3), fixture("PUT", 4)})
			if err := v.setOrder(t.Context(), tt.order); err != nil {
				t.Fatal(err)
			}
			v.setReversed(t.Context(), tt.reversed)
			var got []float64
			for _, f := range v.Flows() {
				got = append(got, f.Common().TimestampCreated)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestFilterFocusAndSettings(t *testing.T) {
	v := New(nil)
	fs := []flow.Flow{fixture("GET", 0), fixture("GET", 1), fixture("PUT", 2), fixture("GET", 3)}
	v.Add(t.Context(), fs)
	if err := v.Focus.Set(fs[2]); err != nil {
		t.Fatal(err)
	}
	if err := v.setFilterCommand(t.Context(), "~m get"); err != nil {
		t.Fatal(err)
	}
	if got := v.Focus.Flow(); got != fs[3] {
		t.Fatalf("nearest focus: %v", got)
	}
	if _, err := v.Settings.Values(fixture("GET", 0)); err == nil {
		t.Fatal("settings admitted unknown flow")
	}
	values, err := v.Settings.Values(fs[0])
	if err != nil {
		t.Fatal(err)
	}
	values["foo"] = "bar"
	must(t, v.remove(t.Context(), []flow.Flow{fs[0]}))
	if _, err := v.Settings.Values(fs[0]); err == nil {
		t.Fatal("removed settings retained")
	}
	if err := v.setFilterCommand(t.Context(), "~m oink"); err != nil {
		t.Fatal(err)
	}
	if v.Focus.Flow() != nil {
		t.Fatal("focus on hidden flow")
	}
}

func TestNotificationsNeverBlock(t *testing.T) {
	v := New(nil)
	events, _ := v.Subscribe(1)
	v.Add(t.Context(), []flow.Flow{fixture("GET", 0), fixture("GET", 1)})
	count := 0
	for range events {
		count++
	}
	if count != 1 {
		t.Fatalf("queued events=%d", count)
	}
}
