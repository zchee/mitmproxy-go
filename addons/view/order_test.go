// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package view

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
)

func TestAllOrderingTies(t *testing.T) {
	tests := map[string]struct {
		order   string
		reverse bool
	}{
		"time": {"time", false}, "time reversed": {"time", true},
		"method": {"method", false}, "method reversed": {"method", true},
		"url": {"url", false}, "url reversed": {"url", true},
		"size": {"size", false}, "size reversed": {"size", true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			v := New(nil)
			fs := []flow.Flow{fixture("PUT", 0), fixture("GET", 0), fixture("PUT", 0), fixture("GET", 0)}
			for i, f := range fs {
				h := f.(*flow.HTTPFlow)
				if i%2 == 0 {
					h.Request.Path = "/b"
					h.Request.RawContent = []byte("bb")
				} else {
					h.Request.Path = "/a"
					h.Request.RawContent = []byte("a")
				}
			}
			v.Add(t.Context(), fs)
			must(t, v.setOrder(t.Context(), tt.order))
			v.setReversed(t.Context(), tt.reverse)
			want := []flow.Flow{fs[1], fs[3], fs[0], fs[2]}
			if tt.order == "time" {
				want = fs
			}
			if tt.reverse {
				want = []flow.Flow{want[3], want[2], want[1], want[0]}
			}
			equalFlows(t, want, v.Flows())
			for idx, f := range want {
				if v.Index(f) != idx {
					t.Fatal("wrong index", idx)
				}
				got, err := v.At(idx)
				must(t, err)
				if got != f {
					t.Fatal("wrong indexed flow", idx)
				}
			}
		})
	}
}

func TestDefaultOrderIdentity(t *testing.T) {
	v := New(nil)
	if diff := cmp.Diff("", v.getOrder(t.Context())); diff != "" {
		t.Fatal(diff)
	}
	must(t, v.setOrder(t.Context(), "time"))
	if diff := cmp.Diff("time", v.getOrder(t.Context())); diff != "" {
		t.Fatal(diff)
	}
}
