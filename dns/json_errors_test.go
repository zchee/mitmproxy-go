// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/omap"
)

func TestJSONErrors(t *testing.T) {
	tests := map[string]struct {
		mutate func(*omap.Map[any])
	}{
		"missing id":          {mutate: func(m *omap.Map[any]) { m.Delete("id") }},
		"bad opcode":          {mutate: func(m *omap.Map[any]) { m.Set("op_code", "BOGUS") }},
		"questions not list":  {mutate: func(m *omap.Map[any]) { m.Set("questions", true) }},
		"question not object": {mutate: func(m *omap.Map[any]) { m.Set("questions", []any{false}) }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			value := tDNSResp().ToJSON()
			tt.mutate(value)
			before := state.CopyMap(value)
			got, err := MessageFromJSON(value)
			if err == nil || got != nil {
				t.Fatalf("MessageFromJSON = %+v, %v; want nil and error", got, err)
			}
			if diff := gocmp.Diff(before, value); diff != "" {
				t.Fatalf("failed decode changed input:\n%s", diff)
			}
		})
	}
	if got, err := MessageFromJSON(nil); err == nil || got != nil {
		t.Fatalf("nil JSON = %+v, %v", got, err)
	}
}

func TestJSONZeroTimestampAndReserved(t *testing.T) {
	message := tDNSReq()
	message.Timestamp = new(0.0)
	message.Reserved = 7
	value := message.ToJSON()
	if value.Has("timestamp") || value.Has("reserved") {
		t.Fatal("false timestamp or reserved bits exposed in JSON")
	}
	got, err := MessageFromJSON(value)
	if err != nil || got.Timestamp != nil || got.Reserved != 0 {
		t.Fatalf("zero timestamp/reserved = %+v, %v", got, err)
	}
}
