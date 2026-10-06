// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestDataSnapshot(t *testing.T) {
	tests := map[string]struct {
		data *Data
		want *Data
	}{
		"nil":                    {},
		"open empty":             {data: &Data{}, want: &Data{}},
		"nil newest message":     {data: &Data{Messages: []*Message{{Content: []byte("older")}, nil}}, want: &Data{}},
		"nil historical message": {data: &Data{Messages: []*Message{nil, {Content: []byte("latest")}}}, want: &Data{Messages: []*Message{{Content: []byte("latest")}}}},
		"terminal with newest message": {
			data: &Data{
				Messages:       []*Message{{Content: []byte("older")}, {Type: OpBinary, FromClient: true, Content: []byte("newest"), Timestamp: 123, Dropped: true, Injected: true}},
				ClosedByClient: new(false), CloseCode: new(1000), CloseReason: new("complete"), TimestampEnd: new(456.0),
			},
			want: &Data{
				Messages:       []*Message{{Type: OpBinary, FromClient: true, Content: []byte("newest"), Timestamp: 123, Dropped: true, Injected: true}},
				ClosedByClient: new(false), CloseCode: new(1000), CloseReason: new("complete"), TimestampEnd: new(456.0),
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := tt.data.Snapshot()
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("Snapshot (-want +got):\n%s", diff)
			}
			if got == nil || got.TimestampEnd == nil {
				return
			}
			*tt.data.ClosedByClient = true
			*tt.data.CloseCode = 1001
			*tt.data.CloseReason = "changed"
			*tt.data.TimestampEnd = 999
			tt.data.Messages[len(tt.data.Messages)-1].Content[0] = 'X'
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("snapshot changed with original (-want +got):\n%s", diff)
			}
		})
	}
}
