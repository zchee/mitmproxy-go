// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tcp

import (
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestMessageState(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in      any
		want    *Message
		wantErr string
	}{
		"success: from client": {
			in:   []any{true, []byte("hello"), 946681204.5},
			want: &Message{FromClient: true, Content: []byte("hello"), Timestamp: 946681204.5},
		},
		"success: integer timestamp and empty content": {
			in:   []any{false, []byte(nil), int64(7)},
			want: &Message{FromClient: false, Content: []byte{}, Timestamp: 7},
		},
		"error: wrong arity": {
			in:      []any{true, []byte("x")},
			wantErr: "TCPMessage.set_state: expected a tuple of 3 items, got 2",
		},
		"error: str content": {
			in:      []any{true, "x", 1.0},
			wantErr: "content: expected bytes, got str",
		},
		"error: not a tuple": {
			in:      nil,
			wantErr: "expected list, got NoneType",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := MessageFromState(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("MessageFromState error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("message mismatch (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(tt.want.GetState(), got.GetState()); diff != "" {
				t.Errorf("GetState mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMessageSetStateAndClone(t *testing.T) {
	t.Parallel()

	// Ports the message part of test_tcp.py::TestTCPFlow::test_copy.
	src := &Message{FromClient: true, Content: []byte("hello"), Timestamp: 946681204}
	m := NewMessage(false, []byte("foo"))
	if err := m.SetState(src.GetState()); err != nil {
		t.Fatal(err)
	}
	if m.Timestamp != src.Timestamp || !m.FromClient || string(m.Content) != "hello" {
		t.Errorf("SetState gave %+v", m)
	}
	before := *m
	if err := m.SetState([]any{1}); err == nil {
		t.Error("SetState accepted a malformed tuple")
	}
	if diff := gocmp.Diff(&before, m); diff != "" {
		t.Errorf("failed SetState modified the message:\n%s", diff)
	}
	c := m.Clone()
	c.Content[0] = 'X'
	if m.Content[0] == 'X' {
		t.Error("Clone shares the content buffer")
	}
	if got := src.String(); got != `-> "hello"` {
		t.Errorf("String() = %q", got)
	}
	if got := NewMessage(false, []byte("a")).String(); got != `<- "a"` {
		t.Errorf("String() = %q", got)
	}
}
