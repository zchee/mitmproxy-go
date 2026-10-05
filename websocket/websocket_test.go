// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow/state"
)

// tWebSocket mirrors upstream's mitmproxy.test.tflow.twebsocket.
func tWebSocket() *Data {
	return &Data{
		Messages: []*Message{
			{Type: OpBinary, FromClient: true, Content: []byte("hello binary"), Timestamp: 946681203},
			{Type: OpText, FromClient: true, Content: []byte("hello text"), Timestamp: 946681204},
			{Type: OpText, FromClient: false, Content: []byte("it's me"), Timestamp: 946681205},
		},
		ClosedByClient: new(false),
		CloseCode:      new(1000),
		CloseReason:    new("Close Reason"),
		TimestampEnd:   new(946681205.0),
	}
}

// fixtureState is the websocket attribute of the upstream fixture
// flows/websocket.mitm, in get_state order.
func fixtureState() *state.Map {
	m := state.NewMap(5)
	m.Set("messages", []any{
		[]any{int64(1), false, []byte(`{"error":"Unknown api key"}`), 1693314200.336985, false, false},
	})
	m.Set("closed_by_client", true)
	m.Set("close_code", int64(1005))
	m.Set("close_reason", "")
	m.Set("timestamp_end", 1693314203.128)
	return m
}

func TestDataStateKeyOrder(t *testing.T) {
	t.Parallel()

	want := []string{"messages", "closed_by_client", "close_code", "close_reason", "timestamp_end"}
	for name, d := range map[string]*Data{"success: populated": tWebSocket(), "success: zero": {}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if diff := gocmp.Diff(want, d.GetState().Keys()); diff != "" {
				t.Errorf("key order mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDataStateNone checks that unset optional attributes are written as
// None (an untyped nil), which the flow file codec writes as a tnetstring
// null; a typed nil pointer would not be.
func TestDataStateNone(t *testing.T) {
	t.Parallel()

	s := (&Data{}).GetState()
	for _, key := range []string{"closed_by_client", "close_code", "close_reason", "timestamp_end"} {
		if v, _ := s.Get(key); v != nil {
			t.Errorf("%s state = %#v, want nil", key, v)
		}
	}
	if v, _ := tWebSocket().GetState().Get("close_code"); !gocmp.Equal(v, any(int64(1000))) {
		t.Errorf("close_code state = %#v, want int64(1000)", v)
	}
}

func TestDataFixtureRoundTrip(t *testing.T) {
	t.Parallel()

	in := fixtureState()
	d, err := DataFromState(in)
	if err != nil {
		t.Fatal(err)
	}
	if in.Len() != 0 {
		t.Errorf("DataFromState left keys %v", in.Keys())
	}
	if diff := gocmp.Diff(fixtureState(), d.GetState()); diff != "" {
		t.Errorf("GetState mismatch (-want +got):\n%s", diff)
	}
	if got := d.Messages[0]; got.Type != OpText || got.FromClient || got.Dropped || got.Injected {
		t.Errorf("decoded message = %+v", got)
	}

	// Ports test_websocket.py::TestWebSocketData::test_state.
	ws := tWebSocket()
	back, err := DataFromState(ws.GetState())
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(ws.GetState(), back.GetState()); diff != "" {
		t.Errorf("round trip mismatch (-want +got):\n%s", diff)
	}
	open := &Data{}
	if v, _ := open.GetState().Get("closed_by_client"); v != nil {
		t.Errorf("open connection closed_by_client = %v, want None", v)
	}
}

func TestDataSetStateErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate  func(*state.Map)
		wantErr string
	}{
		"error: unexpected fields": {
			mutate:  func(m *state.Map) { m.Set("extra", nil) },
			wantErr: "unexpected fields in WebSocketData.set_state: [extra]",
		},
		"error: missing field": {
			mutate:  func(m *state.Map) { m.Delete("close_code") },
			wantErr: `missing field "close_code"`,
		},
		"error: invalid opcode": {
			mutate: func(m *state.Map) {
				m.Set("messages", []any{[]any{int64(3), false, []byte{}, 1.0, false, false}})
			},
			wantErr: "3 is not a valid Opcode",
		},
		"error: short message tuple": {
			mutate:  func(m *state.Map) { m.Set("messages", []any{[]any{int64(1), false}}) },
			wantErr: "expected a tuple of 6 items, got 2",
		},
		"error: str close code": {
			mutate:  func(m *state.Map) { m.Set("close_code", "1000") },
			wantErr: `field "close_code": expected int, got str`,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := fixtureState()
			tt.mutate(m)
			d := tWebSocket()
			before := d.GetState()
			err := d.SetState(m)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("SetState error = %v, want it to contain %q", err, tt.wantErr)
			}
			if diff := gocmp.Diff(before, d.GetState()); diff != "" {
				t.Errorf("failed SetState modified the data (-before +after):\n%s", diff)
			}
		})
	}
}

func TestMessage(t *testing.T) {
	t.Parallel()

	// Ports test_websocket.py::TestWebSocketMessage::test_basic.
	m := NewMessage(OpText, true, []byte("foo"))
	if err := m.SetState(m.GetState()); err != nil {
		t.Fatal(err)
	}
	if string(m.Content) != "foo" || m.Dropped {
		t.Errorf("after SetState(GetState()): %+v", m)
	}
	m.Drop()
	if !m.Dropped {
		t.Error("Drop did not mark the message")
	}
	if diff := gocmp.Diff([]any{int64(1), true, []byte("foo"), m.Timestamp, true, false}, m.GetState()); diff != "" {
		t.Errorf("GetState mismatch (-want +got):\n%s", diff)
	}

	// Ports test_text.
	txt := NewMessage(OpText, true, []byte("foo"))
	bin := NewMessage(OpBinary, true, []byte("foo"))
	if got, err := txt.Text(); err != nil || got != "foo" || !txt.IsText() {
		t.Errorf("Text() = (%q, %v)", got, err)
	}
	if err := txt.SetText("bar"); err != nil || string(txt.Content) != "bar" {
		t.Errorf("SetText = %v, content %q", err, txt.Content)
	}
	const wantErr = "Binary WebSocket frames do not have a 'text' attribute"
	if _, err := bin.Text(); err == nil || err.Error() != wantErr {
		t.Errorf("binary Text() error = %v", err)
	}
	if err := bin.SetText("bar"); err == nil || err.Error() != wantErr {
		t.Errorf("binary SetText error = %v", err)
	}
	if bin.IsText() {
		t.Error("binary message reports IsText")
	}
	if _, err := NewMessage(OpText, true, []byte{0xff}).Text(); err == nil {
		t.Error("Text() accepted invalid UTF-8")
	}
	c := txt.Clone()
	c.Content[0] = 'X'
	if txt.Content[0] == 'X' {
		t.Error("Clone shares the content buffer")
	}
}

func TestFormatting(t *testing.T) {
	t.Parallel()

	// Ports test_formatting and test_message_formatting.
	d := tWebSocket()
	want := "[OUTGOING] hello binary\n[OUTGOING] hello text\n[INCOMING] it's me"
	if got := string(d.FormattedMessages()); got != want {
		t.Errorf("FormattedMessages() = %q, want %q", got, want)
	}
	if got := d.String(); got != "<WebSocketData (3 messages)>" {
		t.Errorf("String() = %q", got)
	}
	if got := OpPong.String(); got != "PONG" {
		t.Errorf("OpPong.String() = %q", got)
	}
	if got := Opcode(3).String(); got != "Opcode(3)" {
		t.Errorf("Opcode(3).String() = %q", got)
	}
}

func TestDataClone(t *testing.T) {
	t.Parallel()

	d := tWebSocket()
	c := d.Clone()
	if diff := gocmp.Diff(d.GetState(), c.GetState()); diff != "" {
		t.Fatalf("clone differs:\n%s", diff)
	}
	c.Messages[0].Content[0] = 'X'
	*c.CloseCode = 1
	if d.Messages[0].Content[0] == 'X' || *d.CloseCode == 1 {
		t.Error("mutating the clone changed the original")
	}
}
