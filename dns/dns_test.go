// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"net/netip"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/state"
)

// tDNSReq mirrors upstream's mitmproxy.test.tutils.tdnsreq.
func tDNSReq() *Message {
	return &Message{
		Timestamp:        new(946681200.0),
		ID:               42,
		Query:            true,
		OpCode:           OpCodeQUERY,
		RecursionDesired: true,
		ResponseCode:     ResponseCodeNOERROR,
		Questions:        []Question{{Name: "dns.google", Type: TypeA, Class: ClassIN}},
		Answers:          []ResourceRecord{},
		Authorities:      []ResourceRecord{},
		Additionals:      []ResourceRecord{},
	}
}

// tDNSResp mirrors upstream's mitmproxy.test.tutils.tdnsresp.
func tDNSResp() *Message {
	m := tDNSReq()
	m.Timestamp = new(946681201.0)
	m.Query = false
	m.RecursionAvailable = true
	m.Answers = []ResourceRecord{
		{Name: "dns.google", Type: TypeA, Class: ClassIN, TTL: 32, Data: []byte{8, 8, 8, 8}},
		{Name: "dns.google", Type: TypeA, Class: ClassIN, TTL: 32, Data: []byte{8, 8, 4, 4}},
	}
	return m
}

var messageKeys = []string{
	"id", "query", "op_code", "authoritative_answer", "truncation", "recursion_desired",
	"recursion_available", "reserved", "response_code", "questions", "answers", "authorities",
	"additionals", "timestamp",
}

// respState is the get_state output of upstream's tdnsresp().
func respState() *state.Map {
	q := state.NewMap(3)
	q.Set("name", "dns.google")
	q.Set("type", int64(1))
	q.Set("class_", int64(1))
	rr := func(data string) *state.Map {
		m := state.NewMap(5)
		m.Set("name", "dns.google")
		m.Set("type", int64(1))
		m.Set("class_", int64(1))
		m.Set("ttl", int64(32))
		m.Set("data", []byte(data))
		return m
	}
	m := state.NewMap(14)
	m.Set("id", int64(42))
	m.Set("query", false)
	m.Set("op_code", int64(0))
	m.Set("authoritative_answer", false)
	m.Set("truncation", false)
	m.Set("recursion_desired", true)
	m.Set("recursion_available", true)
	m.Set("reserved", int64(0))
	m.Set("response_code", int64(0))
	m.Set("questions", []any{q})
	m.Set("answers", []any{rr("\x08\x08\x08\x08"), rr("\x08\x08\x04\x04")})
	m.Set("authorities", []any{})
	m.Set("additionals", []any{})
	m.Set("timestamp", 946681201.0)
	return m
}

func TestMessageState(t *testing.T) {
	t.Parallel()

	if diff := gocmp.Diff(messageKeys, (&Message{}).GetState().Keys()); diff != "" {
		t.Errorf("zero message key order mismatch (-want +got):\n%s", diff)
	}
	if diff := gocmp.Diff(respState(), tDNSResp().GetState()); diff != "" {
		t.Errorf("GetState mismatch (-want +got):\n%s", diff)
	}

	// Ports test_dns.py::TestMessage::test_copy.
	in := respState()
	m, err := MessageFromState(in)
	if err != nil {
		t.Fatal(err)
	}
	if in.Len() != 0 {
		t.Errorf("MessageFromState left keys %v", in.Keys())
	}
	if diff := gocmp.Diff(tDNSResp(), m); diff != "" {
		t.Errorf("decoded message mismatch (-want +got):\n%s", diff)
	}
	c := m.Clone()
	c.Answers[0].Data[0] = 9
	c.Questions[0].Name = "x"
	if m.Answers[0].Data[0] == 9 || m.Questions[0].Name == "x" {
		t.Error("Clone shares sections with the original")
	}

	noTS := tDNSReq()
	noTS.Timestamp = nil
	if v, _ := noTS.GetState().Get("timestamp"); v != nil {
		t.Errorf("timestamp state = %v, want None", v)
	}
}

func TestMessageSetStateErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate  func(*state.Map)
		wantErr string
	}{
		"error: unexpected fields": {
			mutate:  func(m *state.Map) { m.Set("size", int64(8)) },
			wantErr: "unexpected fields in DNSMessage.set_state: [size]",
		},
		"error: unexpected question field": {
			mutate: func(m *state.Map) {
				q := state.NewMap(4)
				q.Set("name", "a")
				q.Set("type", int64(1))
				q.Set("class_", int64(1))
				q.Set("class", int64(1))
				m.Set("questions", []any{q})
			},
			wantErr: "unexpected fields in Question.set_state: [class]",
		},
		"error: record data as str": {
			mutate: func(m *state.Map) {
				rr := state.NewMap(5)
				rr.Set("name", "a")
				rr.Set("type", int64(1))
				rr.Set("class_", int64(1))
				rr.Set("ttl", int64(1))
				rr.Set("data", "x")
				m.Set("answers", []any{rr})
			},
			wantErr: `field "data": expected bytes, got str`,
		},
		"error: missing field": {
			mutate:  func(m *state.Map) { m.Delete("reserved") },
			wantErr: `missing field "reserved"`,
		},
		"error: question not a dict": {
			mutate:  func(m *state.Map) { m.Set("questions", []any{[]any{"a", int64(1), int64(1)}}) },
			wantErr: "expected dict, got list",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := respState()
			tt.mutate(s)
			m := tDNSReq()
			before := m.GetState()
			err := m.SetState(s)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("SetState error = %v, want it to contain %q", err, tt.wantErr)
			}
			if diff := gocmp.Diff(before, m.GetState()); diff != "" {
				t.Errorf("failed SetState modified the message (-before +after):\n%s", diff)
			}
		})
	}
}

func TestResponses(t *testing.T) {
	t.Parallel()

	// Ports test_dns.py::TestMessage::test_responses.
	req := tDNSReq()
	resp := req.Succeed([]ResourceRecord{
		A("dns.google", netip.MustParseAddr("8.8.8.8"), 32),
		A("dns.google", netip.MustParseAddr("8.8.4.4"), 32),
	})
	resp.Timestamp = new(946681201.0)
	if diff := gocmp.Diff(tDNSResp(), resp); diff != "" {
		t.Errorf("Succeed mismatch (-want +got):\n%s", diff)
	}
	if got := resp.Size(); got != 8 {
		t.Errorf("Size() = %d, want 8", got)
	}
	if _, err := req.Fail(ResponseCodeNOERROR); err == nil {
		t.Error("Fail(NOERROR) succeeded")
	}
	f, err := req.Fail(ResponseCodeFORMERR)
	if err != nil || f.ResponseCode != ResponseCodeFORMERR || f.RecursionAvailable || f.Query {
		t.Errorf("Fail(FORMERR) = %+v, %v", f, err)
	}

	// Ports test_question.
	if q, ok := req.Question(); !ok || q.Name != "dns.google" {
		t.Errorf("Question() = %v, %v", q, ok)
	}
	req.Questions = nil
	if _, ok := req.Question(); ok {
		t.Error("Question() reported a question for an empty section")
	}
}

func TestResourceRecordViews(t *testing.T) {
	t.Parallel()

	// Ports the codec-free parts of test_str and test_setter.
	tests := map[string]struct {
		rr   ResourceRecord
		want string
	}{
		"success: A":            {rr: A("test", netip.MustParseAddr("1.2.3.4"), DefaultTTL), want: "1.2.3.4"},
		"success: AAAA":         {rr: AAAA("test", netip.MustParseAddr("::1"), DefaultTTL), want: "::1"},
		"success: TXT":          {rr: TXT("test", "unicode text 😀", DefaultTTL), want: "unicode text 😀"},
		"success: invalid A":    {rr: ResourceRecord{Name: "test", Type: TypeA, Class: ClassIN, TTL: DefaultTTL, Data: []byte{}}, want: "0x (invalid A data)"},
		"success: unknown type": {rr: ResourceRecord{Name: "test", Type: TypeSOA, Class: ClassIN, TTL: DefaultTTL, Data: []byte{0, 1, 2, 3}}, want: "0x00010203"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tt.rr.displayData(); got != tt.want {
				t.Errorf("displayData() = %q, want %q", got, tt.want)
			}
		})
	}

	rr := ResourceRecord{Name: "test", Type: TypeANY, Class: ClassIN, TTL: DefaultTTL, Data: []byte{}}
	rr.SetIPv4Address(netip.MustParseAddr("8.8.4.4"))
	if ip, err := rr.IPv4Address(); err != nil || ip != netip.MustParseAddr("8.8.4.4") {
		t.Errorf("IPv4Address() = %v, %v", ip, err)
	}
	rr.SetIPv6Address(netip.MustParseAddr("2001:4860:4860::8844"))
	if ip, err := rr.IPv6Address(); err != nil || ip != netip.MustParseAddr("2001:4860:4860::8844") {
		t.Errorf("IPv6Address() = %v, %v", ip, err)
	}
	rr.SetText("sample text")
	if s, err := rr.Text(); err != nil || s != "sample text" {
		t.Errorf("Text() = %q, %v", s, err)
	}
	if _, err := rr.IPv4Address(); err == nil {
		t.Error("IPv4Address accepted 11 bytes")
	}

	m := tDNSResp()
	if got, want := m.String(), "dns.google\r\n8.8.8.8\r\n8.8.4.4"; got != want {
		t.Errorf("Message.String() = %q, want %q", got, want)
	}
}

func TestConstantNames(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		toStr   func(int) string
		fromStr func(string) (int, error)
		value   int
		name    string
	}{
		"success: type":                 {toStr: TypeToString, fromStr: TypeFromString, value: TypeHTTPS, name: "HTTPS"},
		"success: type with underscore": {toStr: TypeToString, fromStr: TypeFromString, value: TypeNSAPPTR, name: "NSAP_PTR"},
		"success: unknown type":         {toStr: TypeToString, fromStr: TypeFromString, value: 4242, name: "TYPE(4242)"},
		"success: class":                {toStr: ClassToString, fromStr: ClassFromString, value: ClassIN, name: "IN"},
		"success: unknown class":        {toStr: ClassToString, fromStr: ClassFromString, value: 7, name: "CLASS(7)"},
		"success: op code":              {toStr: OpCodeToString, fromStr: OpCodeFromString, value: OpCodeDSO, name: "DSO"},
		"success: unknown op code":      {toStr: OpCodeToString, fromStr: OpCodeFromString, value: 3, name: "OPCODE(3)"},
		"success: response code":        {toStr: ResponseCodeToString, fromStr: ResponseCodeFromString, value: ResponseCodeNXDOMAIN, name: "NXDOMAIN"},
		"success: unknown rcode":        {toStr: ResponseCodeToString, fromStr: ResponseCodeFromString, value: 12, name: "RCODE(12)"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tt.toStr(tt.value); got != tt.name {
				t.Errorf("to string = %q, want %q", got, tt.name)
			}
			got, err := tt.fromStr(tt.name)
			if err != nil || got != tt.value {
				t.Errorf("from string = (%d, %v), want %d", got, err, tt.value)
			}
		})
	}
	if _, err := TypeFromString("BOGUS"); err == nil {
		t.Error("TypeFromString accepted an unknown name")
	}
	if got := HTTPEquivStatusCode(ResponseCodeNXDOMAIN); got != 404 {
		t.Errorf("HTTPEquivStatusCode(NXDOMAIN) = %d", got)
	}
	if got := HTTPEquivStatusCode(99); got != 500 {
		t.Errorf("HTTPEquivStatusCode(99) = %d", got)
	}
	if TypeDLV != 32769 || ClassANY != 255 || OpCodeUPDATE != 5 || ResponseCodeDSOTYPENI != 11 {
		t.Error("constant values drifted from upstream")
	}
}
