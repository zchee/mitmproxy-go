// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/omap"
)

func TestMessageJSON(t *testing.T) {
	// Ports test_dns.py::TestMessage::test_to_json and test_from_json.
	message := tDNSResp()
	before := message.Clone()
	value := message.ToJSON()
	wantKeys := []string{"id", "query", "op_code", "authoritative_answer", "truncation", "recursion_desired", "recursion_available", "response_code", "status_code", "questions", "answers", "authorities", "additionals", "size", "timestamp"}
	if diff := gocmp.Diff(wantKeys, value.Keys()); diff != "" {
		t.Fatalf("message JSON keys:\n%s", diff)
	}
	got, err := MessageFromJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(message, got); diff != "" {
		t.Fatalf("JSON round trip:\n%s", diff)
	}
	if diff := gocmp.Diff(wantKeys, value.Keys()); diff != "" {
		t.Fatalf("MessageFromJSON consumed caller map:\n%s", diff)
	}
	if diff := gocmp.Diff(before, message); diff != "" {
		t.Fatalf("ToJSON modified message:\n%s", diff)
	}
	answers, _ := value.Get("answers")
	answer := answers.([]any)[0].(*omap.Map[any])
	data, _ := answer.Get("data")
	if data != "8.8.8.8" {
		t.Fatalf("A data = %v", data)
	}
}

func TestRecordJSON(t *testing.T) {
	tests := map[string]struct {
		typ  string
		data any
	}{
		"A":                    {typ: "A", data: "8.8.8.8"},
		"AAAA":                 {typ: "AAAA", data: "::1"},
		"CNAME":                {typ: "CNAME", data: "alias.google"},
		"TXT":                  {typ: "TXT", data: "random text"},
		"opaque":               {typ: "TYPE(65000)", data: "0xffff"},
		"malformed A fallback": {typ: "A", data: "0x (invalid A data)"},
		"HTTPS": {typ: "HTTPS", data: func() *omap.Map[any] {
			m := omap.New[any]()
			m.Set("target_name", "dns.google")
			m.Set("priority", 42)
			m.Set("mandatory", `\x00`)
			m.Set("no_default_alpn", "")
			m.Set("ech", `\x04`)
			m.Set("111", `\x00`)
			return m
		}()},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			value := tDNSResp().ToJSON()
			r := omap.New[any]()
			r.Set("name", "dns.google")
			r.Set("type", tt.typ)
			r.Set("class", "IN")
			r.Set("ttl", 32)
			r.Set("data", tt.data)
			value.Set("answers", []any{r})
			message, err := MessageFromJSON(value)
			if err != nil {
				t.Fatal(err)
			}
			answers, _ := message.ToJSON().Get("answers")
			got := answers.([]any)[0].(*omap.Map[any])
			if diff := gocmp.Diff(r, got); diff != "" {
				t.Fatalf("record JSON round trip:\n%s", diff)
			}
		})
	}
}
