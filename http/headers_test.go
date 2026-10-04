// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func hdrs(kv ...string) Headers {
	h := make(Headers, 0, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		h = append(h, Field{Name: []byte(kv[i]), Value: []byte(kv[i+1])})
	}
	return h
}

func TestHeadersGet(t *testing.T) {
	t.Parallel()

	h := hdrs("Host", "example.com", "Accept", "text/html", "accept", "application/xml")
	tests := map[string]struct {
		name    string
		want    string
		wantOK  bool
		wantAll []string
	}{
		"success: single": {name: "host", want: "example.com", wantOK: true, wantAll: []string{"example.com"}},
		"success: folded in order": {
			name: "ACCEPT", want: "text/html, application/xml", wantOK: true,
			wantAll: []string{"text/html", "application/xml"},
		},
		"success: absent": {name: "cookie", want: "", wantOK: false, wantAll: nil},
		"success: no unicode case folding": {
			// U+212A KELVIN SIGN folds to "k" under Unicode rules but not
			// under the ASCII rules header names use.
			name: "Keep", want: "", wantOK: false, wantAll: nil,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, ok := h.Lookup(tt.name)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("Lookup(%q) = (%q, %v), want (%q, %v)", tt.name, got, ok, tt.want, tt.wantOK)
			}
			if got := h.Get(tt.name); got != tt.want {
				t.Errorf("Get(%q) = %q, want %q", tt.name, got, tt.want)
			}
			if got := h.Has(tt.name); got != tt.wantOK {
				t.Errorf("Has(%q) = %v, want %v", tt.name, got, tt.wantOK)
			}
			if diff := gocmp.Diff(tt.wantAll, h.GetAll(tt.name)); diff != "" {
				t.Errorf("GetAll(%q) mismatch (-want +got):\n%s", tt.name, diff)
			}
		})
	}
}

func TestHeadersMutation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		start Headers
		apply func(*Headers)
		want  Headers
	}{
		"success: set replaces in place keeping name case": {
			start: hdrs("Host", "a", "Accept", "x", "host", "b"),
			apply: func(h *Headers) { h.Set("HOST", "c") },
			want:  hdrs("Host", "c", "Accept", "x"),
		},
		"success: set appends a new key as given": {
			start: hdrs("Host", "a"),
			apply: func(h *Headers) { h.Set("X-New", "1") },
			want:  hdrs("Host", "a", "X-New", "1"),
		},
		"success: set_all fills existing slots then appends": {
			start: hdrs("Set-Cookie", "a", "Date", "d"),
			apply: func(h *Headers) { h.SetAll("set-cookie", []string{"1", "2", "3"}) },
			want:  hdrs("Set-Cookie", "1", "Date", "d", "set-cookie", "2", "set-cookie", "3"),
		},
		"success: set_all with no values deletes": {
			start: hdrs("A", "1", "a", "2", "B", "3"),
			apply: func(h *Headers) { h.SetAll("a", nil) },
			want:  hdrs("B", "3"),
		},
		"success: add keeps duplicates": {
			start: hdrs("A", "1"),
			apply: func(h *Headers) { h.Add("a", "2") },
			want:  hdrs("A", "1", "a", "2"),
		},
		"success: insert at front": {
			// Ports test_http.py::TestHeaders::test_insert.
			start: hdrs("Accept", "text/plain"),
			apply: func(h *Headers) { h.Insert(0, "Host", "example.com") },
			want:  hdrs("Host", "example.com", "Accept", "text/plain"),
		},
		"success: del removes every occurrence": {
			start: hdrs("A", "1", "B", "2", "a", "3"),
			apply: func(h *Headers) { h.Del("A") },
			want:  hdrs("B", "2"),
		},
		"success: set on nil headers": {
			start: nil,
			apply: func(h *Headers) { h.Set("foo", "1") },
			want:  hdrs("foo", "1"),
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := tt.start.Clone()
			tt.apply(&h)
			if diff := gocmp.Diff(tt.want, h); diff != "" {
				t.Errorf("fields mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHeadersBytesAndKeys(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		h         Headers
		wantBytes string
		wantKeys  []string
	}{
		"success: empty": {h: nil, wantBytes: "", wantKeys: nil},
		"success: two fields": {
			h:         hdrs("Host", "example.com", "Accept", "text/plain"),
			wantBytes: "Host: example.com\r\nAccept: text/plain\r\n",
			wantKeys:  []string{"Host", "Accept"},
		},
		"success: repeated key listed once in first spelling": {
			h:         hdrs("Set-Cookie", "foo", "set-cookie", "bar"),
			wantBytes: "Set-Cookie: foo\r\nset-cookie: bar\r\n",
			wantKeys:  []string{"Set-Cookie"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := string(tt.h.Bytes()); got != tt.wantBytes {
				t.Errorf("Bytes() = %q, want %q", got, tt.wantBytes)
			}
			if diff := gocmp.Diff(tt.wantKeys, tt.h.Keys()); diff != "" {
				t.Errorf("Keys() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHeadersState(t *testing.T) {
	t.Parallel()

	h := hdrs("Host", "127.0.0.1:5000", "User-Agent", "curl/8.11.0")
	want := []any{
		[]any{[]byte("Host"), []byte("127.0.0.1:5000")},
		[]any{[]byte("User-Agent"), []byte("curl/8.11.0")},
	}
	if diff := gocmp.Diff(want, h.state()); diff != "" {
		t.Fatalf("state mismatch (-want +got):\n%s", diff)
	}
	back, err := headersFromState(want)
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(h, back); diff != "" {
		t.Errorf("round trip mismatch (-want +got):\n%s", diff)
	}
	if empty, err := headersFromState([]any{}); err != nil || empty == nil {
		t.Errorf("empty header list = (%#v, %v), want non-nil empty headers", empty, err)
	}
	if _, err := headersFromState([]any{[]any{"Host", []byte("x")}}); err == nil {
		t.Error("str header name accepted, want an error")
	}
}
