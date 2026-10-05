// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// TestJavaScriptPrettify ports upstream's test_view_javascript.
func TestJavaScriptPrettify(t *testing.T) {
	t.Parallel()
	t.Run("success: function body gains lines and indentation", func(t *testing.T) {
		t.Parallel()
		got, err := (JavaScript{}).Prettify([]byte("function(a){[1, 2, 3]}"), Metadata{})
		if err != nil {
			t.Fatalf("Prettify() error = %v", err)
		}
		if diff := cmp.Diff("function(a) {\n  [1, 2, 3]\n}\n", got); diff != "" {
			t.Fatalf("text (-want +got):\n%s", diff)
		}
	})
	for name, data := range map[string]string{
		"success: array":          "[1, 2, 3]",
		"success: unclosed array": "[1, 2, 3",
		"success: invalid utf-8":  "\xfe",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := (JavaScript{}).Prettify([]byte(data), Metadata{})
			if err != nil {
				t.Fatalf("Prettify() error = %v", err)
			}
			if got == "" {
				t.Fatal("Prettify() returned empty text")
			}
		})
	}
	t.Run("success: invalid utf-8 becomes replacement characters by maximal subpart", func(t *testing.T) {
		t.Parallel()
		got, err := (JavaScript{}).Prettify([]byte("a\xe6\x97b\xed\xa0\x80c"), Metadata{})
		if err != nil {
			t.Fatalf("Prettify() error = %v", err)
		}
		if diff := cmp.Diff("a�b���c", got); diff != "" {
			t.Fatalf("text (-want +got):\n%s", diff)
		}
	})
}

// TestJavaScriptBeautify ports upstream's fixture comparison.
func TestJavaScriptBeautify(t *testing.T) {
	t.Parallel()
	input := testutil.Fixture(t, "mitmproxy/contentviews/javascript/simple.js")
	want := testutil.Fixture(t, "mitmproxy/contentviews/javascript/simple-formatted.js")
	got, err := (JavaScript{}).Prettify(input, Metadata{})
	if err != nil {
		t.Fatalf("Prettify() error = %v", err)
	}
	if diff := cmp.Diff(string(want), got); diff != "" {
		t.Fatalf("text (-want +got):\n%s", diff)
	}
}

// TestJavaScriptRenderPriority ports upstream's test_render_priority.
func TestJavaScriptRenderPriority(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		data        string
		contentType string
		want        float64
	}{
		"success: x-javascript":       {"data", "application/x-javascript", 1},
		"success: application":        {"data", "application/javascript", 1},
		"success: text":               {"data", "text/javascript", 1},
		"success: other content type": {"data", "text/plain", 0},
		"success: empty data":         {"", "text/javascript", 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := (JavaScript{}).RenderPriority([]byte(tt.data), Metadata{ContentType: tt.contentType})
			if got != tt.want {
				t.Fatalf("RenderPriority() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestJavaScriptMatchTimeout proves the match-timeout behavior through
// the logger hook: in "=/" followed by repeated "\/x" units, every
// escaped slash starts a regular-expression area candidate whose closing
// slash always precedes an "x" that fails the flag lookahead, so each
// unit rescans the tail and the engine abandons the search at its limit.
// The input comes back unformatted with exactly one log line; the test
// asserts no wall-clock bound.
func TestJavaScriptMatchTimeout(t *testing.T) {
	// Swaps the package logger; not parallel.
	var log bytes.Buffer
	previous := SetLogger(slog.New(slog.NewTextHandler(&log, nil)))
	t.Cleanup(func() { SetLogger(previous) })
	input := "=/" + strings.Repeat(`\/x`, 80_000)
	got, err := (JavaScript{}).Prettify([]byte(input), Metadata{})
	if err != nil {
		t.Fatalf("Prettify() error = %v", err)
	}
	if diff := cmp.Diff(input, got); diff != "" {
		t.Fatalf("text (-want +got):\n%s", diff)
	}
	if lines := strings.Count(log.String(), "\n"); lines != 1 {
		t.Fatalf("logged %d lines, want exactly 1:\n%s", lines, log.String())
	}
	if !strings.Contains(log.String(), "match timeout") {
		t.Fatalf("log does not name the match timeout:\n%s", log.String())
	}
}
