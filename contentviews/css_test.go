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

// TestCSSBeautify ports upstream's test_beautify: every fixture formats to
// its recorded formatted twin.
func TestCSSBeautify(t *testing.T) {
	t.Parallel()
	fixtures := []string{
		"animation-keyframe",
		"blank-lines-and-spaces",
		"block-comment",
		"empty-rule",
		"import-directive",
		"indentation",
		"media-directive",
		"quoted-string",
		"selectors",
		"simple",
	}
	for _, fixture := range fixtures {
		t.Run("success: "+fixture, func(t *testing.T) {
			t.Parallel()
			input := testutil.Fixture(t, "mitmproxy/contentviews/css/"+fixture+".css")
			want := testutil.Fixture(t, "mitmproxy/contentviews/css/"+fixture+"-formatted.css")
			got, err := (CSS{}).Prettify(input, Metadata{})
			if err != nil {
				t.Fatalf("Prettify() error = %v", err)
			}
			if diff := cmp.Diff(string(want), got); diff != "" {
				t.Fatalf("text (-want +got):\n%s", diff)
			}
		})
	}
}

// TestCSSSimple ports upstream's test_simple.
func TestCSSSimple(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		data string
		want string
	}{
		"success: rule gains lines and indentation": {
			data: "#foo{color:red}",
			want: "#foo {\n    color: red\n}\n",
		},
		"success: empty input": {
			data: "",
			want: "\n",
		},
		"success: not CSS passes through": {
			data: "console.log('not really css')",
			want: "console.log('not really css')\n",
		},
		"success: undecodable bytes pass through": {
			data: "#foo{color:'\xff\xfe'}",
			want: "#foo {\n    color: '\xff\xfe'\n}\n",
		},
		"success: special characters inside strings stay untouched": {
			data: "a{content:'{;}'}",
			want: "a {\n    content: '{;}'\n}\n",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := (CSS{}).Prettify([]byte(tt.data), Metadata{})
			if err != nil {
				t.Fatalf("Prettify() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("text (-want +got):\n%s", diff)
			}
		})
	}
}

// TestCSSRenderPriority ports upstream's test_render_priority.
func TestCSSRenderPriority(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		data        string
		contentType string
		want        float64
	}{
		"success: css content type":   {"data", "text/css", 1},
		"success: other content type": {"data", "text/plain", 0},
		"success: empty data":         {"", "text/css", 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := (CSS{}).RenderPriority([]byte(tt.data), Metadata{ContentType: tt.contentType})
			if got != tt.want {
				t.Fatalf("RenderPriority() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCSSMatchTimeout proves the match-timeout behavior through the logger
// hook: a run of colons with no brace makes the colon rewrite's lookahead
// rescan the tail from every colon, far beyond the limit, and the input
// comes back as the unmarked text with exactly one log line. The engine's
// own limit is the deterministic signal; the test asserts no wall-clock
// bound.
func TestCSSMatchTimeout(t *testing.T) {
	// Swaps the package logger; not parallel.
	var log bytes.Buffer
	previous := SetLogger(slog.New(slog.NewTextHandler(&log, nil)))
	t.Cleanup(func() { SetLogger(previous) })
	input := strings.Repeat(":", 150_000)
	got, err := (CSS{}).Prettify([]byte(input), Metadata{})
	if err != nil {
		t.Fatalf("Prettify() error = %v", err)
	}
	if diff := cmp.Diff(input+"\n", got); diff != "" {
		t.Fatalf("text (-want +got):\n%s", diff)
	}
	if lines := strings.Count(log.String(), "\n"); lines != 1 {
		t.Fatalf("logged %d lines, want exactly 1:\n%s", lines, log.String())
	}
	if !strings.Contains(log.String(), "match timeout") {
		t.Fatalf("log does not name the match timeout:\n%s", log.String())
	}
}
