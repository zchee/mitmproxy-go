// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

// TestUnsupportedMessageResult exercises the public contract used by dumpers.
func TestUnsupportedMessageResult(t *testing.T) {
	tests := map[string]struct{ message any }{
		"integer":                {42},
		"text":                   {"body"},
		"bytes":                  {[]byte("body")},
		"undocumented structure": {struct{}{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := contentviews.PrettifyMessage(tt.message, nil, "", nil, 0)
			if !errors.Is(got.Err, contentviews.ErrUnsupportedMessage) {
				t.Fatalf("Err=%v, want ErrUnsupportedMessage", got.Err)
			}
			wantText := fmt.Sprintf("unsupported contentview message %T", tt.message)
			if diff := cmp.Diff(wantText, got.Text); diff != "" {
				t.Fatal(diff)
			}
			if got.SyntaxHighlight != "error" || got.ViewName != "" {
				t.Fatalf("result=%+v", got)
			}
		})
	}
}

type failingView struct {
	contentviews.Raw
	cause  error
	panics bool
}

func (failingView) Name() string                                         { return "Failing" }
func (failingView) RenderPriority([]byte, contentviews.Metadata) float64 { return 2 }
func (v failingView) Prettify([]byte, contentviews.Metadata) (string, error) {
	if v.panics {
		panic(v.cause)
	}
	return "", v.cause
}

func TestRenderingResultError(t *testing.T) {
	cause := errors.New("invalid document")
	tests := map[string]struct {
		selected string
		panics   bool
		wantText string
		wantView string
		cutoff   int
	}{
		"automatic":               {"auto", false, "body\nsecond", "Raw", 0},
		"empty selects automatic": {"", false, "body\nsecond", "Raw", 0},
		"explicit":                {"Failing", false, "Couldn't parse as Failing:\ninvalid document\n", "Failing", 0},
		"panic retains cause":     {"auto", true, "body\nsecond", "Raw", 0},
		"cutoff retains cause":    {"auto", false, "body\n", "Raw", 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			registry := contentviews.NewRegistry()
			registry.Register(failingView{cause: cause, panics: tt.panics})
			got := contentviews.PrettifyMessage(&httpmsg.Message{RawContent: []byte("body\nsecond")}, nil, tt.selected, registry, tt.cutoff)
			if !errors.Is(got.Err, cause) {
				t.Fatalf("Err=%v, want original cause", got.Err)
			}
			if diff := cmp.Diff(tt.wantText, got.Text); diff != "" {
				t.Fatal(diff)
			}
			if diff := cmp.Diff(tt.wantView, got.ViewName); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestMessageResultWithoutView(t *testing.T) {
	tests := map[string]struct {
		message  any
		registry *contentviews.Registry
		wantErr  error
	}{
		"missing content": {nil, nil, nil},
		"typed nil":       {(*httpmsg.Request)(nil), nil, nil},
		"valid raw":       {&httpmsg.Message{RawContent: []byte("body")}, nil, nil},
		"empty registry":  {&httpmsg.Message{RawContent: []byte("body")}, &contentviews.Registry{}, contentviews.ErrNoView},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := contentviews.PrettifyMessage(tt.message, nil, "auto", tt.registry, 0)
			if !errors.Is(got.Err, tt.wantErr) {
				t.Fatalf("Err=%v, want %v", got.Err, tt.wantErr)
			}
		})
	}
}
