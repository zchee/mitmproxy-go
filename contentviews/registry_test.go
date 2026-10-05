// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

var errPrettify = errors.New("prettify failure")

type exampleView struct {
	name         string
	priority     float64
	failPriority bool
	failPrettify bool
}

func (v exampleView) Name() string          { return v.name }
func (exampleView) SyntaxHighlight() string { return "none" }
func (v exampleView) RenderPriority([]byte, Metadata) float64 {
	if v.failPriority {
		panic("priority failure")
	}
	return v.priority
}

func (v exampleView) Prettify(data []byte, _ Metadata) (string, error) {
	if v.failPrettify {
		return "", errPrettify
	}
	return string(data), nil
}

// These cases port test__registry.py, including the failing-priority view
// from test__api.py. Go registers instances rather than Python classes.
func TestRegistry(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"register_triggers_on_change": {func(t *testing.T) {
			r := &Registry{}
			var changed []string
			unsubscribe := r.Subscribe(func(v View) { changed = append(changed, v.Name()); r.Get(v.Name()) })
			r.Register(exampleView{name: "Example"})
			unsubscribe()
			r.Register(exampleView{name: "Other"})
			if diff := cmp.Diff([]string{"Example"}, changed); diff != "" {
				t.Fatal(diff)
			}
		}},
		"replace_view_triggers_on_change_and_logs": {func(t *testing.T) {
			var log bytes.Buffer
			previous := SetLogger(slog.New(slog.NewTextHandler(&log, nil)))
			t.Cleanup(func() { SetLogger(previous) })
			r := &Registry{}
			r.Register(exampleView{name: "Example", priority: 1})
			var calls int
			r.Subscribe(func(View) { calls++ })
			replacement := exampleView{name: "Example", priority: 2}
			r.Register(replacement)
			got, _ := r.Get("EXAMPLE")
			if calls != 1 || got != replacement || !strings.Contains(log.String(), "Replacing existing example contentview.") {
				t.Fatalf("calls=%d view=%v log=%s", calls, got, log.String())
			}
		}},
		"dunder_methods": {func(t *testing.T) {
			r := &Registry{}
			view := exampleView{name: "Example"}
			r.Register(view)
			for _, name := range []string{"example", "EXAMPLE"} {
				if got, ok := r.Get(name); !ok || got != view {
					t.Fatalf("Get(%q)=%v,%v", name, got, ok)
				}
			}
			if diff := cmp.Diff([]string{"auto", "example"}, r.AvailableViews()); diff != "" {
				t.Fatal(diff)
			}
		}},
		"get_view_unknown_name": {func(t *testing.T) {
			var log bytes.Buffer
			previous := SetLogger(slog.New(slog.NewTextHandler(&log, nil)))
			t.Cleanup(func() { SetLogger(previous) })
			r := &Registry{}
			view := exampleView{name: "Example"}
			r.Register(view)
			got, err := r.GetView([]byte("data"), Metadata{}, "unknown")
			if err != nil || got != view || !strings.Contains(log.String(), "Unknown contentview 'unknown', selecting best match instead.") {
				t.Fatalf("view=%v err=%v log=%s", got, err, log.String())
			}
		}},
		"render_priority_error": {func(t *testing.T) {
			var log bytes.Buffer
			previous := SetLogger(slog.New(slog.NewTextHandler(&log, nil)))
			t.Cleanup(func() { SetLogger(previous) })
			r := &Registry{}
			r.Register(exampleView{name: "FailingRenderPriority", failPriority: true})
			r.Register(exampleView{name: "Example"})
			got, err := r.GetView(nil, Metadata{}, "auto")
			if err != nil || got.Name() != "Example" {
				t.Fatalf("view=%v err=%v", got, err)
			}
			if !strings.Contains(log.String(), "Error in FailingRenderPriority.render_priority") {
				t.Fatalf("priority panic was not logged: %s", log.String())
			}
		}},
		"equal_priority_keeps_registration_order": {func(t *testing.T) {
			r := &Registry{}
			r.Register(exampleView{name: "Z", priority: 1})
			r.Register(exampleView{name: "A", priority: 1})
			r.Register(exampleView{name: "Z", priority: 1})
			got, err := r.GetView(nil, Metadata{}, "auto")
			if err != nil || got.Name() != "Z" {
				t.Fatalf("view=%v err=%v", got, err)
			}
		}},
		"empty_registry": {func(t *testing.T) {
			_, err := (&Registry{}).GetView(nil, Metadata{}, "auto")
			if !errors.Is(err, ErrNoView) {
				t.Fatalf("got %v", err)
			}
		}},
	}
	for name, tt := range tests {
		t.Run(name, tt.run)
	}
}

// The missing-content and view-failure cases port test___init__.py.
func TestPrettifyMessage(t *testing.T) {
	tests := map[string]struct {
		data            []byte
		selected        string
		fail            bool
		defaultRegistry bool
		cutoff          int
		want            Result
	}{
		"hex_stream":            {data: []byte("content"), selected: "hex stream", want: Result{Text: "636f6e74656e74", SyntaxHighlight: "none", ViewName: "Hex Stream"}},
		"default_registry":      {data: []byte("content"), defaultRegistry: true, want: Result{Text: "content", SyntaxHighlight: "none", ViewName: "Raw"}},
		"zero_line_cutoff":      {data: []byte("first\nsecond\nthird"), want: Result{Text: "first\nsecond\nthird", SyntaxHighlight: "none", ViewName: "Raw"}},
		"negative_line_cutoff":  {data: []byte("first\nsecond\nthird"), cutoff: -1, want: Result{Text: "first\nsecond\nthird", SyntaxHighlight: "none", ViewName: "Raw"}},
		"empty_content":         {want: Result{Text: "Content is missing.", SyntaxHighlight: "error"}},
		"empty_present":         {data: []byte{}, want: Result{SyntaxHighlight: "none", ViewName: "Raw"}},
		"view_failure_auto":     {data: []byte("content"), selected: "auto", fail: true, want: Result{Text: "content", SyntaxHighlight: "none", ViewName: "Raw", Description: "[failed to parse as FailingPrettify]", Err: errPrettify}},
		"view_failure_explicit": {data: []byte("content"), selected: "failing", fail: true, want: Result{Text: "Couldn't parse as FailingPrettify:\nprettify failure\n", SyntaxHighlight: "error", ViewName: "FailingPrettify", Err: errPrettify}},
		"control_characters":    {data: []byte("a\x00b\t\nc"), want: Result{Text: "a.b\t\nc", SyntaxHighlight: "none", ViewName: "Raw"}},
		"line_cutoff":           {data: []byte("first\nsecond\nthird"), cutoff: 2, want: Result{Text: "first\nsecond\n", SyntaxHighlight: "none", ViewName: "Raw", Truncated: true}},
		"complete_lines":        {data: []byte("first\nsecond\n"), cutoff: 2, want: Result{Text: "first\nsecond\n", SyntaxHighlight: "none", ViewName: "Raw"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var r *Registry
			if !tt.defaultRegistry {
				r = NewRegistry()
			}
			if tt.fail {
				r.Register(exampleView{name: "FailingPrettify", priority: 2, failPrettify: true})
			}
			got := PrettifyMessage(&httpmsg.Message{RawContent: tt.data}, nil, tt.selected, r, tt.cutoff)
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateErrors()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestRegistryConcurrent(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			for range 20 {
				r.Register(exampleView{name: "Example"})
				r.Get("Example")
				r.AvailableViews()
				if _, err := r.GetView(nil, Metadata{}, "auto"); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}
