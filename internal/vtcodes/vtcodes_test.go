// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package vtcodes

import (
	"bytes"
	"os"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

// Upstream test/mitmproxy/utils/test_vt_codes.py:
//
//	test_simple -> "non-file writer is not supported" below (io.StringIO
//	becomes a bytes.Buffer). The Windows branch has no upstream test; the
//	stdout/stderr restriction runs only on a Windows console session.
//
// The positive terminal path needs a pseudo-terminal slave and lives in
// the Linux-only test file, because macOS exposes no slave-name call
// through golang.org/x/sys and its pty master answers no termios ioctl.
func TestEnsureSupported(t *testing.T) {
	t.Parallel()

	t.Run("non-file writer is not supported", func(t *testing.T) {
		t.Parallel()
		if got := EnsureSupported(&bytes.Buffer{}); got {
			t.Fatalf("EnsureSupported(bytes.Buffer) = %v, want false", got)
		}
	})

	t.Run("pipe is not a terminal", func(t *testing.T) {
		t.Parallel()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}
		defer func() { _ = r.Close() }()
		defer func() { _ = w.Close() }()
		if got := EnsureSupported(w); got {
			t.Fatalf("EnsureSupported(pipe) = %v, want false", got)
		}
	})

	t.Run("regular file is not a terminal", func(t *testing.T) {
		t.Parallel()
		f, err := os.CreateTemp(t.TempDir(), "out")
		if err != nil {
			t.Fatalf("os.CreateTemp: %v", err)
		}
		defer func() { _ = f.Close() }()
		if got := EnsureSupported(f); got {
			t.Fatalf("EnsureSupported(regular file) = %v, want false", got)
		}
	})
}

func TestColumns(t *testing.T) {
	t.Parallel()

	t.Run("nil file", func(t *testing.T) {
		t.Parallel()
		if n, ok := Columns(nil); ok || n != 0 {
			t.Fatalf("Columns(nil) = %d, %v, want 0, false", n, ok)
		}
	})

	t.Run("pipe has no window size", func(t *testing.T) {
		t.Parallel()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}
		defer func() { _ = r.Close() }()
		defer func() { _ = w.Close() }()
		if n, ok := Columns(w); ok || n != 0 {
			t.Fatalf("Columns(pipe) = %d, %v, want 0, false", n, ok)
		}
	})
}

func TestWidthFrom(t *testing.T) {
	t.Parallel()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()

	tests := map[string]struct {
		env    string
		stdout *os.File
		want   int
	}{
		"success: positive COLUMNS wins":           {env: "120", stdout: w, want: 120},
		"success: no COLUMNS, no terminal is 80":   {env: "", stdout: w, want: 80},
		"error: zero COLUMNS falls through":        {env: "0", stdout: w, want: 80},
		"error: negative COLUMNS falls through":    {env: "-3", stdout: w, want: 80},
		"error: non-numeric COLUMNS falls through": {env: "wide", stdout: w, want: 80},
		"error: nil stdout is 80":                  {env: "", stdout: nil, want: 80},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := widthFrom(tt.env, tt.stdout); got != tt.want {
				t.Fatalf("widthFrom(%q) = %d, want %d", tt.env, got, tt.want)
			}
		})
	}
}

// TestStyleRender checks Render against the strings the vendored
// click.style (mitmproxy/contrib/click) produces for the attribute
// combinations the dumper uses.
func TestStyleRender(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		style Style
		text  string
		want  string
	}{
		"success: no attributes still resets": {
			style: Style{},
			text:  "plain",
			want:  "plain\x1b[0m",
		},
		"success: foreground color": {
			style: Style{FG: "red"},
			text:  "error",
			want:  "\x1b[31merror\x1b[0m",
		},
		"success: bright foreground color": {
			style: Style{FG: "bright_blue"},
			text:  "answer",
			want:  "\x1b[94manswer\x1b[0m",
		},
		"success: foreground and bold": {
			style: Style{FG: "yellow", Bold: new(true)},
			text:  "[replay]",
			want:  "\x1b[33m\x1b[1m[replay]\x1b[0m",
		},
		"success: bold off emits its reset code": {
			style: Style{Bold: new(false)},
			text:  "x",
			want:  "\x1b[22mx\x1b[0m",
		},
		"success: dim": {
			style: Style{Dim: new(true)},
			text:  "(cut off)",
			want:  "\x1b[2m(cut off)\x1b[0m",
		},
		"success: blink": {
			style: Style{Blink: new(true)},
			text:  "418 I'm a teapot",
			want:  "\x1b[5m418 I'm a teapot\x1b[0m",
		},
		"success: all attributes in click's order": {
			style: Style{FG: "magenta", Bold: new(true), Dim: new(false), Blink: new(true)},
			text:  "t",
			want:  "\x1b[35m\x1b[1m\x1b[22m\x1b[5mt\x1b[0m",
		},
		"success: empty text": {
			style: Style{FG: "green"},
			text:  "",
			want:  "\x1b[32m\x1b[0m",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := tt.style.Render(tt.text)
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("Render mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestStyleRenderUnknownColorPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("Render with an unknown color did not panic")
		}
	}()
	Style{FG: "mauve"}.Render("x")
}

func TestStyleIsZero(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		style Style
		want  bool
	}{
		"success: zero value":     {style: Style{}, want: true},
		"success: color set":      {style: Style{FG: "red"}, want: false},
		"success: bold false set": {style: Style{Bold: new(false)}, want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tt.style.IsZero(); got != tt.want {
				t.Fatalf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}
