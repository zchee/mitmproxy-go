// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package readfile

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func newReader(t *testing.T, input io.ReadCloser) (*master.Master, *ReadFile, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	m := master.New(master.Config{})
	r := New(m, Config{Stdin: input, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err := m.Addons.Add(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Addons.Trigger(context.WithoutCancel(t.Context()), addon.DoneHook{}); err != nil {
			t.Error(err)
		}
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	return m, r, &logs
}

func flowBytes(t *testing.T, count int) []byte {
	t.Helper()
	var data bytes.Buffer
	writer := flowio.NewWriter(&data)
	for range count {
		if err := writer.Add(testflow.TFlow()); err != nil {
			t.Fatal(err)
		}
	}
	return data.Bytes()
}

func configure(t *testing.T, m *master.Master, values map[string]any) error {
	t.Helper()
	return m.Do(t.Context(), func(ctx context.Context) error { return m.Options.Update(ctx, values) })
}

func wait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		t.Fatalf("background loading did not stop:\n%s", stack[:n])
	}
}

// Upstream TestReadFile.test_configure.
func TestConfigure(t *testing.T) {
	m, r, _ := newReader(t, nil)
	tests := map[string]struct {
		expression string
		invalid    bool
		count      int
	}{
		"success: request filter":     {expression: "~q", count: 1},
		"success: nonmatching filter": {expression: "~s", count: 0},
		"error: malformed filter":     {expression: "~~", invalid: true},
		"success: clear filter":       {count: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := configure(t, m, map[string]any{"readfile_filter": new(tt.expression)})
			if tt.invalid {
				if _, ok := errors.AsType[*options.OptionsError](err); !ok {
					t.Fatalf("configure = %v, want options error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			count, err := r.LoadFlows(t.Context(), bytes.NewReader(flowBytes(t, 1)))
			if err != nil || count != tt.count {
				t.Fatalf("loaded %d, %v; want %d", count, err, tt.count)
			}
		})
	}
}

// Upstream TestReadFile.test_corrupt and test_nonexistent_file;
// TestReadFileStdin.test_stdin and test_normal.
func TestLoadFlowsFromPath(t *testing.T) {
	tests := map[string]struct {
		count                   int
		corrupt, missing, stdin bool
		message                 string
	}{
		"success: normal":      {count: 2},
		"success: stdin":       {count: 2, stdin: true},
		"success: empty":       {},
		"error: corrupt":       {corrupt: true, message: "Flow file corrupted."},
		"error: partial":       {count: 1, corrupt: true, message: "Flow file corrupted - loaded 1 flows."},
		"error: corrupt stdin": {stdin: true, corrupt: true, message: "Flow file corrupted."},
		"error: missing":       {missing: true, message: "Cannot load flows:"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			data := flowBytes(t, tt.count)
			if tt.corrupt {
				data = append(data, []byte("invalid")...)
			}
			path := filepath.Join(t.TempDir(), "flows")
			if !tt.missing {
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var input io.ReadCloser
			if tt.stdin {
				var err error
				input, err = os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				path = "-"
			}
			_, r, logs := newReader(t, input)
			count, err := r.LoadFlowsFromPath(t.Context(), path)
			if (err != nil) != (tt.corrupt || tt.missing) || count != tt.count {
				t.Fatalf("loaded %d, %v; want %d, error=%v", count, err, tt.count, tt.corrupt || tt.missing)
			}
			if tt.message != "" && !strings.Contains(logs.String(), tt.message) {
				t.Fatalf("logs = %q, missing %q", logs.String(), tt.message)
			}
		})
	}
}

type observer struct {
	count, pauseAt  int
	reached, resume chan struct{}
	runningCount    int
	runningAt       time.Time
}

func (o *observer) Running(context.Context) error {
	o.runningCount = o.count
	o.runningAt = time.Now()
	return nil
}

func (o *observer) Request(ctx context.Context, _ *flow.HTTPFlow) error {
	o.count++
	if o.count != o.pauseAt {
		return nil
	}
	_, err := addon.Concurrent(ctx, func(ctx context.Context) error {
		close(o.reached)
		select {
		case <-o.resume:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	return err
}

// Upstream TestReadFile.test_read, extended with a dispatch handoff while a
// large file is being replayed so loading cannot block the running chain.
func TestRunningLoadsAsynchronously(t *testing.T) {
	m, r, logs := newReader(t, nil)
	path := filepath.Join(t.TempDir(), "flows")
	if err := os.WriteFile(path, flowBytes(t, 1000), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configure(t, m, map[string]any{"rfile": new(path)}); err != nil {
		t.Fatal(err)
	}
	o := &observer{pauseAt: 37, reached: make(chan struct{}), resume: make(chan struct{})}
	if err := m.Addons.Add(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	if value, err := m.Call(t.Context(), "readfile.reading"); err != nil || value != false {
		t.Fatalf("reading before running = %v, %v", value, err)
	}
	if err := m.Addons.Trigger(t.Context(), addon.RunningHook{}); err != nil {
		t.Fatal(err)
	}
	wait(t, o.reached)
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		if o.runningAt.IsZero() || o.runningCount >= 1000 {
			t.Errorf("running observed %d flows at %v", o.runningCount, o.runningAt)
		}
		if o.count != 37 {
			t.Errorf("handoff observed %d flows, want 37", o.count)
		}
		if !r.Reading(ctx) {
			t.Error("loading not reported active")
		}
		close(o.resume)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wait(t, r.done)
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		if o.count != 1000 || r.Reading(ctx) {
			t.Errorf("loaded=%d, reading=%v", o.count, r.Reading(ctx))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Trigger(t.Context(), addon.RunningHook{}); err != nil {
		t.Fatal(err)
	}
	wait(t, r.done)
	loggedPath := path
	if runtime.GOOS == "windows" {
		// TextHandler escapes backslashes inside its quoted message field.
		loggedPath = strings.ReplaceAll(path, `\`, `\\`)
	}
	if !strings.Contains(logs.String(), "Failed to read "+loggedPath) {
		t.Fatalf("missing read failure: %q", logs.String())
	}
}

func TestDoneCancelsStdin(t *testing.T) {
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close(); _ = output.Close() })
	m, r, logs := newReader(t, input)
	if err := configure(t, m, map[string]any{"rfile": new("-")}); err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Trigger(t.Context(), addon.RunningHook{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Addons.Trigger(t.Context(), addon.DoneHook{}); err != nil {
		t.Fatal(err)
	}
	wait(t, r.done)
	if logs.Len() != 0 {
		t.Fatalf("cancellation logged corruption: %s", logs.String())
	}
}

func TestOptions(t *testing.T) {
	m, _, _ := newReader(t, nil)
	tests := map[string]struct{ help string }{
		"rfile":           {"Read flows from file."},
		"readfile_filter": {"Read only matching flows."},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opt, ok := m.Options.Lookup(name)
			if !ok {
				t.Fatal("missing option")
			}
			got := []any{opt.Type(), opt.Default(), opt.Help()}
			if diff := gocmp.Diff([]any{options.TypeOptStr, (*string)(nil), tt.help}, got); diff != "" {
				t.Fatalf("option (-want +got):\n%s", diff)
			}
		})
	}
}
