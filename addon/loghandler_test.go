// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// collector records delivered entries. Its delivery function can be held
// back with gate to fill the handler's queue deterministically.
type collector struct {
	mu      sync.Mutex
	entries []LogEntry
	gate    chan struct{} // when non-nil, every delivery waits for a receive on it
	started chan struct{} // when non-nil, receives once per delivery before it waits
}

func (c *collector) deliver(_ context.Context, e LogEntry) {
	if c.started != nil {
		c.started <- struct{}{}
	}
	if c.gate != nil {
		<-c.gate
	}
	c.mu.Lock()
	c.entries = append(c.entries, e)
	c.mu.Unlock()
}

func (c *collector) got() []LogEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]LogEntry(nil), c.entries...)
}

// at is a fixed local time whose log format is "13:04:05.678".
var at = time.Date(2026, 10, 5, 13, 4, 5, 678_000_000, time.Local)

func record(level slog.Level, msg string, attrs ...slog.Attr) slog.Record {
	r := slog.NewRecord(at, level, msg, 0)
	r.AddAttrs(attrs...)
	return r
}

func closeHandler(t *testing.T, h *LogHandler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), deadlockTimeout)
	defer cancel()
	if err := h.Close(ctx); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestLogHandlerFormat(t *testing.T) {
	tests := map[string]struct {
		build func(h *LogHandler) slog.Handler
		rec   slog.Record
		want  LogEntry
	}{
		"success: plain message": {
			rec:  record(slog.LevelInfo, "proxy started"),
			want: LogEntry{Msg: "[13:04:05.678] proxy started", Level: slog.LevelInfo},
		},
		"success: client attribute goes in brackets": {
			rec:  record(LevelAlert, "client connect", slog.String("client", "127.0.0.1:51234")),
			want: LogEntry{Msg: "[13:04:05.678][127.0.0.1:51234] client connect", Level: LevelAlert},
		},
		"success: other attributes follow the message": {
			rec:  record(slog.LevelWarn, "slow", slog.Int("ms", 1200), slog.String("host", "example.com")),
			want: LogEntry{Msg: "[13:04:05.678] slow ms=1200 host=example.com", Level: slog.LevelWarn},
		},
		"success: group attribute is flattened": {
			rec:  record(slog.LevelDebug, "tls", slog.Group("conn", slog.String("sni", "a.example"), slog.Int("port", 443))),
			want: LogEntry{Msg: "[13:04:05.678] tls conn.sni=a.example conn.port=443", Level: slog.LevelDebug},
		},
		"success: attributes from WithAttrs come before the record's": {
			build: func(h *LogHandler) slog.Handler { return h.WithAttrs([]slog.Attr{slog.String("addon", "dumper")}) },
			rec:   record(slog.LevelError, "boom", slog.Int("n", 1)),
			want:  LogEntry{Msg: "[13:04:05.678] boom addon=dumper n=1", Level: slog.LevelError},
		},
		"success: WithGroup prefixes keys and keeps a client attribute as a plain key": {
			build: func(h *LogHandler) slog.Handler {
				return h.WithGroup("script").WithAttrs([]slog.Attr{slog.String("path", "a.star")})
			},
			rec:  record(slog.LevelInfo, "loaded", slog.String("client", "x")),
			want: LogEntry{Msg: "[13:04:05.678] loaded script.path=a.star script.client=x", Level: slog.LevelInfo},
		},
		"success: empty attribute is skipped": {
			rec:  record(slog.LevelInfo, "m", slog.Attr{}),
			want: LogEntry{Msg: "[13:04:05.678] m", Level: slog.LevelInfo},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := &collector{}
			h := NewLogHandler(c.deliver, LogHandlerOptions{})
			defer closeHandler(t, h)

			var sh slog.Handler = h
			if tt.build != nil {
				sh = tt.build(h)
			}
			if err := sh.Handle(t.Context(), tt.rec); err != nil {
				t.Fatalf("Handle: %v", err)
			}
			if err := h.Flush(t.Context()); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			if diff := cmp.Diff([]LogEntry{tt.want}, c.got()); diff != "" {
				t.Errorf("delivered entries (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLogHandlerEnabled(t *testing.T) {
	tests := map[string]struct {
		level slog.Leveler
		in    slog.Level
		want  bool
	}{
		"success: nil level accepts debug":    {level: nil, in: slog.LevelDebug - 4, want: true},
		"success: at the minimum":             {level: slog.LevelInfo, in: slog.LevelInfo, want: true},
		"success: alert passes an info floor": {level: slog.LevelInfo, in: LevelAlert, want: true},
		"error: below the minimum":            {level: slog.LevelWarn, in: LevelAlert, want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h := NewLogHandler(func(context.Context, LogEntry) {}, LogHandlerOptions{Level: tt.level})
			defer closeHandler(t, h)
			if got := h.Enabled(t.Context(), tt.in); got != tt.want {
				t.Errorf("Enabled(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestLogHandlerOrderThroughSlog(t *testing.T) {
	c := &collector{}
	h := NewLogHandler(c.deliver, LogHandlerOptions{})
	defer closeHandler(t, h)

	logger := slog.New(h)
	const n = 200
	for i := range n {
		logger.Info("entry", "i", i)
	}
	if err := h.Flush(t.Context()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	got := c.got()
	if len(got) != n {
		t.Fatalf("delivered %d entries, want %d", len(got), n)
	}
	for i, e := range got {
		if want := " entry i=" + strconv.Itoa(i); !strings.HasSuffix(e.Msg, want) {
			t.Fatalf("entry %d = %q, want suffix %q", i, e.Msg, want)
		}
	}
}

func TestLogHandlerOverflow(t *testing.T) {
	c := &collector{gate: make(chan struct{}), started: make(chan struct{})}
	h := NewLogHandler(c.deliver, LogHandlerOptions{QueueSize: 3})
	defer closeHandler(t, h)

	handle := func(msg string) {
		t.Helper()
		if err := h.Handle(t.Context(), record(slog.LevelInfo, msg)); err != nil {
			t.Fatalf("Handle: %v", err)
		}
	}

	// "first" is taken by the delivery goroutine, which then waits on the
	// gate; the queue of three fills with a, b, c; d and e are dropped.
	handle("first")
	<-c.started
	within(t, "logging into a full queue", func() {
		for _, m := range []string{"a", "b", "c", "d", "e"} {
			handle(m)
		}
	})

	// Release deliveries one by one until the queue has room for the drop
	// notice and the next entry.
	c.gate <- struct{}{} // first
	<-c.started
	c.gate <- struct{}{} // a
	<-c.started
	handle("after") // the notice and "after" fit behind c

	go func() {
		for range c.started {
			c.gate <- struct{}{}
		}
	}()
	c.gate <- struct{}{} // b
	if err := h.Flush(t.Context()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	close(c.started)

	got := c.got()
	var msgs []string
	for _, e := range got {
		_, msg, _ := strings.Cut(e.Msg, "] ")
		msgs = append(msgs, msg)
	}
	if len(got) != 6 {
		t.Fatalf("delivered %q, want 6 entries", msgs)
	}
	notice := got[4]
	if notice.Level != slog.LevelWarn || !strings.HasSuffix(notice.Msg, "dropped 2 log entries because the add_log queue was full") {
		t.Errorf("drop notice = %+v, want a warning counting 2 dropped entries", notice)
	}
	msgs[4] = "<notice>"
	if diff := cmp.Diff([]string{"first", "a", "b", "c", "<notice>", "after"}, msgs); diff != "" {
		t.Errorf("delivered messages (-want +got):\n%s", diff)
	}
}

func TestLogHandlerFlushContext(t *testing.T) {
	c := &collector{gate: make(chan struct{}), started: make(chan struct{})}
	h := NewLogHandler(c.deliver, LogHandlerOptions{})

	if err := h.Handle(t.Context(), record(slog.LevelInfo, "held")); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	<-c.started

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var err error
	within(t, "Flush with a cancelled context", func() { err = h.Flush(ctx) })
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Flush error = %v, want context.Canceled", err)
	}

	close(c.gate)
	closeHandler(t, h)
	if diff := cmp.Diff(1, len(c.got())); diff != "" {
		t.Errorf("Close did not deliver the queued entry (-want +got):\n%s", diff)
	}
}

func TestLogHandlerClose(t *testing.T) {
	c := &collector{}
	h := NewLogHandler(c.deliver, LogHandlerOptions{})
	for _, m := range []string{"one", "two", "three"} {
		if err := h.Handle(t.Context(), record(slog.LevelInfo, m)); err != nil {
			t.Fatalf("Handle: %v", err)
		}
	}
	closeHandler(t, h)
	if got := len(c.got()); got != 3 {
		t.Fatalf("Close delivered %d entries, want 3", got)
	}

	// Records after Close are discarded; Flush reports the closed handler;
	// a second Close is allowed.
	if err := h.Handle(t.Context(), record(slog.LevelInfo, "late")); err != nil {
		t.Fatalf("Handle after Close: %v", err)
	}
	if err := h.Flush(t.Context()); !errors.Is(err, ErrLogHandlerClosed) {
		t.Errorf("Flush after Close error = %v, want ErrLogHandlerClosed", err)
	}
	closeHandler(t, h)
	if got := len(c.got()); got != 3 {
		t.Errorf("%d entries delivered after Close, want 3", got)
	}
}

func TestLogHandlerCloseContext(t *testing.T) {
	c := &collector{gate: make(chan struct{}), started: make(chan struct{})}
	h := NewLogHandler(c.deliver, LogHandlerOptions{})
	if err := h.Handle(t.Context(), record(slog.LevelInfo, "held")); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	<-c.started

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := h.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Close error = %v, want context.Canceled", err)
	}
	close(c.gate)
	closeHandler(t, h)
}

// TestLogHandlerFromInsideHook logs from inside a hook whose delivery needs
// the dispatch lock that hook holds. Logging must return at once, and the
// entry is delivered once the hook has released the lock.
func TestLogHandlerFromInsideHook(t *testing.T) {
	d := &dispatcher{}
	var (
		mu      sync.Mutex
		entries []LogEntry
	)
	h := NewLogHandler(func(ctx context.Context, e LogEntry) {
		_ = d.do(ctx, func(context.Context) error {
			mu.Lock()
			entries = append(entries, e)
			mu.Unlock()
			return nil
		})
	}, LogHandlerOptions{})
	defer closeHandler(t, h)
	logger := slog.New(h)

	within(t, "logging inside a hook", func() {
		err := d.do(t.Context(), func(ctx context.Context) error {
			logger.InfoContext(ctx, "from hook")
			return nil
		})
		if err != nil {
			t.Errorf("do: %v", err)
		}
	})
	within(t, "Flush", func() {
		if err := h.Flush(t.Context()); err != nil {
			t.Errorf("Flush: %v", err)
		}
	})
	mu.Lock()
	defer mu.Unlock()
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Msg, " from hook") {
		t.Errorf("entries = %+v, want the one logged from the hook", entries)
	}
}

// TestLogHandlerTrailingDrops drops the last records logged and checks that
// the drop notice still arrives through Flush or Close, and that a handler
// whose requested queue is too small for the notice keeps delivering.
func TestLogHandlerTrailingDrops(t *testing.T) {
	tests := map[string]struct {
		queueSize int
		close     bool // finish with Close instead of Flush
		wantMsgs  []string
	}{
		"success: Flush reports drops that nothing follows, and logging continues with a one-entry queue": {
			queueSize: 1,
			wantMsgs:  []string{"first", "a", "b", "<notice 2>", "later"},
		},
		"success: Close reports drops that nothing follows": {
			queueSize: 2,
			close:     true,
			wantMsgs:  []string{"first", "a", "b", "<notice 2>"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := &collector{gate: make(chan struct{}), started: make(chan struct{})}
			h := NewLogHandler(c.deliver, LogHandlerOptions{QueueSize: tt.queueSize})
			handle := func(msg string) {
				t.Helper()
				if err := h.Handle(t.Context(), record(slog.LevelInfo, msg)); err != nil {
					t.Fatalf("Handle: %v", err)
				}
			}

			// "first" is held in delivery; a and b fill the queue, which
			// holds at least two entries; c and d are dropped.
			handle("first")
			<-c.started
			for _, m := range []string{"a", "b", "c", "d"} {
				handle(m)
			}

			released := make(chan struct{})
			go func() {
				defer close(released)
				c.gate <- struct{}{} // first
				for range c.started {
					c.gate <- struct{}{}
				}
			}()

			within(t, "draining", func() {
				if tt.close {
					closeHandler(t, h)
					return
				}
				if err := h.Flush(t.Context()); err != nil {
					t.Errorf("Flush: %v", err)
				}
				handle("later")
				if err := h.Flush(t.Context()); err != nil {
					t.Errorf("Flush: %v", err)
				}
			})
			close(c.started)
			<-released
			if !tt.close {
				closeHandler(t, h)
			}

			var msgs []string
			for _, e := range c.got() {
				_, msg, _ := strings.Cut(e.Msg, "] ")
				if count, ok := strings.CutPrefix(msg, "dropped "); ok && e.Level == slog.LevelWarn {
					n, _, _ := strings.Cut(count, " ")
					msg = "<notice " + n + ">"
				}
				msgs = append(msgs, msg)
			}
			if diff := cmp.Diff(tt.wantMsgs, msgs); diff != "" {
				t.Errorf("delivered messages (-want +got):\n%s", diff)
			}
		})
	}
}
