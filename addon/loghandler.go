// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package addon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// DefaultLogQueueSize is the number of entries a [LogHandler] holds for
// delivery when [LogHandlerOptions.QueueSize] is zero.
const DefaultLogQueueSize = 1024

// ErrLogHandlerClosed reports a call to [LogHandler.Flush] after
// [LogHandler.Close].
var ErrLogHandlerClosed = errors.New("addon: log handler is closed")

// LogHandlerOptions configures a [LogHandler].
type LogHandlerOptions struct {
	// Level is the minimum level the handler accepts. A nil Level accepts
	// every record, as mitmproxy's handler, which has no level of its own,
	// does.
	Level slog.Leveler

	// QueueSize bounds the number of entries waiting for delivery. Zero
	// means [DefaultLogQueueSize]. Sizes below 2 are raised to 2, the room
	// a drop notice and the entry after it need.
	QueueSize int
}

// LogHandler is a [slog.Handler] that turns each record into a [LogEntry]
// and hands it to a delivery function on a goroutine of its own. The master
// installs one whose delivery function dispatches the add_log hook.
//
// Delivery is asynchronous, as mitmproxy schedules add_log on its event
// loop instead of running it inside the logging call. Logging from inside a
// hook therefore never waits for the dispatch lock that hook already holds,
// and never waits for the addons that consume the entries.
//
// The queue is bounded. When it is full, a new record is dropped instead of
// blocking the logging goroutine, and the handler counts it. The count is
// delivered as one entry at [slog.LevelWarn] saying how many entries were
// dropped, so a consumer can tell that its log has a gap. The notice is
// queued as soon as there is room for it and the entry being logged, or
// when the queue has drained, whichever comes first; it is therefore
// delivered after the entries queued before the drops and before any entry
// logged after them, also when the drops were the last thing logged before
// [LogHandler.Flush] or [LogHandler.Close].
//
// An addon that logs from its add_log hook feeds the queue again for each
// entry, which loops for as long as it keeps doing so; mitmproxy documents
// the same hazard. The bound keeps the loop from growing memory.
type LogHandler struct {
	h      *logHandlerCore
	attrs  string // attributes preformatted by WithAttrs, with a leading space
	prefix string // group prefix for attribute keys, ending in "."
}

// logHandlerCore is the state the handlers derived with WithAttrs and
// WithGroup share with the one NewLogHandler returned.
type logHandlerCore struct {
	deliver func(context.Context, LogEntry)
	level   slog.Leveler

	mu        sync.Mutex
	cond      *sync.Cond // signalled when queued entries arrive, are delivered, or the handler closes
	queue     []LogEntry // ring buffer
	head, n   int
	enqueued  uint64 // entries accepted, including drop notices
	delivered uint64
	dropped   uint64 // records dropped since the last drop notice was queued
	closed    bool
	done      chan struct{} // closed when the delivery goroutine returns
}

// NewLogHandler returns a handler that delivers entries to deliver, one at a
// time and in the order they were logged, on a goroutine it starts. deliver
// receives a context without a dispatch frame. It must not panic: there is
// no caller to recover the panic for, so it would end the process; the
// add_log dispatch recovers addon panics itself. Call [LogHandler.Close] to
// stop the goroutine.
func NewLogHandler(deliver func(ctx context.Context, e LogEntry), opts LogHandlerOptions) *LogHandler {
	size := opts.QueueSize
	if size == 0 {
		size = DefaultLogQueueSize
	}
	size = max(size, 2)
	c := &logHandlerCore{
		deliver: deliver,
		level:   opts.Level,
		queue:   make([]LogEntry, size),
		done:    make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mu)
	go c.run()
	return &LogHandler{h: c}
}

// Enabled implements [slog.Handler].
func (l *LogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return l.h.level == nil || level >= l.h.level.Level()
}

// Handle implements [slog.Handler]. It never blocks on delivery: the entry
// is queued, or dropped and counted when the queue is full. Records logged
// after [LogHandler.Close] are discarded.
//
// The entry's message follows mitmproxy's log format without colour:
// "[15:04:05.000] message", or "[15:04:05.000][client] message" when the
// record has a "client" attribute, followed by the record's other
// attributes as key=value pairs.
func (l *LogHandler) Handle(_ context.Context, r slog.Record) error {
	l.h.enqueue(LogEntry{Msg: l.format(r), Level: r.Level})
	return nil
}

// WithAttrs implements [slog.Handler].
func (l *LogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return l
	}
	var b strings.Builder
	b.WriteString(l.attrs)
	for _, a := range attrs {
		appendAttr(&b, l.prefix, a)
	}
	return &LogHandler{h: l.h, attrs: b.String(), prefix: l.prefix}
}

// WithGroup implements [slog.Handler].
func (l *LogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return l
	}
	return &LogHandler{h: l.h, attrs: l.attrs, prefix: l.prefix + name + "."}
}

// Flush waits until every entry queued before the call has been delivered,
// or until ctx is done. It must not be called while holding the dispatch
// lock, because delivery dispatches add_log, which needs that lock.
func (l *LogHandler) Flush(ctx context.Context) error {
	c := l.h
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrLogHandlerClosed
	}
	target := c.enqueued
	if c.dropped > 0 {
		// While drops are pending, the next entry queued is always their
		// notice, so waiting for it covers drops that nothing follows.
		target++
	}
	c.mu.Unlock()
	return c.waitFor(ctx, func() bool { return c.delivered >= target })
}

// Close stops accepting records, waits until the entries already queued
// have been delivered and the delivery goroutine has returned, or until ctx
// is done. After a successful Close the handler starts no more deliveries.
// Calling Close again is allowed.
func (l *LogHandler) Close(ctx context.Context) error {
	c := l.h
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// waitFor blocks until cond holds (checked with c.mu held) or ctx is done.
func (c *logHandlerCore) waitFor(ctx context.Context, cond func() bool) error {
	// sync.Cond cannot wait on a context, so a cancelled context wakes the
	// waiters through a broadcast.
	stop := context.AfterFunc(ctx, func() {
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
	})
	defer stop()

	c.mu.Lock()
	defer c.mu.Unlock()
	for !cond() {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.cond.Wait()
	}
	return nil
}

// enqueue adds e to the queue, or counts it as dropped when the queue is
// full. A pending drop notice is queued ahead of e when there is room for
// both; otherwise e is dropped too, so that the notice keeps its place
// ahead of every entry logged after the drops.
func (c *logHandlerCore) enqueue(e LogEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if c.dropped > 0 {
		if len(c.queue)-c.n < 2 {
			c.dropped++
			return
		}
		c.pushNotice()
	}
	if c.n == len(c.queue) {
		c.dropped++
		return
	}
	c.push(e)
}

// pushNotice queues the notice for the pending drops. It is called with c.mu
// held, c.dropped > 0 and room in the queue.
func (c *logHandlerCore) pushNotice() {
	c.push(LogEntry{
		Msg:   fmt.Sprintf("[%s] dropped %d log entries because the add_log queue was full", formatLogTime(time.Now()), c.dropped),
		Level: slog.LevelWarn,
	})
	c.dropped = 0
}

// push appends e to the ring buffer, which must have room. It is called with
// c.mu held.
func (c *logHandlerCore) push(e LogEntry) {
	c.queue[(c.head+c.n)%len(c.queue)] = e
	c.n++
	c.enqueued++
	c.cond.Broadcast()
}

// run delivers queued entries until the handler is closed and the queue is
// empty. When the queue drains while drops are pending, it queues their
// notice itself, so drops that no later record follows are still reported.
func (c *logHandlerCore) run() {
	defer close(c.done)
	ctx := context.Background()
	c.mu.Lock()
	for {
		for c.n == 0 {
			if c.dropped > 0 {
				c.pushNotice()
				break
			}
			if c.closed {
				c.mu.Unlock()
				return
			}
			c.cond.Wait()
		}
		e := c.queue[c.head]
		c.queue[c.head] = LogEntry{}
		c.head = (c.head + 1) % len(c.queue)
		c.n--
		c.mu.Unlock()

		c.deliver(ctx, e)

		c.mu.Lock()
		c.delivered++
		c.cond.Broadcast()
	}
}

// format renders r in mitmproxy's uncoloured log format.
func (l *LogHandler) format(r slog.Record) string {
	var (
		b      strings.Builder
		client string
		rest   strings.Builder
	)
	r.Attrs(func(a slog.Attr) bool {
		if l.prefix == "" && a.Key == "client" && client == "" {
			client = a.Value.Resolve().String()
			return true
		}
		appendAttr(&rest, l.prefix, a)
		return true
	})

	b.WriteString("[")
	b.WriteString(formatLogTime(r.Time))
	b.WriteString("]")
	if client != "" {
		b.WriteString("[")
		b.WriteString(client)
		b.WriteString("]")
	}
	b.WriteString(" ")
	b.WriteString(r.Message)
	b.WriteString(l.attrs)
	b.WriteString(rest.String())
	return b.String()
}

// formatLogTime formats t as mitmproxy's log formatter does: local time with
// milliseconds. A zero t, which slog uses for records without a time, is
// formatted as the current time, as Python stamps every record when it is
// created.
func formatLogTime(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	return t.Format("15:04:05.000")
}

// appendAttr writes a as " key=value", flattening groups into dotted keys.
func appendAttr(b *strings.Builder, prefix string, a slog.Attr) {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "."
		}
		for _, ga := range v.Group() {
			appendAttr(b, p, ga)
		}
		return
	}
	if a.Equal(slog.Attr{}) {
		return
	}
	b.WriteString(" ")
	b.WriteString(prefix)
	b.WriteString(a.Key)
	b.WriteString("=")
	b.WriteString(v.String())
}
