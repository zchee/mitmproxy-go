// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// Endpoint owns an independent HTTP/2 state table, receive budget, HPACK
// decoder and encoder. Run owns protocol state; a separate serialized writer
// keeps the socket reader independent of stalled stream consumers. SETTINGS
// are acknowledged and peer frame, table, concurrency and window limits obeyed.
// PUSH_PROMISE is rejected. Receive and ReceiveStream never access live flows.
// The caller owns conn and closes it after Run returns.
type Endpoint struct {
	conn     net.Conn
	cfg      Config
	requests chan *request
	wake     chan struct{}
	done     chan struct{}
	started  atomic.Bool
	draining atomic.Bool
	budget   atomic.Pointer[layer.BudgetSnapshot]
	failure  atomic.Pointer[result]
}

// New copies cfg and constructs an endpoint without I/O. A nil connection,
// empty endpoint identity or negative keepalive interval is rejected. Upgrade
// must be server-side with valid SETTINGS, request headers and a complete body
// no larger than InitialStreamWindow. The borrowed connection is never closed.
func New(conn net.Conn, cfg Config) (*Endpoint, error) {
	if conn == nil || cfg.Descriptor.Identity == "" || cfg.PingKeepalive < 0 {
		return nil, errors.New("h2: invalid endpoint configuration")
	}
	if err := validateUpgrade(&cfg); err != nil {
		return nil, err
	}
	if cfg.Clock == nil {
		cfg.Clock = layer.WallClock
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	e := &Endpoint{conn: conn, cfg: cfg, requests: make(chan *request), wake: make(chan struct{}, 1), done: make(chan struct{})}
	e.budget.Store(new(layer.BudgetSnapshot))
	return e, nil
}

// Done closes after Run has stopped all readers/writers and released its
// receive chunks, reservations and outstanding receipts.
func (e *Endpoint) Done() <-chan struct{} { return e.done }

// StreamDone observes termination without consuming stream events. Its channel
// closes on reset, cancellation, received GOAWAY exclusion, normal completion,
// or connection termination. Unknown, foreign and closed identities return an
// already-closed channel. Run must be active when observing a live stream.
func (e *Endpoint) StreamDone(id layer.StreamIdentity) <-chan struct{} {
	r := newRequest(context.TODO(), streamDone)
	r.id = id
	if e.started.Load() {
		if _, err := e.call(r); err == nil && r.done != nil {
			return r.done
		}
	}
	done := make(chan struct{})
	close(done)
	return done
}

// StreamFailed observes unsuccessful stream termination without consuming events.
// Its channel closes on reset, cancellation, GOAWAY exclusion or connection
// failure, but stays open on successful completion. Register it while the stream
// is live; unknown and foreign identities return an already-closed channel.
func (e *Endpoint) StreamFailed(id layer.StreamIdentity) <-chan struct{} {
	r := newRequest(context.TODO(), streamFailed)
	r.id = id
	if e.started.Load() {
		if _, err := e.call(r); err == nil && r.done != nil {
			return r.done
		}
	}
	done := make(chan struct{})
	close(done)
	return done
}

// Budget returns a synchronized immutable observation of reservations and
// their maximum. The owner asserts the budget on every grant/release.
func (e *Endpoint) Budget() layer.BudgetSnapshot { return *e.budget.Load() }

func (e *Endpoint) signal() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (e *Endpoint) call(r *request) (Event, error) {
	select {
	case e.requests <- r:
	case <-r.ctx.Done():
		return Event{}, r.ctx.Err()
	case <-e.done:
		return Event{}, e.endError()
	}
	stop := context.AfterFunc(r.ctx, e.signal)
	defer stop()
	// Do not return while a writer can still hold a borrowed DATA slice.
	select {
	case result := <-r.result:
		return result.event, result.err
	case <-e.done:
		select {
		case result := <-r.result:
			return result.event, result.err
		default:
			return Event{}, e.endError()
		}
	}
}

func (e *Endpoint) endError() error {
	if failure := e.failure.Load(); failure != nil && failure.err != nil {
		return failure.err
	}
	return io.EOF
}

// Receive delivers new server-side request heads and connection GOAWAY/error
// events to one connection owner. DATA for stalled streams does not block it.
// Client-side responses belong to ReceiveStream of the OpenStream identity.
func (e *Endpoint) Receive(ctx context.Context) (Event, error) {
	return e.call(newRequest(ctx, receive))
}

// ReceiveStream delivers ordered stream events to one consumer. At most one
// DATA chunk is outstanding: settle its receipt before requesting the next.
// Small DATA frames append to one ChunkSize tail while the consumer is busy.
// CancelStream, peer reset and connection failure wake blocked receivers.
func (e *Endpoint) ReceiveStream(ctx context.Context, id layer.StreamIdentity) (Event, error) {
	r := newRequest(ctx, receiveStream)
	r.id = id
	return e.call(r)
}

// OpenStream allocates a monotonic odd stream identity in client mode. It waits
// for the peer's first SETTINGS and its concurrent-stream limit. An omitted
// limit is capped at MaxConcurrentStreams. Context cancellation wakes it.
// Opening after received GOAWAY returns ErrDraining without writing request bytes.
// Opening after locally sent GOAWAY also fails. Initial request HEADERS are
// written in stream-id order: a higher stream waits until all lower allocated
// streams have dispatched initial HEADERS or been cancelled. Call CancelStream
// for an allocated stream that will not send initial HEADERS.
func (e *Endpoint) OpenStream(ctx context.Context) (layer.StreamIdentity, error) {
	if e.draining.Load() {
		return layer.StreamIdentity{}, ErrDraining
	}
	event, err := e.call(newRequest(ctx, openStream))
	if err != nil && e.draining.Load() {
		err = ErrDraining
	}
	return event.Identity, err
}

// Send accepts Headers, Informational, Data and Trailers. It borrows all event
// data until return, serializes each stream and re-frames DATA to peer limits.
// Success means socket-written, never merely queued. It waits for both stream
// and connection credit; cancellation wakes stalled sends. Unknown, foreign
// and closed streams return StreamError. Header normalization is the caller's.
// In client mode, initial request HEADERS are written in stream-id order. A Send
// on a higher locally allocated stream waits until every lower allocated stream
// has dispatched its initial HEADERS or been cancelled. Call CancelStream for
// an allocated stream that will not send initial HEADERS.
func (e *Endpoint) Send(ctx context.Context, event Event) error {
	r := newRequest(ctx, send)
	r.event = event
	r.id = event.Identity
	_, err := e.call(r)
	return err
}

// WaitSendCredit waits for positive stream and connection credit and an empty
// send buffer. For streamed input, call this on the destination before the
// source ReceiveStream; that call authorizes transfer of a partial tail. Then
// Send its transformed output and settle the source receipt. Hook-buffered
// input drains ReceiveStream without this wait and completes after body append.
func (e *Endpoint) WaitSendCredit(ctx context.Context, id layer.StreamIdentity) error {
	r := newRequest(ctx, waitSendCredit)
	r.id = id
	_, err := e.call(r)
	return err
}

// CancelStream invalidates receipts, releases chunks/reservations and wakes
// blocked senders once. It queues RST_STREAM without waiting for socket I/O
// only if the stream has started on the wire; no stream WINDOW_UPDATE is
// emitted after cancellation.
func (e *Endpoint) CancelStream(id layer.StreamIdentity, code http2.ErrCode) error {
	r := newRequest(context.TODO(), cancelStream)
	r.id = id
	r.code = code
	_, err := e.call(r)
	return err
}

// Shutdown writes GOAWAY with the last processed peer stream and disallows new
// streams. Run finishes when existing streams drain or ctx ends. It borrows
// debug until return; cancellation of a partial write ends the connection.
// Active writes and the following GOAWAY share GoAwayFlushGrace on Clock;
// expiration interrupts a stalled writer with a typed timeout that ends Run.
func (e *Endpoint) Shutdown(ctx context.Context, code http2.ErrCode, debug []byte) error {
	r := newRequest(ctx, shutdown)
	r.code = code
	r.debug = debug
	_, err := e.call(r)
	return err
}

type readFrame struct {
	frame    http2.Frame
	err      error
	accepted chan struct{}
}

// Run performs the role-specific preface and drives the protocol exactly once.
// Keepalive uses the injected clock, sends the upstream opaque eight zeroes,
// and repeats after inactivity without imposing an extra ping-ACK timeout.
// Incoming GOAWAY is reported and streams above LastStreamID are cancelled;
// the remaining streams may drain. Context cancellation interrupts borrowed
// transport I/O by deadlines and invalidates all outstanding receipts.
func (e *Endpoint) Run(ctx context.Context) error {
	if !e.started.CompareAndSwap(false, true) {
		return errors.New("h2: Run called more than once")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	reads := make(chan readFrame)
	writes := make(chan *writeFrame)
	written := make(chan writeResult, 1)
	var workers sync.WaitGroup
	ioStopped := make(chan struct{})
	stopIO := context.AfterFunc(ctx, func() {
		_ = e.conn.SetDeadline(time.Unix(1, 0))
		close(ioStopped)
	})
	workers.Go(func() { e.readFrames(ctx, reads) })
	workers.Go(func() { e.writeFrames(ctx, writes, written) })
	o := newOwner(e, ctx)
	err := o.run(reads, writes, written)
	cancel()
	// The callback may already be running; an explicit deadline also closes
	// the gap before waiting for the workers that borrow the connection.
	_ = e.conn.SetDeadline(time.Unix(1, 0))
	workers.Wait()
	// The deadline callback must not outlive Run's borrowed connection lifetime.
	if !stopIO() {
		<-ioStopped
	}
	o.closeAll(err)
	e.failure.Store(&result{err: err})
	close(e.done)
	return err
}

func (e *Endpoint) readFrames(ctx context.Context, out chan<- readFrame) {
	if !e.cfg.Client {
		preface := make([]byte, len(http2.ClientPreface))
		_, err := io.ReadFull(e.conn, preface)
		if err == nil && string(preface) != http2.ClientPreface {
			err = protocolError(http2.ErrCodeProtocol, "Invalid HTTP/2 client preface")
		}
		if err != nil {
			select {
			case out <- readFrame{err: err}:
			case <-ctx.Done():
			}
			return
		}
	}
	framer := http2.NewFramer(nil, e.conn)
	framer.AllowIllegalReads = true
	framer.SetMaxReadFrameSize(MaxFrameSize)
	framer.SetReuseFrames()
	for {
		frame, err := framer.ReadFrame()
		accepted := make(chan struct{})
		select {
		case out <- readFrame{frame: frame, err: err, accepted: accepted}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			if _, ok := errors.AsType[http2.StreamError](err); ok {
				continue
			}
			return
		}
		select {
		case <-accepted:
		case <-ctx.Done():
			return
		}
	}
}
