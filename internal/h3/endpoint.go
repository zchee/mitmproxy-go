// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// Endpoint owns bounded HTTP/3 stream queues independently of live flows.
// QUIC owns transport flow control; DATA reservations last until consumption.
// The caller closes the borrowed QUIC connection after Run returns.
type Endpoint struct {
	conn            *quicConnection
	cfg             Config
	running         atomic.Bool
	mu              sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	err             error
	graceful        bool
	draining        bool
	started         chan struct{}
	ready           chan struct{}
	done            chan struct{}
	failed          chan struct{}
	changed         chan struct{}
	workers         sync.WaitGroup
	streams         map[uint64]*requestState
	opening         int
	goAwayWrites    int
	notifications   chan Event
	receiveLock     chan struct{}
	controlLock     chan struct{}
	control         *outgoingUniStream
	locals          []*outgoingUniStream
	incoming        map[uint64]*incomingUniStream
	critical        map[uint64]bool
	peerSettings    bool
	initialized     bool
	peerHeaderLimit uint64
	peerGoAway      uint64
	nextRejected    uint64
}

// Done closes after all owned I/O and receipt cleanup have finished.
func (e *Endpoint) Done() <-chan struct{} { return e.done }

// Run initializes critical streams and drives the protocol exactly once.
// Cancellation interrupts owned streams without closing the caller's transport.
func (e *Endpoint) Run(ctx context.Context) error {
	if !e.running.CompareAndSwap(false, true) {
		return errors.New("h3: Run called more than once")
	}
	e.mu.Lock()
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.incoming = make(map[uint64]*incomingUniStream)
	e.critical = make(map[uint64]bool)
	close(e.started)
	e.mu.Unlock()
	connectionStopped := make(chan struct{})
	stopConnection := context.AfterFunc(e.conn.context(), func() {
		e.fail(connectionTransportError(context.Cause(e.conn.context())))
		close(connectionStopped)
	})
	ioStopped := make(chan struct{})
	stopIO := context.AfterFunc(e.ctx, func() { e.interruptIO(); close(ioStopped) })
	e.workers.Go(e.acceptRequests)
	e.workers.Go(e.acceptUnidirectional)
	if err := e.initialize(); err != nil {
		e.fail(err)
	}
	<-e.ctx.Done()
	e.mu.Lock()
	if e.err == nil && !e.graceful {
		e.err = e.ctx.Err()
	}
	endErr := e.err
	e.mu.Unlock()
	e.interruptIO()
	// A callback which has begun must also finish before the borrowed connection
	// lifetime ends. WaitGroup accounting is protected by the endpoint mutex.
	if !stopConnection() {
		<-connectionStopped
	}
	if !stopIO() {
		<-ioStopped
	}
	e.workers.Wait()
	close(e.done)
	return endErr
}

func (e *Endpoint) interruptIO() {
	e.mu.Lock()
	states := make([]*requestState, 0, len(e.streams))
	for _, s := range e.streams {
		states = append(states, s)
	}
	for _, stream := range e.locals {
		if e.graceful {
			interruptCriticalStreams(nil, stream)
		} else {
			cancelOutgoingUni(stream, ErrCodeRequestCancelled)
		}
	}
	for _, stream := range e.incoming {
		if e.graceful {
			interruptCriticalStreams(stream, nil)
		} else {
			cancelIncomingUni(stream, ErrCodeRequestCancelled)
		}
	}
	err := e.err
	e.mu.Unlock()
	for _, s := range states {
		s.fail(ErrCodeRequestCancelled, err)
	}
}

func (e *Endpoint) initialize() error {
	for _, kind := range []uint64{0, 2, 3} {
		stream, err := e.conn.openUniStream(e.ctx)
		if err != nil {
			return err
		}
		e.mu.Lock()
		e.locals = append(e.locals, stream)
		stopped := e.ctx.Err() != nil
		e.mu.Unlock()
		if stopped {
			cancelOutgoingUni(stream, ErrCodeRequestCancelled)
			return e.ctx.Err()
		}
		if _, err := stream.Write(appendVarint(nil, kind)); err != nil {
			return err
		}
		if kind == 0 {
			settings := appendVarint(nil, 1)
			settings = appendVarint(settings, 0)
			settings = appendVarint(settings, 6)
			settings = appendVarint(settings, MaxHeaderBytes)
			settings = appendVarint(settings, 7)
			settings = appendVarint(settings, 0)
			if err := writeFrame(stream, frameSettings, settings); err != nil {
				return err
			}
			e.mu.Lock()
			e.control = stream
			e.signalLocked()
			e.mu.Unlock()
		}
	}
	e.mu.Lock()
	e.initialized = true
	e.signalLocked()
	e.mu.Unlock()
	return nil
}

func (e *Endpoint) fail(err error) {
	if err == nil {
		err = io.EOF
	}
	e.mu.Lock()
	if e.ctx.Err() != nil || e.err != nil {
		e.mu.Unlock()
		return
	}
	e.err = err
	// Notify consumers before CloseWithError waits for transport context
	// publication. Critical-stream cancellation still follows the wire close.
	close(e.failed)
	e.mu.Unlock()
	if failure, ok := errors.AsType[*ConnectionError](err); ok {
		e.cfg.Logger.Debug("HTTP/3 connection failed", "code", failure.Code.String(), "error", failure.Message)
		// Establish the application close code before cancellation can reset a
		// critical stream and make the peer report a different protocol failure.
		_ = e.conn.closeWithError(uint64(failure.Code))
	}
	e.mu.Lock()
	e.cancel()
	e.signalLocked()
	e.mu.Unlock()
}

func (e *Endpoint) signalLocked() { close(e.changed); e.changed = make(chan struct{}) }

func take(ctx context.Context, lock chan struct{}, stopped <-chan struct{}) error {
	select {
	case lock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-stopped:
		return io.EOF
	}
}

func (e *Endpoint) waitStarted(ctx context.Context) error {
	select {
	case <-e.started:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-e.done:
		return e.endError()
	}
}

// Receive delivers new server request heads and connection notifications to one
// consumer. Backpressure on a request body cannot block other requests.
func (e *Endpoint) Receive(ctx context.Context) (Event, error) {
	if err := e.waitStarted(ctx); err != nil {
		return Event{}, err
	}
	if err := take(ctx, e.receiveLock, e.done); err != nil {
		if errors.Is(err, io.EOF) {
			return Event{}, e.endError()
		}
		return Event{}, err
	}
	defer func() { <-e.receiveLock }()
	var event Event
	select {
	case <-e.failed:
		return Event{}, e.endError()
	default:
	}
	select {
	case event = <-e.notifications:
	default:
		select {
		case event = <-e.notifications:
		case <-ctx.Done():
			return Event{}, ctx.Err()
		case <-e.failed:
			return Event{}, e.endError()
		case <-e.done:
			return Event{}, e.endError()
		}
	}
	if event.Kind == Headers {
		e.mu.Lock()
		e.nextRejected = max(e.nextRejected, event.Identity.Stream+4)
		e.mu.Unlock()
	}
	return event, nil
}

func (e *Endpoint) notify(event Event) bool {
	select {
	case e.notifications <- event:
		return true
	default:
		e.fail(connectionError(ErrCodeExcessiveLoad, "connection notification queue full"))
		return false
	}
}

func (e *Endpoint) endError() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return e.err
	}
	return io.EOF
}

func (e *Endpoint) lookup(id layer.StreamIdentity) (*requestState, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if id.Endpoint == e.cfg.Descriptor.Identity {
		if s := e.streams[id.Stream]; s != nil {
			return s, nil
		}
	}
	return nil, &StreamError{Identity: id, Code: ErrCodeRequestCancelled, Message: "unknown or foreign stream"}
}

// ReceiveStream delivers ordered events; settle a DATA receipt before borrowing
// the next chunk. Cancellation and reset wake blocked receivers. Received
// trailers do not imply FIN: their EndStream is false. Actual EOF is delivered
// as a synthetic zero-byte Data event with EndStream true and a receipt which
// must be settled normally. This event is not a peer DATA frame. Consumers must
// wait for this terminal event before treating a headers-only or trailer-ended
// message as complete.
func (e *Endpoint) ReceiveStream(ctx context.Context, id layer.StreamIdentity) (Event, error) {
	s, err := e.lookup(id)
	if err != nil {
		return Event{}, err
	}
	if err := take(ctx, s.receiveLock, e.done); err != nil {
		if errors.Is(err, io.EOF) {
			return Event{}, e.endError()
		}
		return Event{}, err
	}
	defer func() { <-s.receiveLock }()
	for {
		s.mu.Lock()
		if s.failure != nil {
			failure := s.failure
			first := !s.resetDelivered
			s.resetDelivered = true
			s.mu.Unlock()
			e.retire(s)
			if first {
				return Event{Kind: Reset, Identity: id, Code: failure.Code, Err: failure}, nil
			}
			return Event{}, failure
		}
		if s.receipt == nil && len(s.events) != 0 {
			event := s.events[0]
			s.events[0] = Event{}
			s.events = s.events[1:]
			if event.Kind == Data {
				receipt, receiptErr := layer.NewConsumptionReceipt(len(event.Data))
				if receiptErr != nil {
					s.mu.Unlock()
					return Event{}, receiptErr
				}
				s.receipt = receipt
				event.Receipt = receipt
				e.mu.Lock()
				if e.ctx.Err() != nil {
					e.mu.Unlock()
					receipt.Invalidate()
					s.mu.Unlock()
					return Event{}, e.endError()
				}
				e.workers.Go(func() {
					select {
					case <-receipt.Done():
					case <-e.ctx.Done():
						receipt.Invalidate()
					}
					s.mu.Lock()
					if s.receipt == receipt {
						s.receipt = nil
						s.bytes -= receipt.OriginalBytes()
						s.signalLocked()
					}
					s.mu.Unlock()
					e.retire(s)
				})
				e.mu.Unlock()
			}
			s.signalLocked()
			s.mu.Unlock()
			e.retire(s)
			return event, nil
		}
		if s.remoteEnd && s.receipt == nil && len(s.events) == 0 {
			s.mu.Unlock()
			return Event{}, io.EOF
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return Event{}, ctx.Err()
		case <-e.failed:
			return Event{}, e.endError()
		case <-e.done:
			return Event{}, e.endError()
		}
	}
}

// OpenStream waits for peer SETTINGS and transport admission in client mode.
// Allocation writes no HTTP bytes; GOAWAY returns ErrDraining.
func (e *Endpoint) OpenStream(ctx context.Context) (layer.StreamIdentity, error) {
	if !e.cfg.Client {
		return layer.StreamIdentity{}, errors.New("h3: server cannot open a request stream")
	}
	if err := e.waitStarted(ctx); err != nil {
		return layer.StreamIdentity{}, err
	}
	for {
		e.mu.Lock()
		if e.draining {
			e.mu.Unlock()
			return layer.StreamIdentity{}, ErrDraining
		}
		if e.ctx.Err() != nil {
			e.mu.Unlock()
			return layer.StreamIdentity{}, e.endError()
		}
		if e.peerSettings && e.initialized && len(e.streams)+e.opening < MaxConcurrentStreams {
			e.opening++
			e.workers.Add(1)
			e.mu.Unlock()
			break
		}
		changed := e.changed
		e.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return layer.StreamIdentity{}, ctx.Err()
		case <-e.done:
			return layer.StreamIdentity{}, e.endError()
		}
	}
	defer e.workers.Done()
	openCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.ctx, cancel)
	defer func() { stop(); cancel() }()
	wire, err := e.conn.openStream(openCtx)
	e.mu.Lock()
	e.opening--
	e.signalLocked()
	if err != nil {
		e.mu.Unlock()
		return layer.StreamIdentity{}, err
	}
	if e.draining || e.ctx.Err() != nil {
		e.mu.Unlock()
		cancelRequestStream(wire, ErrCodeRequestRejected)
		return layer.StreamIdentity{}, ErrDraining
	}
	s := newRequestState(e, wire)
	e.streams[s.id.Stream] = s
	e.workers.Go(func() { e.readRequest(s) })
	e.workers.Go(func() { e.watchWriteSide(s) })
	e.mu.Unlock()
	return s.id, nil
}

// CancelStream cancels both directions and invalidates receipts without waiting
// for network I/O. Repeated cancellation of a closed identity is harmless.
func (e *Endpoint) CancelStream(id layer.StreamIdentity, code ErrorCode) error {
	s, err := e.lookup(id)
	if err != nil {
		return nil
	}
	s.fail(code, &StreamError{Identity: id, Code: code, Message: "stream cancelled"})
	return nil
}

// StreamDone observes reset, cancellation, normal completion or connection stop.
// Unknown and foreign identities return an already-closed channel.
func (e *Endpoint) StreamDone(id layer.StreamIdentity) <-chan struct{} {
	if s, err := e.lookup(id); err == nil {
		return s.done
	}
	done := make(chan struct{})
	close(done)
	return done
}

// StreamFailed observes unsuccessful completion only. Register while the stream
// is live; unknown and foreign identities return an already-closed channel.
func (e *Endpoint) StreamFailed(id layer.StreamIdentity) <-chan struct{} {
	if s, err := e.lookup(id); err == nil {
		return s.failed
	}
	failed := make(chan struct{})
	close(failed)
	return failed
}

func (e *Endpoint) retire(s *requestState) {
	s.mu.Lock()
	finished := s.failure != nil && (s.resetDelivered || !e.cfg.Client && !s.announced) || s.failure == nil && s.localEnd && s.remoteEnd && len(s.events) == 0 && s.receipt == nil && s.bytes == 0
	if finished && !s.doneClosed {
		close(s.done)
		s.doneClosed = true
	}
	s.mu.Unlock()
	if !finished {
		return
	}
	e.mu.Lock()
	if e.streams[s.id.Stream] == s {
		delete(e.streams, s.id.Stream)
		e.signalLocked()
	}
	if e.draining && len(e.streams) == 0 && e.opening == 0 && e.goAwayWrites == 0 && e.ctx.Err() == nil {
		e.graceful = true
		e.cancel()
	}
	e.mu.Unlock()
}
