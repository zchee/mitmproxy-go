// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"context"
	"errors"
	"io"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

const maxQueuedEvents = 64

type queuedEvent struct {
	event    Event
	original int
}

type streamState struct {
	id             layer.StreamIdentity
	done           chan struct{}
	failureDone    chan struct{}
	window         streamWindow
	outWindow      int64
	queue          []queuedEvent
	receiver       *request
	sender         *request
	creditWaiter   *request
	offset         int
	inHeaders      bool
	outHeaders     bool
	wireStarted    bool
	remoteEnd      bool
	localEnd       bool
	failed         error
	receipt        *consumption
	contentLength  int64
	received       int64
	requestMethod  string
	responseStatus string
}

func (s *streamState) closeFailure() {
	select {
	case <-s.failureDone:
	default:
		close(s.failureDone)
	}
}

func (s *streamState) closeDone() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

type consumption struct {
	*layer.Receipt
	wake func()
}

// Complete marks the payload consumed once and wakes the endpoint only if completion wins.
func (r *consumption) Complete() bool {
	won := r.Receipt.Complete()
	if won {
		r.wake()
	}
	return won
}

// Invalidate abandons the payload once and wakes the endpoint only if invalidation wins.
func (r *consumption) Invalidate() bool {
	won := r.Receipt.Invalidate()
	if won {
		r.wake()
	}
	return won
}

type owner struct {
	e                *Endpoint
	ctx              context.Context
	streams          map[uint32]*streamState
	order            []uint32
	cursor           int
	budget           windowBudget
	assembly         *headerAssembly
	headEnd          bool
	connectionEvents []Event
	receiver         *request
	opens            []*request
	controls         []*writeFrame
	credits          map[uint32]uint32
	active           *writeFrame
	prepared         *writeFrame
	peerSettings     bool
	peerConcurrent   uint32
	peerInitial      int64
	peerFrame        uint32
	peerHeaders      uint32
	outWindow        int64
	lastPeer         uint32
	lastLocal        uint32
	nextLocal        uint32
	goaway           bool
	shutdown         bool
	shutdownDone     <-chan struct{}
	fatal            error
	fatalSent        bool
	lastActivity     time.Time
	stopPing         func() bool
	pingTicks        chan struct{}
	headDeadline     time.Time
	headStage        string
	stopHead         func() bool
	flushDeadline    time.Time
	stopFlush        func() bool
	flushError       error
	abortError       error
}

func newOwner(e *Endpoint, ctx context.Context) *owner {
	o := &owner{e: e, ctx: ctx, streams: make(map[uint32]*streamState), assembly: newHeaderAssembly(e.cfg.ValidateInboundHeaders), credits: make(map[uint32]uint32), peerConcurrent: MaxConcurrentStreams, peerInitial: 65535, peerFrame: 16384, peerHeaders: ^uint32(0), outWindow: 65535, nextLocal: 1, controls: []*writeFrame{{kind: writeInitial}}, lastActivity: e.cfg.Clock.Now()}
	if e.cfg.Upgrade != nil {
		o.seedUpgrade()
	}
	return o
}

func (o *owner) publish() { o.e.budget.Store(new(o.budget.snapshot())) }

func (o *owner) run(reads <-chan readFrame, writes chan<- *writeFrame, written <-chan writeResult) error {
	o.startHead("preface")
	defer o.finishHead()
	defer o.finishFlush()
	if o.e.cfg.Client && o.e.cfg.PingKeepalive > 0 {
		o.pingTicks = make(chan struct{}, 1)
		o.schedulePing(o.e.cfg.PingKeepalive)
	}
	defer func() {
		if o.stopPing != nil {
			o.stopPing()
		}
	}()
	for {
		o.settle()
		if o.abortError != nil {
			return o.abortError
		}
		o.fulfill()
		if o.shutdown {
			o.settle()
		}
		if o.shutdown && o.budget.streams == 0 && o.active == nil && o.prepared == nil && len(o.controls) == 0 && (!o.e.draining.Load() || len(o.streams) == 0 && len(o.connectionEvents) == 0) {
			return nil
		}
		if o.fatalSent && o.active == nil && o.prepared == nil {
			return o.fatal
		}
		var destination chan<- *writeFrame
		var next *writeFrame
		if o.active == nil {
			if o.prepared == nil {
				o.prepared = o.nextWrite()
			}
			next = o.prepared
			if next != nil {
				destination = writes
			}
		}
		input := reads
		if o.fatal != nil {
			input = nil
		}
		select {
		case <-o.ctx.Done():
			return o.ctx.Err()
		case <-o.shutdownDone:
			return context.Canceled
		case <-o.e.wake:
		case <-o.pingTicks:
			o.keepalive()
		case r := <-o.e.requests:
			o.request(r)
		case incoming := <-input:
			if incoming.err != nil {
				const wsaECONNRESET = syscall.Errno(10054)
				reset := errors.Is(incoming.err, syscall.ECONNRESET) || runtime.GOOS == "windows" && errors.Is(incoming.err, wsaECONNRESET)
				if o.e.draining.Load() && (errors.Is(incoming.err, io.EOF) || reset) {
					complete := true
					for _, s := range o.streams {
						if s.failed == nil && (!s.remoteEnd || !s.localEnd) {
							complete = false
							break
						}
					}
					if complete {
						// A drained peer may close before consumers receive its final events.
						reads = nil
						continue
					}
				}
				_, protocol := errors.AsType[*ProtocolError](incoming.err)
				_, connection := errors.AsType[http2.ConnectionError](incoming.err)
				if stream, ok := errors.AsType[http2.StreamError](incoming.err); ok {
					if s := o.streams[stream.StreamID]; s != nil {
						o.cancel(s, stream.Code, streamError(s.id, stream.Code, stream.Error()), true)
					} else if o.e.cfg.Client && stream.StreamID%2 == 1 {
						if stream.StreamID > o.lastLocal {
							o.fail(protocolError(http2.ErrCodeProtocol, "HTTP/2 framer error on idle stream"))
						}
					} else {
						o.controls = append(o.controls, &writeFrame{kind: writeReset, stream: stream.StreamID, code: stream.Code})
					}
				} else if protocol || connection || errors.Is(incoming.err, http2.ErrFrameTooLarge) {
					o.fail(incoming.err)
				} else {
					return terminalError(o.ctx, incoming.err)
				}
			} else {
				if o.prepared != nil && o.prepared.request != nil && o.prepared.kind != writeGoAway {
					o.discardPrepared()
				}
				o.lastActivity = o.e.cfg.Clock.Now()
				if err := o.frame(incoming.frame); err != nil {
					if stream, ok := errors.AsType[*StreamError](err); ok {
						o.cancel(o.streams[stream.Identity.Stream], stream.Code, err, true)
					} else {
						o.fail(err)
					}
				}
				close(incoming.accepted)
			}
			if len(o.controls) > MaxConcurrentStreams*2 || len(o.connectionEvents) > MaxConcurrentStreams {
				o.fail(protocolError(http2.ErrCodeEnhanceYourCalm, "HTTP/2 control queue limit exceeded"))
			}
		case destination <- next:
			if next.kind == writeHeaders {
				// HEADERS may reach the peer before write completion is processed.
				o.streams[next.stream].wireStarted = true
				if o.e.cfg.Client {
					o.lastLocal = max(o.lastLocal, next.stream)
				}
			}
			o.active = next
			o.prepared = nil
		case result := <-written:
			o.active = nil
			if result.err != nil {
				return terminalError(o.ctx, result.err)
			}
			o.wrote(result.frame)
		}
	}
}

func (o *owner) discardPrepared() {
	w := o.prepared
	if w == nil {
		return
	}
	if w.kind == writeData {
		if s := o.streams[w.stream]; s != nil {
			s.outWindow += int64(w.length)
		}
		o.outWindow += int64(w.length)
	}
	o.prepared = nil
}

func (o *owner) schedulePing(delay time.Duration) {
	o.stopPing = o.e.cfg.Clock.AfterFunc(delay, func() {
		select {
		case o.pingTicks <- struct{}{}:
		default:
		}
	})
}

func (o *owner) keepalive() {
	if o.goaway || o.fatal != nil {
		return
	}
	elapsed := o.e.cfg.Clock.Now().Sub(o.lastActivity)
	if elapsed >= o.e.cfg.PingKeepalive {
		o.controls = append(o.controls, &writeFrame{kind: writePing, payload: []byte("00000000")})
		o.lastActivity = o.e.cfg.Clock.Now()
		o.e.cfg.Logger.Debug("Send HTTP/2 keep-alive PING to " + o.e.conn.RemoteAddr().String())
		elapsed = 0
	}
	o.schedulePing(o.e.cfg.PingKeepalive - elapsed)
}

func (o *owner) startHead(stage string) {
	o.finishHead()
	o.headStage = stage
	o.headDeadline = o.e.cfg.Clock.Now().Add(layer.HeadReadTimeout)
	o.stopHead = o.e.cfg.Clock.AfterFunc(layer.HeadReadTimeout, o.e.signal)
}

func (o *owner) finishHead() {
	if o.stopHead != nil {
		o.stopHead()
		o.stopHead = nil
	}
	o.headDeadline = time.Time{}
}

func (o *owner) beginFlush(err error) {
	if o.active != nil {
		o.abortError = err
		return
	}
	o.flushError = err
	o.flushDeadline = o.e.cfg.Clock.Now().Add(GoAwayFlushGrace)
	o.stopFlush = o.e.cfg.Clock.AfterFunc(GoAwayFlushGrace, o.e.signal)
}

func (o *owner) finishFlush() {
	if o.stopFlush != nil {
		o.stopFlush()
		o.stopFlush = nil
	}
	o.flushDeadline = time.Time{}
}

func (o *owner) settle() {
	if !o.headDeadline.IsZero() && !o.e.cfg.Clock.Now().Before(o.headDeadline) && o.fatal == nil {
		o.fail(protocolError(http2.ErrCodeProtocol, "HTTP/2 "+o.headStage+" deadline exceeded"))
		o.beginFlush(o.fatal)
	}
	if !o.flushDeadline.IsZero() && !o.e.cfg.Clock.Now().Before(o.flushDeadline) {
		o.abortError = o.flushError
	}
	for _, s := range o.streams {
		if s.receipt != nil {
			select {
			case <-s.receipt.Done():
				r := s.receipt
				s.receipt = nil
				if r.Consumed() && s.failed == nil && (!s.localEnd || !s.remoteEnd) {
					credit := o.budget.consume(&s.window, r.OriginalBytes())
					o.credits[s.id.Stream] += uint32(credit)
					o.publish()
				}
			default:
			}
		}
		if s.failed == nil && s.localEnd && s.remoteEnd && s.receipt == nil && !s.hasData() {
			s.closeDone()
			o.budget.release(&s.window)
			o.publish()
		}
		for _, r := range []*request{s.receiver, s.creditWaiter} {
			if r != nil && r.ctx.Err() != nil {
				r.complete(Event{}, r.ctx.Err())
				if r == s.receiver {
					s.receiver = nil
				} else {
					s.creditWaiter = nil
				}
			}
		}
		if s.sender != nil && s.sender.ctx.Err() != nil && (o.active == nil || o.active.request != s.sender) {
			if o.prepared != nil && o.prepared.request == s.sender {
				o.discardPrepared()
			}
			if s.offset > 0 {
				o.cancel(s, http2.ErrCodeCancel, s.sender.ctx.Err(), true)
			}
			if s.sender != nil {
				s.sender.complete(Event{}, s.sender.ctx.Err())
				s.sender = nil
			}
		}
		if s.sender == nil && s.receipt == nil && len(s.queue) == 0 && s.window.grant == 0 && (s.failed != nil || s.localEnd && s.remoteEnd) {
			if s.receiver != nil {
				s.receiver.complete(Event{}, io.EOF)
				s.receiver = nil
			}
			delete(o.streams, s.id.Stream)
			o.order = slices.DeleteFunc(o.order, func(id uint32) bool { return id == s.id.Stream })
		}
	}
	if o.receiver != nil && o.receiver.ctx.Err() != nil {
		o.receiver.complete(Event{}, o.receiver.ctx.Err())
		o.receiver = nil
	}
	for i := 0; i < len(o.opens); {
		if o.opens[i].ctx.Err() != nil {
			o.opens[i].complete(Event{}, o.opens[i].ctx.Err())
			o.opens = slices.Delete(o.opens, i, i+1)
		} else {
			i++
		}
	}
}

func (s *streamState) hasData() bool {
	for _, q := range s.queue {
		if q.event.Kind == Data {
			return true
		}
	}
	return false
}

func (o *owner) fulfill() {
	if o.receiver != nil && len(o.connectionEvents) > 0 {
		o.receiver.complete(o.connectionEvents[0], nil)
		o.receiver = nil
		o.connectionEvents = slices.Delete(o.connectionEvents, 0, 1)
	}
	for _, s := range o.streams {
		if s.creditWaiter != nil && (s.failed != nil || s.localEnd) {
			s.creditWaiter.complete(Event{}, streamError(s.id, http2.ErrCodeStreamClosed, "h2: stream closed"))
			s.creditWaiter = nil
		}
		if s.creditWaiter != nil && s.sender == nil && s.outWindow > 0 && o.outWindow > 0 {
			s.creditWaiter.complete(Event{}, nil)
			s.creditWaiter = nil
		}
		if s.receiver != nil && s.receipt == nil {
			if len(s.queue) > 0 {
				q := s.queue[0]
				s.queue = slices.Delete(s.queue, 0, 1)
				if q.event.Kind == Data {
					if q.event.Data == nil {
						q.event.Data = make([]byte, 0, ChunkSize)
					}
					receipt, err := layer.NewConsumptionReceipt(q.original)
					if err != nil {
						panic("h2: negative original DATA length")
					}
					s.receipt = &consumption{Receipt: receipt, wake: o.e.signal}
					q.event.Receipt = s.receipt
				}
				s.receiver.complete(q.event, nil)
				s.receiver = nil
			} else if s.failed != nil || s.remoteEnd {
				err := s.failed
				if err == nil {
					err = io.EOF
				}
				s.receiver.complete(Event{}, err)
				s.receiver = nil
			}
		}
	}
	for len(o.opens) > 0 && o.peerSettings && !o.goaway && o.fatal == nil && uint32(o.budget.streams) < o.peerConcurrent {
		r := o.opens[0]
		if o.nextLocal > 0x7fffffff {
			r.complete(Event{}, errors.New("h2: stream IDs exhausted"))
			o.opens = slices.Delete(o.opens, 0, 1)
			continue
		}
		s := o.newStream(o.nextLocal)
		if s == nil {
			break
		}
		o.nextLocal += 2
		r.complete(Event{Identity: s.id}, nil)
		o.opens = slices.Delete(o.opens, 0, 1)
	}
}

func (o *owner) newStream(id uint32) *streamState {
	if len(o.streams) >= MaxConcurrentStreams*2 {
		for _, oldID := range o.order {
			old := o.streams[oldID]
			if old.failed != nil && old.sender == nil && old.receiver == nil && old.creditWaiter == nil && old.receipt == nil {
				delete(o.streams, oldID)
				o.order = slices.DeleteFunc(o.order, func(id uint32) bool { return id == oldID })
				break
			}
		}
		if len(o.streams) >= MaxConcurrentStreams*2 {
			return nil
		}
	}
	s := &streamState{id: layer.StreamIdentity{Endpoint: o.e.cfg.Descriptor.Identity, Stream: id}, done: make(chan struct{}), failureDone: make(chan struct{}), outWindow: o.peerInitial, contentLength: -1}
	if !o.budget.reserve(&s.window) {
		return nil
	}
	o.streams[id] = s
	o.order = append(o.order, id)
	o.publish()
	return s
}

func (o *owner) request(r *request) {
	if r.ctx.Err() != nil {
		r.complete(Event{}, r.ctx.Err())
		return
	}
	if o.fatal != nil {
		r.complete(Event{}, o.fatal)
		return
	}
	s := o.streams[r.id.Stream]
	if r.kind != receive && r.kind != openStream && r.kind != shutdown {
		if r.id.Endpoint != o.e.cfg.Descriptor.Identity || s == nil {
			r.complete(Event{}, streamError(r.id, http2.ErrCodeStreamClosed, "h2: unknown or foreign stream"))
			return
		}
	}
	switch r.kind {
	case receive:
		if o.receiver != nil {
			r.complete(Event{}, errors.New("h2: concurrent connection Receive"))
			return
		}
		o.receiver = r
	case streamDone:
		r.done = s.done
		r.complete(Event{}, nil)
	case streamFailed:
		r.done = s.failureDone
		r.complete(Event{}, nil)
	case receiveStream:
		if s.receiver != nil {
			r.complete(Event{}, errors.New("h2: concurrent stream Receive"))
			return
		}
		s.receiver = r
	case openStream:
		if o.e.draining.Load() {
			r.complete(Event{}, ErrDraining)
			return
		}
		if !o.e.cfg.Client || o.goaway {
			r.complete(Event{}, errors.New("h2: endpoint cannot open a stream"))
			return
		}
		if len(o.opens) >= MaxConcurrentStreams {
			r.complete(Event{}, errors.New("h2: too many waiting stream opens"))
			return
		}
		o.opens = append(o.opens, r)
	case waitSendCredit:
		if s.creditWaiter != nil {
			r.complete(Event{}, errors.New("h2: concurrent credit wait"))
			return
		}
		s.creditWaiter = r
	case send:
		if failure, ok := errors.AsType[*StreamError](s.failed); ok {
			r.complete(Event{}, failure)
			return
		}
		if s.failed != nil || s.localEnd {
			r.complete(Event{}, streamError(r.id, http2.ErrCodeStreamClosed, "h2: stream closed"))
			return
		}
		if s.sender != nil {
			r.complete(Event{}, errors.New("h2: concurrent sends on one stream"))
			return
		}
		if err := o.checkSend(s, r.event); err != nil {
			r.complete(Event{}, err)
			return
		}
		s.sender, s.offset = r, 0
	case cancelStream:
		o.cancel(s, r.code, streamError(s.id, r.code, "h2: stream cancelled"), true)
		r.complete(Event{}, nil)
	case shutdown:
		if len(r.debug) > maxHeaderBytes {
			r.complete(Event{}, errors.New("h2: GOAWAY debug data too large"))
			return
		}
		o.goaway, o.shutdown = true, true
		o.shutdownDone = r.ctx.Done()
		o.beginFlush(protocolError(r.code, "HTTP/2 GOAWAY flush deadline exceeded"))
		o.controls = append(o.controls, &writeFrame{kind: writeGoAway, stream: o.lastPeer, code: r.code, payload: r.debug, request: r})
		for _, open := range o.opens {
			open.complete(Event{}, errors.New("h2: connection shutting down"))
		}
		o.opens = nil
	}
}

func (o *owner) checkSend(s *streamState, event Event) error {
	switch event.Kind {
	case Headers:
		if s.outHeaders {
			return streamError(s.id, http2.ErrCodeProtocol, "h2: duplicate outgoing headers")
		}
	case Informational:
		if o.e.cfg.Client || s.outHeaders || event.EndStream {
			return streamError(s.id, http2.ErrCodeProtocol, "h2: invalid informational response")
		}
	case Data:
		if !s.outHeaders {
			return streamError(s.id, http2.ErrCodeProtocol, "h2: DATA before headers")
		}
	case Trailers:
		if !s.outHeaders || !event.EndStream {
			return streamError(s.id, http2.ErrCodeProtocol, "h2: trailers must end a headed stream")
		}
	default:
		return streamError(s.id, http2.ErrCodeProtocol, "h2: unsupported Send event")
	}
	if event.Kind != Data {
		var size uint64
		for _, field := range event.Headers {
			size += uint64(len(field.Name) + len(field.Value) + 32)
		}
		if size > uint64(o.peerHeaders) || size > maxHeaderBytes {
			return streamError(s.id, http2.ErrCodeEnhanceYourCalm, "h2: outbound headers exceed peer limit")
		}
	}
	if o.e.cfg.Client && event.Kind == Headers {
		for _, field := range event.Headers {
			if field.Name == ":method" {
				s.requestMethod = field.Value
			}
		}
	}
	return nil
}

func (o *owner) nextWrite() *writeFrame {
	if len(o.controls) > 0 {
		frame := o.controls[0]
		o.controls = slices.Delete(o.controls, 0, 1)
		return frame
	}
	if o.fatal != nil {
		code := http2.ErrCodeProtocol
		if protocol, ok := errors.AsType[*ProtocolError](o.fatal); ok {
			code = protocol.Code
		}
		o.fatalSent = true
		return &writeFrame{kind: writeGoAway, stream: o.lastPeer, code: code, payload: []byte(o.fatal.Error())}
	}
	for stream, value := range o.credits {
		delete(o.credits, stream)
		if value == 0 {
			continue
		}
		if stream != 0 {
			s := o.streams[stream]
			if s == nil || s.failed != nil || s.window.grant == 0 {
				continue
			}
		}
		return &writeFrame{kind: writeCredit, stream: stream, value: value}
	}
	// Opening a higher local ID implicitly closes lower idle IDs at the peer.
	firstPending := ^uint32(0)
	if o.e.cfg.Client {
		for _, id := range o.order {
			s := o.streams[id]
			if id%2 == 1 && s != nil && s.failed == nil && !s.wireStarted {
				firstPending = min(firstPending, id)
			}
		}
	}
	for range len(o.order) {
		if len(o.order) == 0 {
			return nil
		}
		o.cursor %= len(o.order)
		id := o.order[o.cursor]
		o.cursor++
		s := o.streams[id]
		if s == nil || s.sender == nil || s.failed != nil {
			continue
		}
		r := s.sender
		if r.ctx.Err() != nil {
			continue
		}
		if r.event.Kind != Data {
			if o.e.cfg.Client && id%2 == 1 && !s.wireStarted && id > firstPending {
				continue
			}
			return &writeFrame{kind: writeHeaders, stream: id, end: r.event.EndStream, fields: r.event.Headers, maxFrame: o.peerFrame, request: r}
		}
		left := len(r.event.Data) - s.offset
		n := min(left, int(o.peerFrame), int(max(int64(0), s.outWindow)), int(max(int64(0), o.outWindow)))
		if left > 0 && n == 0 {
			continue
		}
		s.outWindow -= int64(n)
		o.outWindow -= int64(n)
		return &writeFrame{kind: writeData, stream: id, end: r.event.EndStream && n == left, payload: r.event.Data[s.offset : s.offset+n], request: r, length: n}
	}
	return nil
}

func (o *owner) wrote(frame *writeFrame) {
	if frame.kind == writeGoAway {
		o.finishFlush()
	}
	if frame.request == nil {
		return
	}
	r := frame.request
	if frame.kind == writeGoAway {
		r.complete(Event{}, nil)
		return
	}
	s := o.streams[frame.stream]
	if s == nil {
		r.complete(Event{}, streamError(r.id, http2.ErrCodeStreamClosed, "h2: stream closed during send"))
		return
	}
	if s.failed != nil {
		r.complete(Event{}, s.failed)
		s.sender = nil
		return
	}
	if r.ctx.Err() != nil {
		r.complete(Event{}, r.ctx.Err())
		s.sender = nil
		o.cancel(s, http2.ErrCodeCancel, r.ctx.Err(), true)
		return
	}
	if frame.kind == writeData {
		s.offset += frame.length
		if s.offset < len(r.event.Data) {
			return
		}
	} else if r.event.Kind == Headers {
		s.outHeaders = true
	}
	if r.event.EndStream {
		s.localEnd = true
	}
	s.sender = nil
	r.complete(Event{}, nil)
}

func (o *owner) cancel(s *streamState, code http2.ErrCode, err error, sendReset bool) {
	if s.failed != nil {
		return
	}
	if o.prepared != nil && o.prepared.stream == s.id.Stream && (o.prepared.kind == writeCredit || o.prepared.request == s.sender && s.sender != nil) {
		o.discardPrepared()
	}
	s.failed = err
	s.closeFailure()
	s.closeDone()
	if s.receipt != nil {
		s.receipt.Invalidate()
		s.receipt = nil
	}
	s.queue = []queuedEvent{{event: Event{Kind: Reset, Identity: s.id, Code: code, Err: err}}}
	o.budget.release(&s.window)
	o.publish()
	delete(o.credits, s.id.Stream)
	if s.sender != nil && (o.active == nil || o.active.request != s.sender) {
		s.sender.complete(Event{}, err)
		s.sender = nil
	}
	locallyInitiated := (s.id.Stream%2 == 1) == o.e.cfg.Client
	if sendReset && (!locallyInitiated || s.wireStarted) {
		o.controls = append(o.controls, &writeFrame{kind: writeReset, stream: s.id.Stream, code: code})
	}
}

func (o *owner) fail(err error) {
	if o.fatal != nil {
		return
	}
	if connection, ok := errors.AsType[http2.ConnectionError](err); ok {
		err = protocolError(http2.ErrCode(connection), connection.Error())
	} else if errors.Is(err, http2.ErrFrameTooLarge) {
		err = protocolError(http2.ErrCodeFrameSize, err.Error())
	}
	code := http2.ErrCodeProtocol
	if protocol, ok := errors.AsType[*ProtocolError](err); ok {
		code = protocol.Code
	}
	o.fatal = err
	o.goaway = true
	o.e.cfg.Logger.Error(err.Error())
	o.connectionEvents = append(o.connectionEvents, Event{Kind: GoAway, Err: err, Code: code, LastStreamID: o.lastPeer})
	for _, s := range o.streams {
		o.cancel(s, code, err, false)
	}
	for _, r := range o.opens {
		r.complete(Event{}, err)
	}
	o.opens = nil
}

func (o *owner) closeAll(err error) {
	if err == nil {
		err = io.EOF
	}
	for _, s := range o.streams {
		if !s.localEnd || !s.remoteEnd {
			s.closeFailure()
		}
		s.closeDone()
		if s.receipt != nil {
			s.receipt.Invalidate()
			s.receipt = nil
		}
		s.queue = nil
		o.budget.release(&s.window)
		for _, r := range []*request{s.sender, s.receiver, s.creditWaiter} {
			if r != nil {
				r.complete(Event{}, err)
			}
		}
		s.sender, s.receiver, s.creditWaiter = nil, nil, nil
	}
	o.publish()
	if o.receiver != nil {
		o.receiver.complete(Event{}, err)
		o.receiver = nil
	}
	for _, r := range o.opens {
		r.complete(Event{}, err)
	}
	o.opens = nil
	for _, w := range o.controls {
		if w.request != nil {
			w.request.complete(Event{}, err)
		}
	}
	if o.active != nil && o.active.request != nil && o.active.kind == writeGoAway {
		o.active.request.complete(Event{}, err)
	}
}

func (o *owner) frame(frame http2.Frame) error {
	if !o.peerSettings {
		settings, ok := frame.(*http2.SettingsFrame)
		if !ok || settings.IsAck() {
			return protocolError(http2.ErrCodeProtocol, "HTTP/2 peer preface must start with SETTINGS")
		}
	}
	if o.assembly.stream != 0 {
		continuation, ok := frame.(*http2.ContinuationFrame)
		if !ok || continuation.StreamID != o.assembly.stream {
			return protocolError(http2.ErrCodeProtocol, "Invalid HTTP/2 HEADERS/CONTINUATION order")
		}
	}
	switch f := frame.(type) {
	case *http2.SettingsFrame:
		return o.settings(f)
	case *http2.HeadersFrame:
		o.startHead("HEADERS")
		o.headEnd = f.StreamEnded()
		fields, err := o.assembly.fragment(f.StreamID, true, f.HeadersEnded(), f.HeaderBlockFragment())
		if err != nil {
			return err
		}
		if f.HeadersEnded() {
			o.finishHead()
			return o.headers(f.StreamID, fields, o.headEnd)
		}
	case *http2.ContinuationFrame:
		fields, err := o.assembly.fragment(f.StreamID, false, f.HeadersEnded(), f.HeaderBlockFragment())
		if err != nil {
			return err
		}
		if f.HeadersEnded() {
			o.finishHead()
			return o.headers(f.StreamID, fields, o.headEnd)
		}
	case *http2.DataFrame:
		return o.data(f)
	case *http2.WindowUpdateFrame:
		s := o.streams[f.StreamID]
		if o.e.cfg.Client && f.StreamID%2 == 1 && (f.StreamID > o.lastLocal || s != nil && !s.wireStarted) {
			return protocolError(http2.ErrCodeProtocol, "HTTP/2 WINDOW_UPDATE on idle stream")
		}
		if f.StreamID == 0 {
			if o.outWindow+int64(f.Increment) > 0x7fffffff {
				return protocolError(http2.ErrCodeFlowControl, "HTTP/2 connection window overflow")
			}
			o.outWindow += int64(f.Increment)
		} else if s != nil && s.failed == nil {
			if s.outWindow+int64(f.Increment) > 0x7fffffff {
				o.cancel(s, http2.ErrCodeFlowControl, streamError(s.id, http2.ErrCodeFlowControl, "h2: stream window overflow"), true)
			} else {
				s.outWindow += int64(f.Increment)
			}
		} else if f.StreamID >= o.nextLocal && o.e.cfg.Client {
			return protocolError(http2.ErrCodeProtocol, "HTTP/2 WINDOW_UPDATE on idle stream")
		}
	case *http2.RSTStreamFrame:
		s := o.streams[f.StreamID]
		if o.e.cfg.Client && f.StreamID%2 == 1 && (f.StreamID > o.lastLocal || s != nil && !s.wireStarted) {
			return protocolError(http2.ErrCodeProtocol, "HTTP/2 RST_STREAM on idle stream")
		}
		if s != nil {
			o.cancel(s, f.ErrCode, streamError(s.id, f.ErrCode, "stream reset by client ("+f.ErrCode.String()+")"), false)
		}
	case *http2.GoAwayFrame:
		o.goaway, o.shutdown = true, true
		o.e.draining.Store(true)
		o.connectionEvents = append(o.connectionEvents, Event{Kind: GoAway, Code: f.ErrCode, LastStreamID: f.LastStreamID, Err: errors.New("HTTP/2 connection closed: " + string(f.DebugData()))})
		for _, s := range o.streams {
			locallyInitiated := (s.id.Stream%2 == 1) == o.e.cfg.Client
			if locallyInitiated && s.id.Stream > f.LastStreamID || f.ErrCode != http2.ErrCodeNo {
				o.cancel(s, f.ErrCode, streamError(s.id, f.ErrCode, "h2: stream rejected by GOAWAY"), false)
			}
		}
		for _, r := range o.opens {
			r.complete(Event{}, ErrDraining)
		}
		o.opens = nil
	case *http2.PingFrame:
		if !f.Flags.Has(http2.FlagPingAck) {
			o.controls = append(o.controls, &writeFrame{kind: writePing, ack: true, payload: slices.Clone(f.Data[:])})
		}
	case *http2.PushPromiseFrame:
		return protocolError(http2.ErrCodeProtocol, "Received HTTP/2 push promise, even though we signalled no support.")
	case *http2.PriorityFrame:
	case *http2.UnknownFrame:
		if f.Header().Type == 0x0a {
			o.e.cfg.Logger.Debug("Received HTTP/2 Alt-Svc frame, which will not be forwarded.")
		} else {
			o.e.cfg.Logger.Debug("Ignoring unknown HTTP/2 frame type: " + strconv.Itoa(int(f.Header().Type)))
		}
	}
	if len(o.controls) > MaxConcurrentStreams*2 || len(o.connectionEvents) > MaxConcurrentStreams {
		return protocolError(http2.ErrCodeEnhanceYourCalm, "HTTP/2 control queue limit exceeded")
	}
	return nil
}

func (o *owner) settings(f *http2.SettingsFrame) error {
	if f.IsAck() {
		return nil
	}
	err := f.ForeachSetting(func(setting http2.Setting) error {
		return o.applySetting(setting)
	})
	if err != nil {
		return err
	}
	if !o.peerSettings {
		o.finishHead()
	}
	o.peerSettings = true
	o.controls = append(o.controls, &writeFrame{kind: writeSettingsAck})
	return nil
}

func (o *owner) headers(id uint32, fields []hpack.HeaderField, end bool) error {
	if id == 1 && o.e.cfg.Upgrade != nil {
		return protocolError(http2.ErrCodeProtocol, "HTTP/2 upgrade stream 1 cannot be reused")
	}
	s := o.streams[id]
	if o.e.cfg.Client && id%2 == 1 {
		if id > o.lastLocal || s != nil && !s.wireStarted {
			return protocolError(http2.ErrCodeProtocol, "Unexpected HTTP/2 stream headers")
		}
		// Decode before discarding in-flight headers to preserve the HPACK table.
		if s == nil {
			return nil
		}
	}
	isNew := s == nil
	if isNew {
		if o.e.cfg.Client || id%2 == 0 || id <= o.lastPeer {
			return protocolError(http2.ErrCodeProtocol, "Unexpected HTTP/2 stream headers")
		}
		o.lastPeer = id
		if o.goaway {
			o.controls = append(o.controls, &writeFrame{kind: writeReset, stream: id, code: http2.ErrCodeRefusedStream})
			return nil
		}
		s = o.newStream(id)
		if s == nil {
			o.controls = append(o.controls, &writeFrame{kind: writeReset, stream: id, code: http2.ErrCodeRefusedStream})
			return nil
		}
	}
	if s.failed != nil || s.remoteEnd {
		o.controls = append(o.controls, &writeFrame{kind: writeReset, stream: id, code: http2.ErrCodeStreamClosed})
		return nil
	}
	kind := Headers
	if s.inHeaders {
		kind = Trailers
		if !end {
			return protocolError(http2.ErrCodeProtocol, "HTTP/2 trailers do not end the stream")
		}
		for _, field := range fields {
			if field.IsPseudo() {
				return protocolError(http2.ErrCodeProtocol, "HTTP/2 pseudo-header in trailers")
			}
		}
	} else {
		if o.e.cfg.Client {
			for _, field := range fields {
				if field.Name == ":status" && strings.HasPrefix(field.Value, "1") {
					kind = Informational
				}
			}
			if kind == Informational && end {
				return protocolError(http2.ErrCodeProtocol, "HTTP/2 informational response ends stream")
			}
		}
		if kind != Informational {
			if err := checkPseudo(fields, o.e.cfg.Client); err != nil {
				return err
			}
			s.inHeaders = true
			for _, field := range fields {
				if field.Name == ":status" {
					s.responseStatus = field.Value
				}
			}
			if err := s.setContentLength(fields); err != nil {
				return err
			}
		}
	}
	if end {
		if err := s.checkLength(true); err != nil {
			return err
		}
		s.remoteEnd = true
	}
	event := Event{Kind: kind, Identity: s.id, Headers: fields, EndStream: end}
	if isNew {
		o.connectionEvents = append(o.connectionEvents, event)
	} else {
		s.queue = append(s.queue, queuedEvent{event: event})
	}
	if len(s.queue) > maxQueuedEvents {
		return protocolError(http2.ErrCodeEnhanceYourCalm, "HTTP/2 stream event queue exceeded")
	}
	return nil
}

func checkPseudo(fields []hpack.HeaderField, response bool) error {
	pseudo := make(map[string]string)
	for _, field := range fields {
		if field.IsPseudo() {
			if _, ok := pseudo[field.Name]; ok {
				return protocolError(http2.ErrCodeProtocol, "Duplicate HTTP/2 pseudo header: "+field.Name)
			}
			pseudo[field.Name] = field.Value
		}
	}
	if response {
		status, err := strconv.Atoi(pseudo[":status"])
		if err != nil || status < 200 || status > 999 || len(pseudo) != 1 {
			return protocolError(http2.ErrCodeProtocol, "Invalid HTTP/2 response headers")
		}
	} else {
		if pseudo[":method"] == "CONNECT" {
			if pseudo[":authority"] == "" || pseudo[":scheme"] != "" || pseudo[":path"] != "" {
				return protocolError(http2.ErrCodeProtocol, "Invalid HTTP/2 CONNECT pseudo headers")
			}
		} else if pseudo[":method"] == "" || pseudo[":scheme"] == "" || pseudo[":path"] == "" {
			return protocolError(http2.ErrCodeProtocol, "Required pseudo header is missing")
		}
		for name := range pseudo {
			switch name {
			case ":method", ":scheme", ":path", ":authority":
			default:
				return protocolError(http2.ErrCodeProtocol, "Unknown HTTP/2 pseudo header: "+name)
			}
		}
	}
	return nil
}

func (s *streamState) checkLength(end bool) error {
	length := s.contentLength
	// HEAD and bodyless status codes describe a representation, not DATA bytes.
	if s.responseStatus != "" && (s.requestMethod == "HEAD" || s.responseStatus == "204" || s.responseStatus == "304" || strings.HasPrefix(s.responseStatus, "1")) {
		length = 0
	}
	if length >= 0 && (s.received > length || end && s.received != length) {
		return streamError(s.id, http2.ErrCodeProtocol, "InvalidBodyLengthError: Expected "+strconv.FormatInt(length, 10)+" bytes, received "+strconv.FormatInt(s.received, 10))
	}
	return nil
}

func (o *owner) data(f *http2.DataFrame) error {
	s := o.streams[f.StreamID]
	if o.e.cfg.Client && f.StreamID%2 == 1 {
		if f.StreamID > o.lastLocal || s != nil && !s.wireStarted {
			return protocolError(http2.ErrCodeProtocol, "HTTP/2 DATA on idle stream")
		}
		if s == nil {
			// Discarded DATA still consumes the connection flow-control window.
			o.credits[0] += f.Length
			return nil
		}
	}
	if s == nil {
		if (!o.e.cfg.Client && f.StreamID > o.lastPeer) || (o.e.cfg.Client && f.StreamID >= o.nextLocal) {
			return protocolError(http2.ErrCodeProtocol, "HTTP/2 DATA on idle stream")
		}
		o.credits[0] += f.Length
		o.controls = append(o.controls, &writeFrame{kind: writeReset, stream: f.StreamID, code: http2.ErrCodeStreamClosed})
		return nil
	}
	o.credits[0] += f.Length
	if s.failed != nil || s.remoteEnd {
		o.controls = append(o.controls, &writeFrame{kind: writeReset, stream: f.StreamID, code: http2.ErrCodeStreamClosed})
		return nil
	}
	if !s.inHeaders {
		return protocolError(http2.ErrCodeProtocol, "Received HTTP/2 data frame, expected headers.")
	}
	if int(f.Length) > s.window.available {
		o.cancel(s, http2.ErrCodeFlowControl, streamError(s.id, http2.ErrCodeFlowControl, "h2: receive stream window exceeded"), true)
		return nil
	}
	s.window.available -= int(f.Length)
	s.received += int64(len(f.Data()))
	if err := s.checkLength(f.StreamEnded()); err != nil {
		return err
	}
	payload := f.Data()
	padding := int(f.Length) - len(payload)
	if len(payload) == 0 {
		s.queue = append(s.queue, queuedEvent{event: Event{Kind: Data, Identity: s.id, Data: nil, EndStream: f.StreamEnded()}, original: padding})
	} else {
		for len(payload) > 0 {
			var tail *queuedEvent
			if len(s.queue) > 0 {
				last := &s.queue[len(s.queue)-1]
				if last.event.Kind == Data && !last.event.EndStream && len(last.event.Data) > 0 && len(last.event.Data) < ChunkSize {
					tail = last
				}
			}
			if tail == nil {
				s.queue = append(s.queue, queuedEvent{event: Event{Kind: Data, Identity: s.id, Data: make([]byte, 0, ChunkSize)}})
				tail = &s.queue[len(s.queue)-1]
			}
			n := min(len(payload), ChunkSize-len(tail.event.Data))
			tail.event.Data = append(tail.event.Data, payload[:n]...)
			tail.original += n
			payload = payload[n:]
			if len(payload) == 0 {
				tail.original += padding
				tail.event.EndStream = f.StreamEnded()
			}
		}
	}
	if f.StreamEnded() {
		s.remoteEnd = true
	}
	// A growing stream may hold 128 full chunks plus bounded metadata.
	if len(s.queue) > MaxStreamWindow/ChunkSize+maxQueuedEvents {
		return protocolError(http2.ErrCodeEnhanceYourCalm, "HTTP/2 stream queue limit exceeded")
	}
	return nil
}
