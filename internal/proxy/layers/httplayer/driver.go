// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type driverRead struct {
	event    Event
	err      error
	write    bool
	accepted chan struct{}
	receipt  layer.ConsumptionReceipt
}

type driverPermit struct {
	streaming bool
	credit    func(context.Context) error
}

type driverFailure struct {
	source int
	result driverRead
}

// A turn retains one transition's output until Send acknowledges it. The
// owner does not accept another input from that direction before its output
// and continuation finish. The opposite direction remains independent.
type driverTurn struct {
	output  streamOutput
	pending bool
	receipt layer.ConsumptionReceipt
}

type driverWrite struct {
	ctx   context.Context
	event Event
	turn  *driverTurn
}

type driverWritten struct {
	turn *driverTurn
	err  error
}

// streamDriver runs one exchange against stream-scoped endpoints. Its caller
// must serialize HTTP/1 exchanges, or demultiplex a shared HTTP/2 connection
// before calling it. Only this goroutine touches the stream and invokes hooks
// or StreamFunc; readers and writers move owned events without inspecting flows.
type streamDriver struct {
	stream *httpStream
	client ClientEndpoint
	server ServerEndpoint

	// beforeRequest retires an idle origin reader on the owner goroutine,
	// after hooks return and before the server writer acquires a transport.
	beforeRequest func()
}

var errEndpointFailed = errors.New("HTTP stream endpoint failed")

func (d *streamDriver) run(ctx context.Context) (err error) {
	ctx, cancel := context.WithCancelCause(ctx)
	clientTerminal, terminate := context.WithCancelCause(ctx)
	terminateClient := func() { terminate(nil) }
	terminateStream := func() { terminate(errEndpointFailed) }
	defer terminateClient()
	d.stream.clientTerminal, d.stream.cancel = clientTerminal, cancel
	var workers sync.WaitGroup
	var turns [3]*driverTurn
	var activeTurns [2]*driverTurn
	defer func() {
		cancel(nil)
		workers.Wait()
		for _, turn := range activeTurns {
			if turn != nil && turn.receipt != nil {
				turn.receipt.Invalidate()
			}
		}
		for _, turn := range turns {
			if turn != nil && turn.receipt != nil {
				turn.receipt.Invalidate()
			}
		}
		if errors.Is(context.Cause(ctx), io.EOF) {
			// The reader only cancels the owner. Retire shared flow state here,
			// under dispatch, without waiting on another intercepted hook.
			err = io.EOF
			if d.stream.flow != nil {
				err = errors.Join(err, d.stream.notLive(context.WithoutCancel(ctx)))
			}
		}
	}()
	// One request slot lets a reader observe a terminal read following a
	// partial body chunk even while the owner is paused in requestheaders.
	reads := [2]chan driverRead{make(chan driverRead, 1), make(chan driverRead)}
	writes := [2]chan driverWrite{make(chan driverWrite), make(chan driverWrite)}
	written := [2]chan driverWritten{make(chan driverWritten, 1), make(chan driverWritten, 1)}
	failures := make(chan driverFailure, 2)
	requestReads, responseReads := reads[0], reads[1]
	var permits [2]chan driverPermit
	var receiving [2]bool
	for i, endpoint := range []any{d.client, d.server} {
		if _, controlled := endpoint.(interface{ needsReadCredit() bool }); controlled {
			permits[i] = make(chan driverPermit)
		}
		if endpoint, ok := endpoint.(interface {
			waitStreamFailed(context.Context) <-chan struct{}
		}); ok {
			workers.Go(func() {
				if observer, ok := endpoint.(interface{ waitEndpointFailed(context.Context) bool }); ok {
					if observer.waitEndpointFailed(ctx) {
						terminateStream()
					}
					return
				}
				select {
				case <-endpoint.waitStreamFailed(ctx):
					terminateStream()
				case <-ctx.Done():
				}
			})
		}
	}
	if _, ok := d.client.(interface {
		waitStreamFailed(context.Context) <-chan struct{}
	}); ok {
		terminateClient = terminateStream
	}
	workers.Go(func() { readRequests(ctx, terminateClient, d.client, requestReads, failures, permits[0]) })
	workers.Go(func() { readResponses(ctx, d.server, responseReads, failures, permits[1]) })
	workers.Go(func() {
		writeEvents(ctx, writes[0], written[0], func(ctx context.Context, event Event) error {
			return d.server.Send(ctx, event.(RequestEvent))
		})
	})
	workers.Go(func() {
		writeEvents(ctx, writes[1], written[1], func(ctx context.Context, event Event) error {
			return d.client.Send(ctx, event.(ResponseEvent))
		})
	})

	// The third slot holds terminal output. Old turns are discarded on
	// termination, but each outstanding Send is still acknowledged before
	// its writer is reused to deliver the protocol error.
	var active [2]context.CancelFunc
	terminated := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		for i, turn := range turns {
			if turn == nil || turn.pending || len(turn.output.events) != 0 {
				continue
			}
			if turn.output.after == nil {
				if turn.receipt != nil {
					turn.receipt.Complete()
				}
				turns[i] = nil
				continue
			}
			out, err := turn.output.after(ctx)
			if err != nil {
				return err
			}
			if d.stream.failed {
				if turn.receipt != nil {
					turn.receipt.Invalidate()
				}
				turns[i] = nil
				turns[2] = &driverTurn{output: out}
			} else {
				turn.output = out
			}
		}
		if d.stream.failed && !terminated {
			terminated = true
			for i := range 2 {
				if turns[i] != nil && !turns[i].pending && turns[i].receipt != nil {
					turns[i].receipt.Invalidate()
				}
			}
			turns[0] = nil
			if active[0] != nil {
				active[0]()
			}
			// A completed early response must still reach the client when
			// the origin closes immediately afterwards. Incomplete response
			// data is discarded before delivering the protocol error.
			if !d.stream.response.done {
				turns[1] = nil
				if active[1] != nil {
					active[1]()
				}
			}
			reads[0], reads[1] = nil, nil
		}
		if d.stream.done() && turns == [3]*driverTurn{} && active[0] == nil && active[1] == nil {
			return nil
		}

		inputs := reads
		var allowed [2]chan driverPermit
		var allowance [2]driverPermit
		for i := range 2 {
			if turns[i] != nil {
				inputs[i] = nil
			} else if reads[i] != nil && !receiving[i] {
				allowed[i] = permits[i]
				allowance[i].streaming = d.stream.body(i == 0).streaming
				destination := any(d.server)
				if i == 1 {
					destination = d.client
				}
				if endpoint, ok := destination.(interface{ waitSendCredit(context.Context) error }); ok {
					allowance[i].credit = endpoint.waitSendCredit
				}
			}
		}
		var destinations [2]chan driverWrite
		var next [2]driverWrite
		for _, turn := range turns {
			if turn == nil || turn.pending || len(turn.output.events) == 0 {
				continue
			}
			event := turn.output.events[0]
			direction := 1
			if _, request := event.(RequestEvent); request {
				direction = 0
			}
			if active[direction] == nil && destinations[direction] == nil {
				if _, headers := event.(RequestHeaders); headers && d.beforeRequest != nil {
					d.beforeRequest()
					d.beforeRequest = nil
				}
				destinations[direction] = writes[direction]
				next[direction] = driverWrite{event: event, turn: turn}
			}
		}
		var writeCtx [2]context.Context
		var writeCancel [2]context.CancelFunc
		for i := range 2 {
			if destinations[i] != nil {
				writeCtx[i], writeCancel[i] = context.WithCancel(ctx)
				next[i].ctx = writeCtx[i]
			}
		}
		var result driverRead
		source := -1
		select {
		case <-ctx.Done():
		case failure := <-failures:
			source, result = failure.source, failure.result
		case allowed[0] <- allowance[0]:
			receiving[0] = true
		case allowed[1] <- allowance[1]:
			receiving[1] = true
		case result = <-inputs[0]:
			receiving[0] = false
			source = 0
		case result = <-inputs[1]:
			receiving[1] = false
			source = 1
		case destinations[0] <- next[0]:
			if headers, ok := next[0].event.(RequestHeaders); ok && d.stream.upgrade.clientRequest != nil {
				d.stream.upgrade.serverRequest = headers.Request.Clone()
			}
			next[0].turn.pending = true
			activeTurns[0] = next[0].turn
			active[0], writeCancel[0] = writeCancel[0], nil
		case destinations[1] <- next[1]:
			if headers, ok := next[1].event.(ResponseHeaders); ok && headers.Response.StatusCode == 101 {
				d.stream.upgrade.clientResponse = headers.Response.Clone()
			}
			next[1].turn.pending = true
			activeTurns[1] = next[1].turn
			active[1], writeCancel[1] = writeCancel[1], nil
		case ack := <-written[0]:
			active[0]()
			active[0], activeTurns[0] = nil, nil
			source, result = d.acknowledge(0, ack)
		case ack := <-written[1]:
			active[1]()
			active[1], activeTurns[1] = nil, nil
			source, result = d.acknowledge(1, ack)
		}
		for _, stop := range writeCancel {
			if stop != nil {
				stop()
			}
		}
		if result.accepted != nil {
			close(result.accepted)
		}
		if source < 0 || d.stream.failed {
			if result.receipt != nil {
				result.receipt.Invalidate()
			}
			continue
		}
		if d.stream.done() && !result.write {
			// Endpoint retirement can report EOF as either an error or a
			// protocol event, possibly under the next HTTP/1 stream ID.
			continue
		}
		if result.err != nil {
			reads[source] = nil
			message := result.err.Error()
			if source == 0 {
				if errors.Is(result.err, io.EOF) {
					message = "peer closed connection"
				}
				result.event = RequestProtocolError{ID: d.stream.id, Code: httpStreamFailure(result.err, ClientDisconnected), Message: message}
			} else {
				if errors.Is(result.err, io.EOF) {
					message = "server closed connection"
				}
				result.event = ResponseProtocolError{ID: d.stream.id, Code: httpStreamFailure(result.err, GenericServerError), Message: message}
			}
		}
		if _, end := result.event.(RequestEndOfMessage); end {
			reads[0] = nil
		}
		out, err := d.stream.handle(ctx, result.event)
		if err != nil {
			if result.receipt != nil {
				result.receipt.Invalidate()
			}
			return err
		}
		if d.stream.failed {
			if result.receipt != nil {
				result.receipt.Invalidate()
			}
			turns[2] = &driverTurn{output: out}
		} else {
			turns[source] = &driverTurn{output: out, receipt: result.receipt}
		}
	}
}

// waitEndpointFailed distinguishes an origin failure from retiring an identity
// whose initial Send was rejected locally. That cleanup must unblock siblings,
// but must not release an intercepted error hook while the origin stays usable.
func (s *http2Stream) waitEndpointFailed(ctx context.Context) bool {
	select {
	case <-s.waitStreamFailed(ctx):
	case <-ctx.Done():
		return false
	}
	if s.initialSendFailure.Load() == nil {
		return true
	}
	select {
	case <-s.engine.Done():
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *lazyServer) waitEndpointFailed(ctx context.Context) bool {
	select {
	case <-s.ready:
	case <-ctx.Done():
		return false
	}
	s.mu.Lock()
	endpoint := s.endpoint
	s.mu.Unlock()
	if observer, ok := endpoint.(interface{ waitEndpointFailed(context.Context) bool }); ok {
		return observer.waitEndpointFailed(ctx)
	}
	select {
	case <-s.waitStreamFailed(ctx):
		return ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}

func (d *streamDriver) acknowledge(direction int, ack driverWritten) (int, driverRead) {
	ack.turn.pending = false
	ack.turn.output.events[0] = nil
	ack.turn.output.events = ack.turn.output.events[1:]
	if ack.turn.receipt != nil && (ack.err != nil || d.stream.failed) {
		ack.turn.receipt.Invalidate()
		ack.turn.receipt = nil
	}
	if ack.err == nil || d.stream.failed {
		return -1, driverRead{}
	}
	if direction == 0 {
		if failure, ok := errors.AsType[*acquisitionError](ack.err); ok {
			return 1, driverRead{event: ResponseProtocolError{ID: d.stream.id, Code: ConnectFailed, Message: failure.Error()}, write: true}
		}
	}
	// A failed upload is a server error; a failed download is a client error.
	return 1 - direction, driverRead{err: ack.err, write: true}
}

func writeEvents(ctx context.Context, input <-chan driverWrite, output chan<- driverWritten, send func(context.Context, Event) error) {
	for {
		select {
		case <-ctx.Done():
			return
		case work := <-input:
			result := driverWritten{turn: work.turn, err: send(work.ctx, work.event)}
			select {
			case output <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

// runHook resumes an intercepted wait when an endpoint fails, preserving the
// protocol failure for the exchange owner to record after the hook returns.
func (s *httpStream) runHook(ctx context.Context, prepare func(context.Context) error, hook addon.Hook) (*layer.Snapshot, error) {
	if s.clientTerminal == nil {
		return s.c.Hooks.FireFunc(ctx, prepare, hook)
	}
	var stop func() bool
	done := make(chan struct{})
	defer func() {
		if stop != nil && !stop() {
			<-done
		}
	}()
	return s.c.Hooks.FireFunc(ctx, func(hookCtx context.Context) error {
		if prepare != nil {
			if err := prepare(hookCtx); err != nil {
				return err
			}
		}
		// Arm under dispatch so the callback checks interception after the
		// hook releases dispatch, even if the reader has already terminated.
		// The callback owns no endpoint lock and never blocks the reader.
		stop = context.AfterFunc(s.clientTerminal, func() {
			defer close(done)
			_ = s.c.Do(ctx, func(context.Context) error {
				if s.flow.Intercepted() {
					if errors.Is(context.Cause(s.clientTerminal), errEndpointFailed) {
						s.flow.Resume()
					} else {
						s.cancel(io.EOF)
					}
				}
				return nil
			})
		})
		return nil
	}, hook)
}

func readRequests(ctx context.Context, terminate context.CancelFunc, endpoint ClientEndpoint, out chan<- driverRead, failures chan<- driverFailure, permits ...<-chan driverPermit) {
	readCtx, stopReader := driverReaderContext(ctx, endpoint)
	defer stopReader()
	if client, ok := endpoint.(*http1Server); ok {
		client.onReadTermination = terminate
		defer func() { client.onReadTermination = nil }()
	}
	var failure driverRead
	defer func() {
		if failure.event != nil || failure.err != nil {
			terminate()
			failures <- driverFailure{source: 0, result: failure}
		}
	}()
	for {
		if err := receivePermit(readCtx, endpoint, permits); err != nil && (ctx.Err() != nil || readCtx.Err() == nil) {
			failure.err = err
			return
		}
		event, err := endpoint.Receive(ctx)
		if _, failed := event.(RequestProtocolError); failed || err != nil {
			failure = driverRead{event: event, err: err}
			return
		}
		if _, end := event.(RequestEndOfMessage); end {
			// The buffered slot lets the reader observe disconnects during the
			// final request hook without parsing the next pipelined request.
			select {
			case out <- driverRead{event: event}:
			case <-ctx.Done():
				return
			}
			if observer, ok := endpoint.(interface {
				waitStreamFailed(context.Context) <-chan struct{}
				receiveFailure(context.Context) error
			}); ok {
				select {
				case <-observer.waitStreamFailed(ctx):
					failure.err = observer.receiveFailure(ctx)
				case <-ctx.Done():
				}
			} else if client, ok := endpoint.(*http1Server); ok {
				failure.err = client.readWait(ctx)
				if len(client.queue) != 0 {
					failure.event = client.queue[0]
					client.queue[0] = nil
					client.queue = client.queue[1:]
				}
			}
			return
		}
		result := driverRead{event: event, receipt: takeEndpointReceipt(endpoint)}
		if _, headers := event.(RequestHeaders); headers {
			// A terminal event must not overtake the head that creates its flow.
			result.accepted = make(chan struct{})
		}
		select {
		case out <- result:
		case <-ctx.Done():
			if result.receipt != nil {
				result.receipt.Invalidate()
			}
			return
		}
		if result.accepted != nil {
			select {
			case <-result.accepted:
			case <-ctx.Done():
				return
			}
		}
	}
}

func readResponses(ctx context.Context, endpoint ServerEndpoint, out chan<- driverRead, failures chan<- driverFailure, permits ...<-chan driverPermit) {
	readCtx, stopReader := driverReaderContext(ctx, endpoint)
	defer stopReader()
	for {
		if err := receivePermit(readCtx, endpoint, permits); err != nil && (ctx.Err() != nil || readCtx.Err() == nil) {
			failures <- driverFailure{source: 1, result: driverRead{err: err}}
			return
		}
		event, err := endpoint.Receive(ctx)
		if _, failed := event.(ResponseProtocolError); failed || err != nil {
			failures <- driverFailure{source: 1, result: driverRead{event: event, err: err}}
			return
		}
		result := driverRead{event: event, receipt: takeEndpointReceipt(endpoint)}
		select {
		case out <- result:
		case <-ctx.Done():
			if result.receipt != nil {
				result.receipt.Invalidate()
			}
			return
		}
	}
}

func takeEndpointReceipt(endpoint any) layer.ConsumptionReceipt {
	if endpoint, ok := endpoint.(interface {
		takeReceipt() layer.ConsumptionReceipt
	}); ok {
		return endpoint.takeReceipt()
	}
	return nil
}

// A source reset must wake a reader waiting on destination credit, without
// consuming more source DATA or cancelling an unrelated multiplexed stream.
func driverReaderContext(ctx context.Context, endpoint any) (context.Context, context.CancelFunc) {
	observer, ok := endpoint.(interface {
		waitStreamFailed(context.Context) <-chan struct{}
	})
	if !ok {
		return ctx, func() {}
	}
	readCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-observer.waitStreamFailed(readCtx):
			cancel()
		case <-readCtx.Done():
		}
	}()
	return readCtx, func() { cancel(); <-done }
}

func receivePermit(ctx context.Context, endpoint any, permits []<-chan driverPermit) error {
	if len(permits) == 0 || permits[0] == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case permit := <-permits[0]:
		if permit.streaming && permit.credit != nil && endpoint.(interface{ needsReadCredit() bool }).needsReadCredit() {
			return permit.credit(ctx)
		}
		return nil
	}
}
