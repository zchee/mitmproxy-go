// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"io"
	"sync"
)

type driverRead struct {
	event Event
	err   error
	write bool
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

func (d *streamDriver) run(ctx context.Context) (err error) {
	ctx, cancel := context.WithCancelCause(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel(nil)
		workers.Wait()
		if errors.Is(context.Cause(ctx), io.EOF) {
			// The reader only cancels the owner. Retire shared flow state here,
			// under dispatch, without waiting on another intercepted hook.
			err = io.EOF
			if d.stream.flow != nil {
				err = errors.Join(err, d.stream.notLive(context.WithoutCancel(ctx)))
			}
		}
	}()
	reads := [2]chan driverRead{make(chan driverRead), make(chan driverRead)}
	writes := [2]chan driverWrite{make(chan driverWrite), make(chan driverWrite)}
	written := [2]chan driverWritten{make(chan driverWritten, 1), make(chan driverWritten, 1)}
	failures := make(chan driverFailure, 2)
	requestEnds := make(chan driverRead, 1)
	requestReads, responseReads := reads[0], reads[1]
	workers.Go(func() { readRequests(ctx, cancel, d.client, requestReads, requestEnds, failures) })
	workers.Go(func() { readResponses(ctx, d.server, responseReads, failures) })
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
	var turns [3]*driverTurn
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
				turns[i] = nil
				continue
			}
			out, err := turn.output.after(ctx)
			if err != nil {
				return err
			}
			if d.stream.failed {
				turns[i] = nil
				turns[2] = &driverTurn{output: out}
			} else {
				turn.output = out
			}
		}
		if d.stream.failed && !terminated {
			terminated = true
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
		for i := range 2 {
			if turns[i] != nil {
				inputs[i] = nil
			}
		}
		ends := requestEnds
		if inputs[0] == nil {
			ends = nil
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
		case result = <-inputs[0]:
			source = 0
		case result = <-ends:
			source = 0
		case result = <-inputs[1]:
			source = 1
		case destinations[0] <- next[0]:
			next[0].turn.pending = true
			active[0], writeCancel[0] = writeCancel[0], nil
		case destinations[1] <- next[1]:
			next[1].turn.pending = true
			active[1], writeCancel[1] = writeCancel[1], nil
		case ack := <-written[0]:
			active[0]()
			active[0] = nil
			source, result = d.acknowledge(0, ack)
		case ack := <-written[1]:
			active[1]()
			active[1] = nil
			source, result = d.acknowledge(1, ack)
		}
		for _, stop := range writeCancel {
			if stop != nil {
				stop()
			}
		}
		if source < 0 || d.stream.failed {
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
				result.event = RequestProtocolError{ID: d.stream.id, Code: ClientDisconnected, Message: message}
			} else {
				if errors.Is(result.err, io.EOF) {
					message = "server closed connection"
				}
				result.event = ResponseProtocolError{ID: d.stream.id, Code: GenericServerError, Message: message}
			}
		}
		if _, end := result.event.(RequestEndOfMessage); end {
			reads[0] = nil
		}
		out, err := d.stream.handle(ctx, result.event)
		if err != nil {
			return err
		}
		if d.stream.failed {
			turns[2] = &driverTurn{output: out}
		} else {
			turns[source] = &driverTurn{output: out}
		}
	}
}

func (d *streamDriver) acknowledge(direction int, ack driverWritten) (int, driverRead) {
	ack.turn.pending = false
	ack.turn.output.events[0] = nil
	ack.turn.output.events = ack.turn.output.events[1:]
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

func readRequests(ctx context.Context, cancel context.CancelCauseFunc, endpoint ClientEndpoint, out, ends chan<- driverRead, failures chan<- driverFailure) {
	for {
		event, err := endpoint.Receive(ctx)
		if _, failed := event.(RequestProtocolError); failed || err != nil {
			failures <- driverFailure{source: 0, result: driverRead{event: event, err: err}}
			return
		}
		if _, end := event.(RequestEndOfMessage); end {
			// Completion has a separate slot so a paused hook cannot prevent
			// observing a disconnect. Do not parse the next pipelined request.
			ends <- driverRead{event: event}
			if client, ok := endpoint.(*http1Server); ok {
				err := client.readWait(ctx)
				var failure Event
				if len(client.queue) != 0 {
					failure = client.queue[0]
					client.queue[0] = nil
					client.queue = client.queue[1:]
				}
				if closed, ok := failure.(RequestProtocolError); ok && closed.Code == ClientDisconnected {
					// A queued event cannot wake an owner in WaitForResume.
					// Cancel the same stream context that protects the hook wait.
					cancel(io.EOF)
					return
				}
				if failure != nil || err != nil {
					failures <- driverFailure{source: 0, result: driverRead{event: failure, err: err}}
				}
			}
			return
		}
		select {
		case out <- driverRead{event: event}:
		case <-ctx.Done():
			return
		}
	}
}

func readResponses(ctx context.Context, endpoint ServerEndpoint, out chan<- driverRead, failures chan<- driverFailure) {
	for {
		event, err := endpoint.Receive(ctx)
		if _, failed := event.(ResponseProtocolError); failed || err != nil {
			failures <- driverFailure{source: 1, result: driverRead{event: event, err: err}}
			return
		}
		select {
		case out <- driverRead{event: event}:
		case <-ctx.Done():
			return
		}
	}
}
