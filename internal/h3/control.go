// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"context"
	"errors"
	"io"

	quic "github.com/quic-go/quic-go"
)

func (e *Endpoint) acceptUnidirectional() {
	for {
		stream, err := e.conn.acceptUniStream(e.ctx)
		if err != nil {
			if e.ctx.Err() == nil {
				e.fail(connectionTransportError(err))
			}
			return
		}
		e.mu.Lock()
		if e.ctx.Err() != nil {
			e.mu.Unlock()
			cancelIncomingUni(stream, ErrCodeRequestCancelled)
			return
		}
		if len(e.incoming) >= MaxConcurrentStreams+3 {
			e.mu.Unlock()
			cancelIncomingUni(stream, ErrCodeExcessiveLoad)
			e.fail(connectionError(ErrCodeExcessiveLoad, "too many unclassified streams"))
			return
		}
		e.incoming[uint64(stream.StreamID())] = stream
		e.workers.Go(func() { e.readUnidirectional(stream) })
		e.mu.Unlock()
	}
}

func (e *Endpoint) readUnidirectional(stream *incomingUniStream) {
	defer func() { e.mu.Lock(); delete(e.incoming, uint64(stream.StreamID())); e.mu.Unlock() }()
	kind, err := readVarint(stream)
	if err != nil {
		if e.ctx.Err() != nil {
			return
		}
		// A close can end this read before endpoint cancellation propagates.
		// Preserve its typed cause before a normal close becomes EOF.
		if _, ok := errors.AsType[*quic.ApplicationError](err); ok {
			e.fail(connectionTransportError(err))
			return
		}
		if cause := context.Cause(e.conn.context()); cause != nil {
			e.fail(connectionTransportError(cause))
			return
		}
		if !errors.Is(err, io.EOF) {
			e.fail(connectionError(ErrCodeStreamCreation, "truncated stream type"))
		}
		return
	}
	if kind == 1 {
		if !e.cfg.Client {
			e.fail(connectionError(ErrCodeStreamCreation, "client sent push stream"))
			return
		}
		id, err := readVarint(stream)
		if err != nil {
			e.fail(connectionError(ErrCodeIDError, "truncated push stream identifier"))
			return
		}
		if err := e.controlFrame(e.ctx, frameCancelPush, appendVarint(nil, id)); err != nil {
			e.fail(err)
			return
		}
		cancelIncomingUni(stream, ErrCodeNoError)
		return
	}
	if kind != 0 && kind != 2 && kind != 3 {
		cancelIncomingUni(stream, ErrCodeNoError)
		return
	}
	e.mu.Lock()
	if e.critical[kind] {
		e.mu.Unlock()
		e.fail(connectionError(ErrCodeStreamCreation, "duplicate critical stream"))
		return
	}
	e.critical[kind] = true
	e.mu.Unlock()
	if kind == 0 {
		err = e.readControl(stream)
	} else {
		for e.ctx.Err() == nil {
			if err = readQPACKInstruction(stream, kind == 2); err != nil {
				break
			}
		}
	}
	if e.ctx.Err() != nil {
		return
	}
	// Stream reads may observe the connection close before its context is
	// cancelled. Preserve that terminal error before NO_ERROR becomes EOF.
	if _, ok := errors.AsType[*quic.ApplicationError](err); ok {
		e.fail(connectionTransportError(err))
		return
	}
	if cause := context.Cause(e.conn.context()); cause != nil {
		e.fail(connectionTransportError(cause))
		return
	}
	err = connectionTransportError(err)
	if _, ok := errors.AsType[*ConnectionError](err); ok {
		e.fail(err)
		return
	}
	e.fail(connectionError(ErrCodeClosedCriticalStream, "peer closed a critical stream"))
}

func (e *Endpoint) readControl(reader io.Reader) error {
	first := true
	for {
		parsed, err := readFrame(reader)
		if err != nil {
			return err
		}
		if first && parsed.kind != frameSettings {
			return connectionError(ErrCodeMissingSettings, "SETTINGS must be first on control stream")
		}
		first = false
		switch parsed.kind {
		case frameSettings:
			e.mu.Lock()
			if e.peerSettings {
				e.mu.Unlock()
				return connectionError(ErrCodeFrameUnexpected, "duplicate SETTINGS frame")
			}
			if limit, ok := parsed.settings[6]; ok {
				e.peerHeaderLimit = min(limit, MaxHeaderBytes)
			}
			e.peerSettings = true
			close(e.ready)
			e.signalLocked()
			e.mu.Unlock()
		case frameGoAway:
			if e.cfg.Client && parsed.id%4 != 0 {
				return connectionError(ErrCodeIDError, "invalid request identifier in GOAWAY")
			}
			e.mu.Lock()
			if parsed.id > e.peerGoAway {
				e.mu.Unlock()
				return connectionError(ErrCodeIDError, "GOAWAY identifier increased")
			}
			e.peerGoAway = parsed.id
			e.draining = true
			e.signalLocked()
			states := make([]*requestState, 0, len(e.streams))
			if e.cfg.Client {
				for _, s := range e.streams {
					if s.id.Stream >= parsed.id {
						states = append(states, s)
					}
				}
			}
			e.mu.Unlock()
			if !e.notify(Event{Kind: GoAway, Code: ErrCodeNoError, LastStreamID: parsed.id}) {
				return e.endError()
			}
			for _, s := range states {
				s.fail(ErrCodeRequestRejected, &StreamError{Identity: s.id, Code: ErrCodeRequestRejected, Message: "request rejected by GOAWAY"})
			}
		case frameMaxPushID:
			if e.cfg.Client {
				return connectionError(ErrCodeFrameUnexpected, "server sent MAX_PUSH_ID")
			}
			// The server never initiates push, regardless of the peer's allowance.
		case frameCancelPush:
			return connectionError(ErrCodeIDError, "cancellation of an unallocated push")
		default:
			return connectionError(ErrCodeFrameUnexpected, "request frame on control stream")
		}
	}
}

func (e *Endpoint) controlFrame(ctx context.Context, kind uint64, payload []byte) error {
	if err := e.waitStarted(ctx); err != nil {
		return err
	}
	if err := take(ctx, e.controlLock, e.done); err != nil {
		if errors.Is(err, io.EOF) {
			return e.endError()
		}
		return err
	}
	defer func() { <-e.controlLock }()
	var stream *outgoingUniStream
	for {
		e.mu.Lock()
		stream = e.control
		changed := e.changed
		stopped := e.ctx.Err() != nil
		e.mu.Unlock()
		if stopped {
			return e.endError()
		}
		if stream != nil {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-e.done:
			return e.endError()
		}
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { cancelOutgoingUni(stream, ErrCodeRequestCancelled); close(done) })
	err := writeFrame(stream, kind, payload)
	if !stop() {
		<-done
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return err
}

// Shutdown writes a GOAWAY first-rejected identifier and drains accepted
// streams. Other codes abort the QUIC connection; diagnostics stay local.
func (e *Endpoint) Shutdown(ctx context.Context, code ErrorCode, debug []byte) error {
	if err := e.waitStarted(ctx); err != nil {
		return err
	}
	if code != ErrCodeNoError {
		message := string(debug[:min(len(debug), 1024)])
		e.fail(connectionError(code, message))
		return nil
	}
	e.mu.Lock()
	boundary := e.nextRejected
	if e.cfg.Client {
		boundary = 0
	}
	// Snapshot the rejection boundary and close admission under the same lock,
	// before GOAWAY reaches the wire. Keep the control stream alive until every
	// pending GOAWAY write finishes, even if the last accepted request retires.
	e.draining = true
	e.goAwayWrites++
	e.signalLocked()
	e.mu.Unlock()
	err := e.controlFrame(ctx, frameGoAway, appendVarint(nil, boundary))
	e.mu.Lock()
	e.goAwayWrites--
	if err != nil {
		e.mu.Unlock()
		e.fail(connectionError(ErrCodeInternal, "GOAWAY write interrupted"))
		return err
	}
	if len(e.streams) == 0 && e.opening == 0 && e.goAwayWrites == 0 && e.ctx.Err() == nil {
		e.graceful = true
		e.cancel()
	}
	e.mu.Unlock()
	select {
	case <-e.done:
		return e.endErrorUnlessGraceful()
	case <-ctx.Done():
		e.mu.Lock()
		e.cancel()
		e.mu.Unlock()
		<-e.done
		return ctx.Err()
	}
}

func (e *Endpoint) endErrorUnlessGraceful() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}
