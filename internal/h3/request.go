// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http/httpguts"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type requestState struct {
	e              *Endpoint
	wire           *requestStream
	id             layer.StreamIdentity
	mu             sync.Mutex
	changed        chan struct{}
	events         []Event
	bytes          int
	receipt        *layer.Receipt
	failure        *StreamError
	resetDelivered bool
	localEnd       bool
	remoteEnd      bool
	doneClosed     bool
	done           chan struct{}
	failed         chan struct{}
	sendLock       chan struct{}
	receiveLock    chan struct{}
	outHeaders     bool
	outLength      int64
	outBytes       uint64
	method         string
}

func newRequestState(e *Endpoint, wire *requestStream) *requestState {
	return &requestState{
		e: e, wire: wire, id: layer.StreamIdentity{Endpoint: e.cfg.Descriptor.Identity, Stream: uint64(wire.StreamID())},
		changed: make(chan struct{}), done: make(chan struct{}), failed: make(chan struct{}), sendLock: make(chan struct{}, 1), receiveLock: make(chan struct{}, 1), outLength: -1,
	}
}

func (s *requestState) signalLocked() { close(s.changed); s.changed = make(chan struct{}) }

func (s *requestState) fail(code ErrorCode, err error) {
	s.mu.Lock()
	if s.failure != nil {
		s.mu.Unlock()
		return
	}
	message := "stream stopped"
	if err != nil {
		message = err.Error()
	}
	failure, ok := errors.AsType[*StreamError](err)
	if !ok {
		failure = &StreamError{Identity: s.id, Code: code, Message: message}
	}
	s.failure = failure
	if s.receipt != nil {
		s.receipt.Invalidate()
		s.receipt = nil
	}
	clear(s.events)
	s.events = nil
	s.bytes = 0
	close(s.failed)
	if !s.doneClosed {
		close(s.done)
		s.doneClosed = true
	}
	s.signalLocked()
	s.mu.Unlock()
	cancelRequestStream(s.wire, failure.Code)
}

func (s *requestState) reserve(size int) bool {
	for {
		s.mu.Lock()
		if s.failure != nil || s.e.ctx.Err() != nil {
			s.mu.Unlock()
			return false
		}
		if s.bytes+size <= ReceiveQueueBytes && len(s.events) < MaxQueuedEvents {
			s.bytes += size
			s.mu.Unlock()
			return true
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-s.e.ctx.Done():
			return false
		}
	}
}

func (s *requestState) enqueue(event Event) bool {
	for {
		s.mu.Lock()
		if s.failure != nil || s.e.ctx.Err() != nil {
			s.mu.Unlock()
			return false
		}
		if len(s.events) < MaxQueuedEvents {
			s.events = append(s.events, event)
			s.signalLocked()
			s.mu.Unlock()
			return true
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-s.e.ctx.Done():
			return false
		}
	}
}

// Send serializes one stream and returns only after its borrowed slices are no
// longer being written. QUIC, not the endpoint, handles send credit and retries.
func (e *Endpoint) Send(ctx context.Context, event Event) error {
	s, err := e.lookup(event.Identity)
	if err != nil {
		return err
	}
	if err := take(ctx, s.sendLock, e.done); err != nil {
		return err
	}
	defer func() { <-s.sendLock }()
	e.mu.Lock()
	if e.ctx.Err() != nil {
		e.mu.Unlock()
		return e.endError()
	}
	limit := e.peerHeaderLimit
	e.workers.Add(1)
	e.mu.Unlock()
	defer e.workers.Done()
	s.mu.Lock()
	if s.failure != nil {
		err = s.failure
		s.mu.Unlock()
		return err
	}
	if s.localEnd {
		s.mu.Unlock()
		return &StreamError{Identity: s.id, Code: ErrCodeMessageError, Message: "send after stream end"}
	}
	initial := s.outHeaders
	length := s.outLength
	count := s.outBytes
	method := s.method
	s.mu.Unlock()
	kind := frameHeaders
	var payload []byte
	switch event.Kind {
	case Headers, Informational, Trailers:
		if event.Kind == Trailers && (!initial || !event.EndStream) || event.Kind != Trailers && initial || event.Kind == Informational && (e.cfg.Client || event.EndStream) {
			return &StreamError{Identity: s.id, Code: ErrCodeMessageError, Message: "invalid outbound header sequence"}
		}
		if event.Kind != Trailers {
			length, err = messageLength(event.Headers, method)
			if err != nil {
				return err
			}
		}
		payload, err = encodeHeaders(event.Headers)
		if err != nil {
			return err
		}
		decoded := uint64(0)
		for _, field := range event.Headers {
			decoded += uint64(len(field.Name) + len(field.Value) + 32)
		}
		if decoded > limit {
			return &StreamError{Identity: s.id, Code: ErrCodeExcessiveLoad, Message: "peer field section limit"}
		}
	case Data:
		if !initial {
			return &StreamError{Identity: s.id, Code: ErrCodeFrameUnexpected, Message: "DATA before initial headers"}
		}
		kind, payload = frameData, event.Data
		count += uint64(len(payload))
		if count < s.outBytes || length >= 0 && count > uint64(length) {
			return &StreamError{Identity: s.id, Code: ErrCodeMessageError, Message: "outbound body length exceeded"}
		}
	default:
		return errors.New("h3: unsupported outbound event")
	}
	if event.EndStream && length >= 0 && count != uint64(length) {
		return &StreamError{Identity: s.id, Code: ErrCodeMessageError, Message: "outbound body length mismatch"}
	}
	if e.cfg.Client && event.Kind == Headers {
		s.mu.Lock()
		for _, field := range event.Headers {
			if field.Name == ":method" {
				s.method = field.Value
			}
		}
		s.mu.Unlock()
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { cancelRequestStream(s.wire, ErrCodeRequestCancelled); close(callbackDone) })
	err = writeFrame(s.wire, kind, payload)
	if err == nil && event.EndStream {
		err = s.wire.Close()
	}
	if !stop() {
		<-callbackDone
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		err = streamTransportError(err, s.id)
		if ctx.Err() == nil {
			cause := streamTransportError(context.Cause(requestWriteContext(s.wire)), s.id)
			if reset, ok := errors.AsType[*StreamError](cause); ok {
				err = reset
			}
		}
		s.fail(ErrCodeRequestCancelled, err)
		return err
	}
	s.mu.Lock()
	if event.Kind != Informational {
		s.outHeaders = true
		s.outLength = length
		s.outBytes = count
	}
	s.localEnd = event.EndStream
	s.signalLocked()
	s.mu.Unlock()
	e.retire(s)
	return nil
}

func headerLength(fields []HeaderField) (int64, error) {
	length := int64(-1)
	for _, field := range fields {
		if strings.EqualFold(field.Name, "content-length") {
			if field.Value == "" {
				return 0, errors.New("h3: invalid content-length")
			}
			for _, digit := range []byte(field.Value) {
				if digit < '0' || digit > '9' {
					return 0, errors.New("h3: invalid content-length")
				}
			}
			value, err := strconv.ParseInt(field.Value, 10, 64)
			if err != nil || value < 0 || length >= 0 && length != value {
				return 0, errors.New("h3: invalid content-length")
			}
			length = value
		}
	}
	return length, nil
}

func messageLength(fields []HeaderField, method string) (int64, error) {
	length, err := headerLength(fields)
	if err != nil {
		return 0, err
	}
	for _, field := range fields {
		if field.Name == ":status" && (method == "HEAD" || field.Value == "204" || field.Value == "304") {
			return 0, nil
		}
	}
	return length, nil
}

func validatePseudoFields(fields []HeaderField, response bool) error {
	pseudo := make(map[string]bool)
	for _, field := range fields {
		if !strings.HasPrefix(field.Name, ":") {
			continue
		}
		allowed := field.Name == ":status"
		if !response {
			allowed = field.Name == ":method" || field.Name == ":scheme" || field.Name == ":path" || field.Name == ":authority"
		}
		if !allowed {
			return errors.New("h3: unknown pseudo-header for endpoint role")
		}
		pseudo[field.Name] = true
	}
	required := []string{":method", ":scheme", ":path"}
	if response {
		required = []string{":status"}
	}
	for _, name := range required {
		if !pseudo[name] {
			return errors.New("h3: required pseudo-header is missing: " + name)
		}
	}
	return nil
}

func validateFields(fields []HeaderField, trailers bool) error {
	regular := false
	pseudo := make(map[string]bool)
	for _, field := range fields {
		isPseudo := strings.HasPrefix(field.Name, ":")
		name := strings.TrimPrefix(field.Name, ":")
		if name != strings.ToLower(name) || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(field.Value) {
			return errors.New("h3: invalid header field")
		}
		if isPseudo {
			switch field.Name {
			case ":method", ":scheme", ":authority", ":path", ":status", ":protocol":
			default:
				return errors.New("h3: unknown pseudo-header")
			}
			if regular || trailers || pseudo[field.Name] {
				return errors.New("h3: duplicate or misplaced pseudo-header")
			}
			pseudo[field.Name] = true
		} else {
			regular = true
		}
		if name == "connection" || name == "proxy-connection" || name == "keep-alive" || name == "transfer-encoding" || name == "upgrade" || name == "te" && field.Value != "trailers" {
			return errors.New("h3: prohibited connection-specific field")
		}
	}
	return nil
}

func (e *Endpoint) readRequest(s *requestState) {
	initial := false
	length := int64(-1)
	received := uint64(0)
	trailers := false
	for {
		parsed, err := readFrame(s.wire)
		if err != nil {
			if errors.Is(err, io.EOF) && initial && (length < 0 || received == uint64(length)) {
				if !s.enqueue(Event{Kind: Data, Identity: s.id, EndStream: true}) {
					return
				}
				s.mu.Lock()
				s.remoteEnd = true
				s.signalLocked()
				s.mu.Unlock()
				e.retire(s)
				return
			}
			if e.ctx.Err() != nil {
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
			err = streamTransportError(err, s.id)
			code := ErrCodeRequestIncomplete
			if initial && length >= 0 && received != uint64(length) && errors.Is(err, io.EOF) {
				code = ErrCodeMessageError
			}
			s.fail(code, err)
			return
		}
		if trailers {
			s.fail(ErrCodeFrameUnexpected, errors.New("h3: frame after trailers"))
			return
		}
		switch parsed.kind {
		case frameHeaders:
			if !s.reserve(0) {
				return
			}
			payload, err := readPayload(s.wire, parsed.length, MaxHeaderBytes)
			if err != nil {
				s.fail(ErrCodeFrameError, err)
				return
			}
			fields, err := decodeHeaders(payload)
			if err != nil {
				e.fail(connectionError(ErrCodeQPACKDecompressionFailed, err.Error()))
				return
			}
			if !initial {
				if err := validatePseudoFields(fields, e.cfg.Client); err != nil {
					e.fail(connectionError(ErrCodeGeneralProtocol, err.Error()))
					return
				}
			}
			if e.cfg.ValidateInboundHeaders {
				if err := validateFields(fields, initial); err != nil {
					s.fail(ErrCodeMessageError, err)
					return
				}
			}
			kind := Headers
			if initial {
				kind = Trailers
				trailers = true
			} else {
				if !e.cfg.Client {
					s.mu.Lock()
					for _, field := range fields {
						if field.Name == ":method" {
							s.method = field.Value
						}
					}
					s.mu.Unlock()
				}
				s.mu.Lock()
				method := s.method
				s.mu.Unlock()
				length, err = messageLength(fields, method)
				if err != nil {
					s.fail(ErrCodeMessageError, err)
					return
				}
				if e.cfg.Client {
					for _, field := range fields {
						if field.Name == ":status" {
							status, err := strconv.Atoi(field.Value)
							if err != nil || status < 100 || status > 999 || status == 101 {
								s.fail(ErrCodeMessageError, errors.New("h3: invalid status"))
								return
							}
							if status < 200 {
								kind = Informational
							}
						}
					}
				}
			}
			event := Event{Kind: kind, Identity: s.id, Headers: fields}
			if !e.cfg.Client && !initial {
				if !e.notify(event) {
					return
				}
			} else if !s.enqueue(event) {
				return
			}
			initial = initial || kind != Informational
		case frameData:
			if !initial {
				s.fail(ErrCodeFrameUnexpected, errors.New("h3: DATA before initial headers"))
				return
			}
			for remaining := parsed.length; remaining > 0; {
				size := int(min(remaining, ChunkSize))
				if !s.reserve(size) {
					return
				}
				data := make([]byte, size)
				if _, err := io.ReadFull(s.wire, data); err != nil {
					s.fail(ErrCodeRequestIncomplete, streamTransportError(err, s.id))
					return
				}
				next := received + uint64(size)
				if next < received || length >= 0 && next > uint64(length) {
					s.fail(ErrCodeMessageError, errors.New("h3: body length exceeded"))
					return
				}
				received = next
				if !s.enqueue(Event{Kind: Data, Identity: s.id, Data: data}) {
					return
				}
				remaining -= uint64(size)
			}
		case framePushPromise:
			if !e.cfg.Client {
				e.fail(connectionError(ErrCodeFrameUnexpected, "client sent PUSH_PROMISE"))
				return
			}
			payload, err := readPayload(s.wire, parsed.length, MaxHeaderBytes)
			if err != nil {
				e.fail(err)
				return
			}
			reader := strings.NewReader(string(payload))
			id, err := readVarint(reader)
			if err != nil {
				e.fail(connectionError(ErrCodeFrameError, "truncated push promise"))
				return
			}
			if err := e.controlFrame(e.ctx, frameCancelPush, appendVarint(nil, id)); err != nil {
				e.fail(err)
				return
			}
		default:
			e.fail(connectionError(ErrCodeFrameUnexpected, "control frame on request stream"))
			return
		}
	}
}

func (e *Endpoint) watchWriteSide(s *requestState) {
	ctx := requestWriteContext(s.wire)
	select {
	case <-ctx.Done():
	case <-e.ctx.Done():
		return
	}
	if e.ctx.Err() != nil {
		return
	}
	if cause := context.Cause(e.conn.context()); cause != nil {
		e.fail(connectionTransportError(cause))
		return
	}
	failure := streamTransportError(context.Cause(ctx), s.id)
	if reset, ok := errors.AsType[*StreamError](failure); ok {
		s.fail(reset.Code, reset)
	}
	// A local FIN closes the write context without a stream error. It must not
	// cancel the still-active response/read half of the bidirectional exchange.
}

func (e *Endpoint) acceptRequests() {
	for {
		wire, err := e.conn.acceptStream(e.ctx)
		if err != nil {
			if e.ctx.Err() == nil {
				e.fail(connectionTransportError(err))
			}
			return
		}
		if e.cfg.Client || uint64(wire.StreamID())%4 != 0 {
			cancelRequestStream(wire, ErrCodeStreamCreation)
			e.fail(connectionError(ErrCodeStreamCreation, "server-initiated request stream"))
			return
		}
		e.mu.Lock()
		if e.ctx.Err() != nil || e.draining || len(e.streams)+e.opening >= MaxConcurrentStreams {
			e.mu.Unlock()
			cancelRequestStream(wire, ErrCodeRequestRejected)
			continue
		}
		s := newRequestState(e, wire)
		e.streams[s.id.Stream] = s
		e.workers.Go(func() { e.readRequest(s) })
		e.workers.Go(func() { e.watchWriteSide(s) })
		e.mu.Unlock()
	}
}
