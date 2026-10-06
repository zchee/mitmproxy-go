// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"sync"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

const (
	injectionCapacity = layer.InjectionCapacity
	maxInjectionBytes = layer.MaxInjectionBytes
)

var (
	// ErrInjectionFull means the owning layer has not drained its bounded queue.
	ErrInjectionFull = layer.ErrInjectionFull
	// ErrInjectionSize means the injected payload exceeds its protocol's bound.
	ErrInjectionSize = layer.ErrInjectionSize
	// ErrInjectionType means the injection does not carry a compatible message.
	ErrInjectionType = layer.ErrInjectionType
	// ErrInjectionIdentity means the explicit identity differs from the flow's ID.
	ErrInjectionIdentity = layer.ErrInjectionIdentity
	// ErrInjectionDirection means the explicit peer direction is invalid or mismatched.
	ErrInjectionDirection = layer.ErrInjectionDirection
	// ErrInjectionClosed means the flow or its client connection has finished.
	ErrInjectionClosed = layer.ErrInjectionClosed
)

type injectionQueue struct {
	messages chan layer.Injected
	done     chan struct{}
	stop     sync.Once
}

func newInjectionQueue() *injectionQueue {
	return &injectionQueue{messages: make(chan layer.Injected, injectionCapacity), done: make(chan struct{})}
}

func (q *injectionQueue) send(injected layer.Injected) error {
	select {
	case <-q.done:
		return ErrInjectionClosed
	default:
	}
	var fromClient bool
	switch message := injected.Message.(type) {
	case *tcp.Message:
		if message == nil {
			return ErrInjectionType
		}
		if len(message.Content) > maxInjectionBytes {
			return ErrInjectionSize
		}
		fromClient = message.FromClient
		injected.Message = message.Clone()
	case *udp.Message:
		if message == nil {
			return ErrInjectionType
		}
		if len(message.Content) > layer.MaxUDPPacketBytes {
			return ErrInjectionSize
		}
		fromClient = message.FromClient
		injected.Message = message.Clone()
	case *websocket.Message:
		if message == nil || message.Type != websocket.OpText && message.Type != websocket.OpBinary {
			return ErrInjectionType
		}
		if len(message.Content) > maxInjectionBytes {
			return ErrInjectionSize
		}
		fromClient = message.FromClient
		injected.Message = message.Clone()
	default:
		return ErrInjectionType
	}
	direction := layer.DirectionFromServer
	if fromClient {
		direction = layer.DirectionFromClient
	}
	if injected.Direction != layer.DirectionUnspecified && injected.Direction != direction {
		return ErrInjectionDirection
	}
	injected.Direction = direction
	select {
	case <-q.done:
		return ErrInjectionClosed
	case q.messages <- injected:
		return nil
	default:
		return ErrInjectionFull
	}
}

func (q *injectionQueue) close() {
	// Only the lifetime signal closes. A concurrent sender can never panic by
	// writing to a closed data channel; the layer exits on its own context.
	q.stop.Do(func() { close(q.done) })
}
