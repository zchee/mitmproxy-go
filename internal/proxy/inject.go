// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"errors"
	"net"
	"sync"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tcp"
)

const (
	injectionCapacity = 64
	maxInjectionBytes = 128 << 10
)

var (
	// ErrInjectionFull means the owning layer has not drained its bounded queue.
	ErrInjectionFull = errors.New("proxy: injection queue is full")
	// ErrInjectionSize means the injected TCP payload exceeds 128 KiB.
	ErrInjectionSize = errors.New("proxy: injected message exceeds 128 KiB")
	// ErrInjectionType means the injection does not carry a supported message.
	ErrInjectionType = errors.New("proxy: injection requires a TCP message")
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
		return net.ErrClosed
	default:
	}
	message, ok := injected.Message.(*tcp.Message)
	if !ok || message == nil {
		return ErrInjectionType
	}
	if len(message.Content) > maxInjectionBytes {
		return ErrInjectionSize
	}
	injected.Message = message.Clone()
	select {
	case <-q.done:
		return net.ErrClosed
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
