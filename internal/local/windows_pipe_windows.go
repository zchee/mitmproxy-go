// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"

	"golang.org/x/sys/windows"
)

// An overlapped operation owns its buffer and event until completion, including
// canceled operations. Closing prevents new I/O before canceling and joining it.
type windowsMessagePipe struct {
	handle windows.Handle
	mu     sync.Mutex
	closed bool
	active sync.WaitGroup
	once   sync.Once
	err    error
}

func (p *windowsMessagePipe) operation(ctx context.Context, initiate func(*windows.Overlapped, *uint32) error) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(event) }()
	overlapped := &windows.Overlapped{HEvent: event}
	p.mu.Lock()
	if p.closed || ctx.Err() != nil {
		p.mu.Unlock()
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, net.ErrClosed
	}
	p.active.Add(1)
	defer p.active.Done()
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = windows.CancelIoEx(p.handle, overlapped)
		close(canceled)
	})
	joined := false
	defer func() {
		if !joined && !stop() {
			<-canceled
		}
	}()
	var count uint32
	err = initiate(overlapped, &count)
	p.mu.Unlock()
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		// Cancellation may have fired just before the kernel saw the operation.
		if ctx.Err() != nil {
			_ = windows.CancelIoEx(p.handle, overlapped)
		}
		err = windows.GetOverlappedResult(p.handle, overlapped, &count, true)
	}
	if !stop() {
		<-canceled
	}
	joined = true
	runtime.KeepAlive(overlapped)
	if ctx.Err() != nil {
		return count, ctx.Err()
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return count, errors.Join(net.ErrClosed, err)
	}
	return count, err
}

func (p *windowsMessagePipe) connect(ctx context.Context) error {
	_, err := p.operation(ctx, func(overlapped *windows.Overlapped, _ *uint32) error {
		err := windows.ConnectNamedPipe(p.handle, overlapped)
		if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			return nil
		}
		return err
	})
	return err
}

func (p *windowsMessagePipe) read(ctx context.Context, data []byte) (int, error) {
	count, err := p.operation(ctx, func(overlapped *windows.Overlapped, count *uint32) error {
		return windows.ReadFile(p.handle, data, count, overlapped)
	})
	runtime.KeepAlive(data)
	if errors.Is(err, windows.ERROR_MORE_DATA) || int(count) > maxNativeIPCMessageSize {
		return int(count), errNativeMessageTooLarge
	}
	if err == nil && count == 0 {
		err = io.EOF
	}
	return int(count), err
}

func (p *windowsMessagePipe) write(ctx context.Context, data []byte) (int, error) {
	count, err := p.operation(ctx, func(overlapped *windows.Overlapped, count *uint32) error {
		return windows.WriteFile(p.handle, data, count, overlapped)
	})
	runtime.KeepAlive(data)
	if err == nil && int(count) != len(data) {
		err = io.ErrShortWrite
	}
	return int(count), err
}

func (p *windowsMessagePipe) Close() error {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		_ = windows.CancelIoEx(p.handle, nil)
		p.mu.Unlock()
		p.active.Wait()
		p.err = windows.CloseHandle(p.handle)
	})
	return p.err
}
