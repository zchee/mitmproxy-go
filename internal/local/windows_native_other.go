// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !windows

package local

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
)

type windowsUnavailableRedirector struct{ closed atomic.Bool }

func newWindowsRedirector(_, _ string) Redirector { return new(windowsUnavailableRedirector) }

func (r *windowsUnavailableRedirector) operationError(ctx context.Context) error {
	if r.closed.Load() {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("windows redirector requires a Windows host")
}

func (r *windowsUnavailableRedirector) Launch(ctx context.Context) error {
	return r.operationError(ctx)
}

func (r *windowsUnavailableRedirector) SetIntercept(ctx context.Context, _ string) error {
	return r.operationError(ctx)
}

func (r *windowsUnavailableRedirector) ReadPacket(ctx context.Context) (*PacketWithMeta, error) {
	return nil, r.operationError(ctx)
}

func (r *windowsUnavailableRedirector) WritePacket(ctx context.Context, _ *Packet) error {
	return r.operationError(ctx)
}

func (r *windowsUnavailableRedirector) Close() error { r.closed.Store(true); return nil }
