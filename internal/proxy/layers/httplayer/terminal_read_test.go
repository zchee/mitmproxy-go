// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

// terminalDataConn exercises the io.Reader contract allowing data and an error
// in the same read, after one body chunk has filled the driver's pending slot.
type terminalDataConn struct {
	layer.Conn
	reads     int
	firstBody chan struct{}
}

// Read signals the first body read and returns data with an unexpected EOF on the next read.
func (c *terminalDataConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.reads++
	if c.reads == 2 {
		close(c.firstBody)
	}
	if c.reads == 3 && n > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func TestDriverTerminalReadWithPendingData(t *testing.T) {
	held := make(chan *flow.HTTPFlow, 1)
	a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
		if name == "requestheaders" {
			f.Intercept()
			held <- f
		}
	}}
	s, m := newTestStream(t, a)
	conn, peer := layertest.Pipe(t)
	origin, _ := layertest.Pipe(t)
	fault := &terminalDataConn{Conn: conn, firstBody: make(chan struct{})}
	wire := newWireStore()
	driver := &streamDriver{stream: s, client: newHTTP1Server(fault, wire, nil), server: newHTTP1Client(origin, wire, nil)}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- driver.run(ctx) }()
	write(t, peer, "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 200000\r\n\r\n")
	f := await(t, held)
	write(t, peer, "a")
	await(t, fault.firstBody)
	write(t, peer, "b")
	if err := await(t, done); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal client read = %v, want EOF without resuming", err)
	}
	if err := m.Do(t.Context(), func(context.Context) error {
		if f.Live {
			t.Error("terminated flow remains live")
		}
		f.Resume()
		if diff := gocmp.Diff([]string{"requestheaders"}, a.calls); diff != "" {
			t.Errorf("hooks after terminal read (-want +got):\n%s", diff)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
