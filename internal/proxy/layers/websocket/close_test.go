// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package websocket

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/options"
)

type terminalCheckedConn struct {
	net.Conn
	manager *addon.Manager
	flow    *flow.HTTPFlow
	checked chan bool
	ctx     context.Context
}

func (c terminalCheckedConn) Write(b []byte) (int, error) {
	if err := c.manager.Do(context.WithoutCancel(c.ctx), func(context.Context) error {
		ws := c.flow.WebSocket
		c.checked <- ws != nil && ws.TimestampEnd != nil && ws.ClosedByClient != nil && *ws.ClosedByClient && ws.CloseCode != nil && *ws.CloseCode == 1000 && ws.CloseReason != nil && *ws.CloseReason == "done"
		return nil
	}); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func TestCloseMetadataPrecedesTransportWrites(t *testing.T) {
	client, clientInput := layertest.Pipe(t)
	server, serverInput := layertest.Pipe(t)
	manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	f := flow.NewHTTPFlow(nil, nil, true)
	checked := make(chan bool, 4)
	l, err := New(Config{Flow: f, Client: terminalCheckedConn{clientInput, manager, f, checked, t.Context()}, Server: terminalCheckedConn{serverInput, manager, f, checked, t.Context()}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	finished := make(chan struct{})
	t.Cleanup(func() { cancel(); await(t, finished) })
	go func() {
		done <- l.Run(ctx, &layer.Context{Hooks: &proxy.HookRunner{Manager: manager}, Do: manager.Do})
		close(finished)
	}()
	clientWS, serverWS := gows.NewClientConn(client), gows.NewServerConn(server)
	written := make(chan error, 1)
	go func() {
		written <- clientWS.WriteFrame(gows.OpcodeClose, true, gows.AppendCloseBody(nil, gows.CloseNormalClosure, []byte("done")), false)
	}()
	for _, peer := range []*gows.Conn{clientWS, serverWS} {
		if !await(t, checked) {
			t.Error("terminal metadata was absent when a Close transport write started")
		}
		if frame := readFrame(t, peer); frame.Header.Opcode != gows.OpcodeClose {
			t.Fatalf("expected Close, got %+v", frame)
		}
	}
	if err := errors.Join(await(t, written), await(t, done)); err != nil {
		t.Fatal(err)
	}
}
