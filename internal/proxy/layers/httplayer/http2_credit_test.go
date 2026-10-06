// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"errors"
	"io"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

func zeroCreditHTTP2Origin(t *testing.T) (*h2.Endpoint, <-chan uint32) {
	t.Helper()
	conn, peer := layertest.Pipe(t)
	ctx, cancel := context.WithCancel(t.Context())
	endpoint, err := h2.New(conn, h2.Config{Client: true, Descriptor: layer.EndpointDescriptor{Identity: "zero-credit-origin", ConnectionID: "zero-credit-origin"}, ValidateInboundHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	engineDone, peerDone := make(chan error, 1), make(chan error, 1)
	ready, heads := make(chan struct{}), make(chan uint32, 4)
	go func() { engineDone <- endpoint.Run(ctx) }()
	go func() {
		prefix := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(peer, prefix); err != nil {
			peerDone <- err
			return
		}
		if string(prefix) != http2.ClientPreface {
			peerDone <- errors.New("wrong origin client preface")
			return
		}
		reader, writer := http2.NewFramer(nil, peer), http2.NewFramer(peer, nil)
		reader.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		if err := writer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
			peerDone <- err
			return
		}
		for {
			frame, err := reader.ReadFrame()
			if err != nil {
				peerDone <- err
				return
			}
			switch frame := frame.(type) {
			case *http2.SettingsFrame:
				if frame.IsAck() {
					close(ready)
				} else if err := writer.WriteSettingsAck(); err != nil {
					peerDone <- err
					return
				}
			case *http2.MetaHeadersFrame:
				heads <- frame.StreamID
				if frame.StreamID != 1 {
					// A sibling without DATA needs no stream send credit.
					if err := writer.WriteHeaders(http2.HeadersFrameParam{StreamID: frame.StreamID, BlockFragment: []byte{0x89}, EndHeaders: true, EndStream: true}); err != nil {
						peerDone <- err
						return
					}
				}
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = conn.Close()
		_ = peer.Close()
		_ = await(t, engineDone)
		_ = await(t, peerDone)
	})
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return endpoint, heads
}

func TestHTTP2DriverResetWhileWaitingForCredit(t *testing.T) {
	tests := map[string]struct{ body string }{
		"success: original queued bytes released on source reset": {body: "waiting-body"},
		"success: empty source also wakes a credit wait":          {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			stream, _ := newTestStream(t, &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if name == "requestheaders" {
					f.Request.Stream = true
				}
			}})
			peer, source := h2EndpointPair(t)
			destination, originHeads := zeroCreditHTTP2Origin(t)
			clientID, err := peer.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			serverID, err := destination.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := peer.Send(t.Context(), h2.Event{Kind: h2.Headers, Identity: clientID, Headers: []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/blocked"}, {Name: ":authority", Value: "example.com"}}}); err != nil {
				t.Fatal(err)
			}
			head, err := source.Receive(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			client := &http2Server{engine: source, identity: head.Identity, id: 1, normalize: true, head: &head}
			server := &http2Client{engine: destination, identity: serverID, id: 1, normalize: true}
			done := make(chan error, 1)
			go func() { done <- (&streamDriver{stream: stream, client: client, server: server}).run(t.Context()) }()
			if got := await(t, originHeads); got != serverID.Stream {
				t.Fatalf("origin head stream = %d", got)
			}
			if tt.body != "" {
				if err := peer.Send(t.Context(), h2.Event{Kind: h2.Data, Identity: clientID, Data: []byte(tt.body)}); err != nil {
					t.Fatal(err)
				}
			}
			if err := peer.CancelStream(clientID, http2.ErrCodeCancel); err != nil {
				t.Fatal(err)
			}
			if err := await(t, done); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			<-source.StreamDone(head.Identity)
			if got := source.Budget().Granted; got != 0 {
				t.Errorf("source grants after reset = %d", got)
			}
			<-destination.StreamDone(serverID)
			if got := destination.Budget().Granted; got != 0 {
				t.Errorf("destination grants after reset = %d", got)
			}

			// The same two connection owners continue serving another exchange.
			clientID, err = peer.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			serverID, err = destination.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := peer.Send(t.Context(), h2.Event{Kind: h2.Headers, Identity: clientID, Headers: []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/other"}, {Name: ":authority", Value: "example.com"}}, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			head, err = source.Receive(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			sibling := &httpStream{c: stream.c, id: 3}
			client = &http2Server{engine: source, identity: head.Identity, id: 3, normalize: true, head: &head}
			server = &http2Client{engine: destination, identity: serverID, id: 3, normalize: true}
			go func() { done <- (&streamDriver{stream: sibling, client: client, server: server}).run(t.Context()) }()
			if got := await(t, originHeads); got != serverID.Stream {
				t.Fatalf("sibling origin stream = %d", got)
			}
			response, err := peer.ReceiveStream(t.Context(), clientID)
			if err != nil || response.Kind != h2.Headers || !response.EndStream {
				t.Fatalf("sibling response = %+v, error = %v", response, err)
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}
