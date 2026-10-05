// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tcplayer

import (
	"context"
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/tcp"
)

// Upstream test_ignore: bytes relay without a flow and without hooks.
func TestIgnore(t *testing.T) {
	tests := map[string]struct{ openServer bool }{
		"existing server": {},
		"open connection": {openServer: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, nil)
			s.ignore = true
			if tt.openServer {
				server := s.context.Server
				s.context.Server = nil
				s.context.Pool = openPool{open: func(_ context.Context, metadata *connection.Server, _ layer.OpenOptions) (layer.Conn, *connection.Server, error) {
					return server, metadata, nil
				}}
			}
			injected := make(chan layer.Injected, 1)
			injected <- layer.Injected{Message: &tcp.Message{FromClient: true, Content: []byte("never forwarded")}}
			s.context.Inject = injected
			s.start(t)
			exchange(t, s.client, s.server, []byte("hello!"), []byte("hello!"))
			exchange(t, s.server, s.client, []byte("hello back!"), []byte("hello back!"))
			s.finish(t)
			if diff := gocmp.Diff([]string(nil), s.observed.events); diff != "" {
				t.Fatalf("ignored connection fired hooks: %s", diff)
			}
			if s.observed.flow != nil {
				t.Fatalf("ignored connection created a flow: %+v", s.observed.flow)
			}
		})
	}
}

// An ignored connection's opening failure surfaces the error without hooks.
func TestIgnoreOpenConnectionError(t *testing.T) {
	s := newSession(t, nil)
	s.ignore = true
	s.context.Server = nil
	want := errors.New("connection refused")
	s.context.Pool = openPool{open: func(context.Context, *connection.Server, layer.OpenOptions) (layer.Conn, *connection.Server, error) {
		return nil, nil, want
	}}
	s.start(t)
	if err := await(t, s.done); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if len(s.observed.events) != 0 {
		t.Fatalf("ignored connection fired hooks: %v", s.observed.events)
	}
}

// The ignore path keeps half-close semantics in both orders.
func TestIgnoreHalfClose(t *testing.T) {
	tests := map[string]struct{ clientFirst bool }{
		"client half-closes": {clientFirst: true},
		"server half-closes": {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSession(t, nil)
			s.ignore = true
			s.start(t)
			first, second := s.client, s.server
			if !tt.clientFirst {
				first, second = second, first
			}
			if err := first.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if n, err := second.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("half-close read = %d, %v", n, err)
			}
			exchange(t, second, first, []byte("still open"), []byte("still open"))
			if err := second.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if err := await(t, s.done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The ignore path replays recorded bytes and passes the shared conformance suite.
func TestIgnoreConformance(t *testing.T) {
	layertest.Conformance(t, func(t *testing.T) layertest.Session {
		s := newSession(t, nil)
		return layertest.Session{
			Client: s.client, Server: s.server,
			ClientInput: s.context.Client, ServerInput: s.context.Server,
			ClientData: []byte("request\n"), ServerData: []byte("response\n"),
			Run: func(ctx context.Context) error {
				l, err := layer.Build(ctx, s.context, hookdata.LayerStack{{Kind: hookdata.LayerTCP, Ignore: true}})
				if err != nil {
					return err
				}
				return l.Run(ctx, s.context)
			},
		}
	})
}
