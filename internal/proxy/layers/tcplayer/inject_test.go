// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tcplayer

import (
	"bytes"
	"context"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tcp"
)

// Upstream test_inject: messages queued before opening and in both directions.
func TestInjectMessages(t *testing.T) {
	tests := map[string]struct {
		fromClient bool
		content    string
	}{
		"to server": {fromClient: true, content: "hello!"},
		"to client": {content: "I have already done the greeting for you."},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			injected := make(chan layer.Injected, 1)
			a := &observer{started: make(chan *flow.TCPFlow, 1)}
			s := newSession(t, a)
			s.context.Inject = injected
			server := s.context.Server
			s.context.Server = nil
			opening, release := make(chan struct{}), make(chan struct{})
			s.context.Pool = openPool{open: func(ctx context.Context, metadata *connection.Server, _ layer.OpenOptions) (layer.Conn, *connection.Server, error) {
				close(opening)
				select {
				case <-release:
					return server, metadata, nil
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				}
			}}
			s.start(t)
			f := await(t, a.started)
			await(t, opening)
			message := &tcp.Message{FromClient: tt.fromClient, Content: []byte(tt.content), Timestamp: -1}
			injected <- layer.Injected{Flow: f, Message: message}
			close(release)
			destination := s.client
			if tt.fromClient {
				destination = s.server
			}
			got := make([]byte, len(tt.content))
			if _, err := io.ReadFull(destination, got); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.content, string(got)); diff != "" {
				t.Fatal(diff)
			}
			s.finish(t)
			if diff := gocmp.Diff([]string{"tcp_start", "tcp_message", "tcp_end"}, a.events); diff != "" {
				t.Fatal(diff)
			}
			if len(f.Messages) != 1 || f.Messages[0] == message || f.Messages[0].Timestamp <= 0 {
				t.Fatalf("injection did not create one fresh received message: %+v", f.Messages)
			}
		})
	}
}

func TestInjectRewriteAndInvalidMessages(t *testing.T) {
	injected := make(chan layer.Injected, 8)
	received := make(chan *tcp.Message, 8)
	a := &observer{
		started: make(chan *flow.TCPFlow, 1),
		message: func(_ context.Context, f *flow.TCPFlow) error {
			m := f.Messages[len(f.Messages)-1]
			copy(m.Content, bytes.ToUpper(m.Content))
			received <- m.Clone()
			return nil
		},
	}
	s := newSession(t, a)
	s.context.Inject = injected
	s.start(t)
	f := await(t, a.started)
	message := &tcp.Message{FromClient: true, Content: []byte("rewrite"), Timestamp: -1}
	injected <- layer.Injected{Flow: flow.NewTCPFlow(nil, nil, true), Message: message}
	injected <- layer.Injected{Flow: f, Message: "not a TCP message"}
	injected <- layer.Injected{Flow: f, Message: (*tcp.Message)(nil)}
	injected <- layer.Injected{Flow: f, Message: message}
	got := make([]byte, len(message.Content))
	if _, err := io.ReadFull(s.server, got); err != nil || string(got) != "REWRITE" {
		t.Fatalf("rewritten injection = %q, %v", got, err)
	}
	await(t, received)
	injected <- layer.Injected{Flow: f, Message: &tcp.Message{FromClient: false}}
	if m := await(t, received); m.FromClient || len(m.Content) != 0 || m.Timestamp <= 0 {
		t.Fatalf("empty injected message = %+v", m)
	}
	close(injected)
	exchange(t, s.client, s.server, []byte("after close"), []byte("AFTER CLOSE"))
	s.finish(t)
	if len(f.Messages) != 3 {
		t.Fatalf("message count = %d, want valid injection, empty injection, and network data", len(f.Messages))
	}
	if diff := gocmp.Diff("rewrite", string(message.Content)); diff != "" {
		t.Fatalf("hook mutated caller's injection: %s", diff)
	}
}

func TestInjectWaitsForCurrentHook(t *testing.T) {
	injected := make(chan layer.Injected, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	a := &observer{started: make(chan *flow.TCPFlow, 1)}
	a.message = func(ctx context.Context, f *flow.TCPFlow) error {
		if len(f.Messages) != 1 {
			return nil
		}
		last := f.Messages[0].Clone()
		_, err := addon.Concurrent(ctx, func(ctx context.Context) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		if len(f.Messages) != 1 {
			t.Errorf("message appended during suspended hook: %d messages", len(f.Messages))
		}
		if diff := gocmp.Diff(last, f.Messages[0]); diff != "" {
			t.Errorf("suspended hook's message changed: %s", diff)
		}
		return err
	}
	s := newSession(t, a)
	s.context.Inject = injected
	s.start(t)
	f := await(t, a.started)
	if _, err := s.client.Write([]byte("network")); err != nil {
		t.Fatal(err)
	}
	await(t, entered)
	injected <- layer.Injected{Flow: f, Message: &tcp.Message{FromClient: true, Content: []byte("injected")}}
	if _, err := s.server.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	if err := s.manager.Do(t.Context(), func(context.Context) error {
		if len(f.Messages) != 1 {
			t.Errorf("injection bypassed the flow owner: %d messages", len(f.Messages))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	close(release)
	got := make([]byte, len("networkinjected"))
	if _, err := io.ReadFull(s.server, got); err != nil || string(got) != "networkinjected" {
		t.Fatalf("server received %q, %v", got, err)
	}
	got = make([]byte, len("reply"))
	if _, err := io.ReadFull(s.client, got); err != nil || string(got) != "reply" {
		t.Fatalf("client received %q, %v", got, err)
	}
	s.finish(t)
	if len(f.Messages) != 3 {
		t.Fatalf("recorded %d messages, want network, injection, and reply", len(f.Messages))
	}
}
