// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"errors"
	"net"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/tcp"
)

func TestInjectionQueue(t *testing.T) {
	q := newInjectionQueue()
	f := flow.NewTCPFlow(nil, nil, true)
	message := &tcp.Message{FromClient: true, Content: []byte("original"), Timestamp: 123}
	if err := q.send(layer.Injected{Flow: f, Message: message}); err != nil {
		t.Fatal(err)
	}
	message.Content[0] = 'X'
	got := <-q.messages
	if got.Flow != f {
		t.Fatal("injection changed flow identity")
	}
	if diff := gocmp.Diff(&tcp.Message{FromClient: true, Content: []byte("original"), Timestamp: 123}, got.Message); diff != "" {
		t.Fatalf("queued message (-want +got):\n%s", diff)
	}
	for range injectionCapacity {
		if err := q.send(layer.Injected{Flow: f, Message: message}); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.send(layer.Injected{Flow: f, Message: message}); !errors.Is(err, ErrInjectionFull) {
		t.Fatalf("full queue: %v", err)
	}
	q.close()
	q.close()
	if err := q.send(layer.Injected{Flow: f, Message: message}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed full queue: %v", err)
	}
}

func TestInjectionValidation(t *testing.T) {
	tests := map[string]struct {
		message any
		want    error
	}{
		"nil":         {want: ErrInjectionType},
		"typed nil":   {message: (*tcp.Message)(nil), want: ErrInjectionType},
		"unsupported": {message: "not a message", want: ErrInjectionType},
		"oversized":   {message: &tcp.Message{Content: make([]byte, maxInjectionBytes+1)}, want: ErrInjectionSize},
		"boundary":    {message: &tcp.Message{Content: make([]byte, maxInjectionBytes)}},
		"empty":       {message: &tcp.Message{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			q := newInjectionQueue()
			if err := q.send(layer.Injected{Message: tt.message}); !errors.Is(err, tt.want) {
				t.Fatalf("send error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestInjectionConcurrentClose(t *testing.T) {
	q := newInjectionQueue()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 50 {
		wg.Go(func() {
			<-start
			err := q.send(layer.Injected{Message: &tcp.Message{Content: []byte("message")}})
			if err != nil && !errors.Is(err, ErrInjectionFull) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("concurrent injection: %v", err)
			}
		})
	}
	wg.Go(func() { <-start; q.close() })
	close(start)
	wg.Wait()
	if err := q.send(layer.Injected{Message: &tcp.Message{}}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("injection after close = %v", err)
	}
}
