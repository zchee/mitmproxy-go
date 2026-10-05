// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
)

type selectorAddon struct {
	next func(context.Context, *hookdata.NextLayer) error
}

func (a *selectorAddon) NextLayer(ctx context.Context, data *hookdata.NextLayer) error {
	return a.next(ctx, data)
}

type selectedLayer struct{}

func (selectedLayer) Kind() hookdata.LayerKind                  { return "test-selected" }
func (selectedLayer) Run(context.Context, *layer.Context) error { return nil }

var registerSelected = sync.OnceFunc(func() {
	layer.Register("test-selected", func(*layer.Context, hookdata.LayerSpec, layer.Layer) (layer.Layer, error) {
		return selectedLayer{}, nil
	})
})

func newSelector(t *testing.T, client layer.Conn, next func(context.Context, *hookdata.NextLayer) error) *layer.Context {
	t.Helper()
	registerSelected()
	runner := newHookRunner(t, &selectorAddon{next: next})
	return &layer.Context{
		Data: &hookdata.Context{
			Client: connection.NewClient(connection.Address{}, connection.Address{}, 1),
			Server: connection.NewServer(nil),
		},
		Client:    Record(client),
		Record:    Record,
		Hooks:     runner,
		Do:        runner.Manager.Do,
		NextLayer: nextLayer,
	}
}

type selectionResult struct {
	layer layer.Layer
	err   error
}

func startSelection(t *testing.T, ctx context.Context, c *layer.Context) <-chan selectionResult {
	t.Helper()
	done := make(chan selectionResult, 1)
	go func() {
		selected, err := layer.Next(ctx, c)
		done <- selectionResult{selected, err}
	}()
	return done
}

func requireSelection(t *testing.T, done <-chan selectionResult) {
	t.Helper()
	result := await(t, done)
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.layer == nil || result.layer.Kind() != "test-selected" {
		t.Fatalf("selected layer = %v", result.layer)
	}
}

func requireReplay(t *testing.T, reader io.Reader, want []byte) {
	t.Helper()
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(reader)
		done <- result{data, err}
	}()
	got := await(t, done)
	if got.err != nil {
		t.Fatal(got.err)
	}
	if diff := gocmp.Diff(want, got.data); diff != "" {
		t.Fatalf("replayed bytes (-want +got):\n%s", diff)
	}
}

// TestNextLayerReasks ports TestNextLayer.test_simple from
// py:test/mitmproxy/proxy/test_layer.py. The production mode contract excludes
// ask_on_start; the initial hook therefore waits for actual bytes.
func TestNextLayerReasks(t *testing.T) {
	client, peer := layertest.Pipe(t)
	asked := make(chan string, 2)
	c := newSelector(t, client, func(_ context.Context, data *hookdata.NextLayer) error {
		asked <- string(data.DataClient)
		if len(data.DataClient) == 6 {
			data.Layer = hookdata.LayerStack{{Kind: "test-selected"}}
		}
		// A handler owns its input snapshot, not the bytes awaiting replay.
		data.DataClient[0] = 'X'
		return nil
	})
	done := startSelection(t, t.Context(), c)
	if _, err := peer.Write([]byte("foo")); err != nil {
		t.Fatal(err)
	}
	if got := await(t, asked); got != "foo" {
		t.Fatalf("first ask = %q", got)
	}
	if _, err := peer.Write([]byte("bar")); err != nil {
		t.Fatal(err)
	}
	if got := await(t, asked); got != "foobar" {
		t.Fatalf("second ask = %q", got)
	}
	requireSelection(t, done)
	if len(c.Data.Layers) != 1 {
		t.Fatalf("published %d layers, want 1", len(c.Data.Layers))
	}
	// Reads beyond the recording cap must stream after selection, rather than
	// leaving an underlying recorder accumulating application data.
	body := bytes.Repeat([]byte{'b'}, MaxRecordBytes+1)
	written := make(chan error, 1)
	go func() {
		_, err := peer.Write(body)
		if err == nil {
			err = peer.CloseWrite()
		}
		written <- err
	}()
	requireReplay(t, c.Client, append([]byte("foobar"), body...))
	if err := await(t, written); err != nil {
		t.Fatal(err)
	}
}

// TestNextLayerLateReply ports TestNextLayer.test_late_hook_reply: data that
// arrives during a hook is paused, then replayed even if the hook decides.
func TestNextLayerLateReply(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	entered := make(chan struct{})
	release := make(chan struct{})
	c := newSelector(t, memoryConn{Conn: a, input: a}, func(ctx context.Context, data *hookdata.NextLayer) error {
		close(entered)
		_, err := addon.Concurrent(ctx, func(ctx context.Context) error {
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		if string(data.DataClient) != "foo" {
			t.Errorf("pending data changed the in-flight hook: %q", data.DataClient)
		}
		data.Layer = hookdata.LayerStack{{Kind: "test-selected"}}
		return err
	})
	done := startSelection(t, t.Context(), c)
	written := make(chan error, 1)
	go func() { _, err := b.Write([]byte("foo")); written <- err }()
	await(t, entered)
	if err := await(t, written); err != nil {
		t.Fatal(err)
	}
	go func() { _, err := b.Write([]byte("bar")); written <- err }()
	// net.Pipe's write completes only once the selector has read the bytes.
	if err := await(t, written); err != nil {
		t.Fatal(err)
	}
	close(release)
	requireSelection(t, done)
	_ = b.Close()
	requireReplay(t, c.Client, []byte("foobar"))
}

// TestNextLayerClientClose ports TestNextLayer.test_receive_close. Python's
// method-rebinding and repr tests have no Go counterpart: selection returns a
// Layer value instead of replacing an event handler or formatting a stack.
func TestNextLayerClientClose(t *testing.T) {
	tests := map[string]struct{ choose bool }{"undecided": {}, "decided": {true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client, peer := layertest.Pipe(t)
			c := newSelector(t, client, func(_ context.Context, data *hookdata.NextLayer) error {
				if tt.choose {
					data.Layer = hookdata.LayerStack{{Kind: "test-selected"}}
				}
				return nil
			})
			done := startSelection(t, t.Context(), c)
			if _, err := peer.Write([]byte("foo")); err != nil {
				t.Fatal(err)
			}
			if err := peer.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if tt.choose {
				requireSelection(t, done)
				requireReplay(t, c.Client, []byte("foo"))
			} else if result := await(t, done); !errors.Is(result.err, io.EOF) || result.layer != nil {
				t.Fatalf("undecided close = %+v, want EOF without a layer", result)
			}
		})
	}
}

func TestNextLayerServerGreeting(t *testing.T) {
	client, peer := layertest.Pipe(t)
	server, upstream := layertest.Pipe(t)
	c := newSelector(t, client, func(_ context.Context, data *hookdata.NextLayer) error {
		if len(data.DataClient) != 0 || string(data.DataServer) != "220 ready\r\n" {
			t.Errorf("unexpected greeting: client %q, server %q", data.DataClient, data.DataServer)
		}
		data.Layer = hookdata.LayerStack{{Kind: "test-selected"}}
		return nil
	})
	c.Server = Record(server)
	done := startSelection(t, t.Context(), c)
	if _, err := upstream.Write([]byte("220 ready\r\n")); err != nil {
		t.Fatal(err)
	}
	requireSelection(t, done)
	if err := upstream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	requireReplay(t, c.Server, []byte("220 ready\r\n"))
	// The blocked client reader was joined and its deadline cleared.
	if _, err := peer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	requireReplay(t, c.Client, []byte("hello"))
}

func TestNextLayerCancelBeforeData(t *testing.T) {
	client, _ := layertest.Pipe(t)
	var calls atomic.Int32
	c := newSelector(t, client, func(context.Context, *hookdata.NextLayer) error {
		calls.Add(1)
		return nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := startSelection(t, ctx, c)
	cancel()
	if result := await(t, done); !errors.Is(result.err, context.Canceled) {
		t.Fatalf("canceled selection = %+v", result)
	}
	if calls.Load() != 0 {
		t.Fatal("next_layer fired without any received bytes")
	}
}

func TestNextLayerRepeatedHandover(t *testing.T) {
	client, peer := layertest.Pipe(t)
	c := newSelector(t, client, func(_ context.Context, data *hookdata.NextLayer) error {
		data.Layer = hookdata.LayerStack{{Kind: "test-selected"}}
		return nil
	})
	for range 2 {
		done := startSelection(t, t.Context(), c)
		if _, err := peer.Write([]byte("next")); err != nil {
			t.Fatal(err)
		}
		requireSelection(t, done)
		var got [4]byte
		if _, err := io.ReadFull(c.Client, got[:]); err != nil {
			t.Fatal(err)
		}
		if string(got[:]) != "next" {
			t.Fatalf("handover replay = %q", got)
		}
	}
	if len(c.Data.Layers) != 2 {
		t.Fatalf("published %d layers, want 2", len(c.Data.Layers))
	}
}

func TestNextLayerServerEOF(t *testing.T) {
	client, peer := layertest.Pipe(t)
	server, upstream := layertest.Pipe(t)
	c := newSelector(t, client, func(_ context.Context, data *hookdata.NextLayer) error {
		if string(data.DataClient) == "hello" {
			data.Layer = hookdata.LayerStack{{Kind: "test-selected"}}
		}
		return nil
	})
	c.Server = Record(server)
	if err := upstream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	done := startSelection(t, t.Context(), c)
	if _, err := peer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	requireSelection(t, done)
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	requireReplay(t, c.Client, []byte("hello"))
	requireReplay(t, c.Server, []byte{})
}

func TestNextLayerInvalidStack(t *testing.T) {
	tests := map[string]struct{ stack hookdata.LayerStack }{
		"empty":          {hookdata.LayerStack{}},
		"unknown":        {hookdata.LayerStack{{Kind: "unregistered"}}},
		"top-level mode": {hookdata.LayerStack{{Kind: hookdata.LayerRegular}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client, peer := layertest.Pipe(t)
			c := newSelector(t, client, func(_ context.Context, data *hookdata.NextLayer) error {
				data.Layer = tt.stack
				return nil
			})
			done := startSelection(t, t.Context(), c)
			if _, err := peer.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			if result := await(t, done); result.err == nil || result.layer != nil {
				t.Fatalf("invalid selection = %+v", result)
			}
			if len(c.Data.Layers) != 0 {
				t.Fatalf("failed build published layers: %v", c.Data.Layers)
			}
		})
	}
}

func TestNextLayerNoProgress(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	reader := &emptyReader{}
	c := newSelector(t, memoryConn{Conn: a, input: reader}, func(context.Context, *hookdata.NextLayer) error {
		t.Error("hook fired without bytes")
		return nil
	})
	if result := await(t, startSelection(t, t.Context(), c)); !errors.Is(result.err, io.ErrNoProgress) {
		t.Fatalf("empty reads = %+v", result)
	}
	if reader.calls != 100 {
		t.Fatalf("read count = %d, want 100", reader.calls)
	}
}

func TestNextLayerBound(t *testing.T) {
	client, peer := layertest.Pipe(t)
	c := newSelector(t, client, func(_ context.Context, data *hookdata.NextLayer) error {
		if len(data.DataClient) > MaxRecordBytes {
			t.Errorf("unbounded input: %d bytes", len(data.DataClient))
		}
		return nil
	})
	done := startSelection(t, t.Context(), c)
	written := make(chan error, 1)
	go func() { _, err := peer.Write(bytes.Repeat([]byte{'x'}, MaxRecordBytes+1)); written <- err }()
	if result := await(t, done); !errors.Is(result.err, ErrRecordSize) {
		t.Fatalf("oversized selection = %+v", result)
	}
	if err := await(t, written); err != nil {
		t.Fatal(err)
	}
}
