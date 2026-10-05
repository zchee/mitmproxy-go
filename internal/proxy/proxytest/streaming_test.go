// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build integration && !race

package proxytest_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

type bodyStreamHooks struct {
	upload    bool
	transform bool
	headers   atomic.Int32
	complete  atomic.Int32
	final     atomic.Int32
	done      chan bool
}

func (a *bodyStreamHooks) RequestHeaders(_ context.Context, f *flow.HTTPFlow) error {
	if a.upload {
		a.prepare(&f.Request.Message)
	}
	return nil
}

func (a *bodyStreamHooks) ResponseHeaders(_ context.Context, f *flow.HTTPFlow) error {
	if !a.upload {
		a.prepare(&f.Response.Message)
	}
	return nil
}

func (a *bodyStreamHooks) Request(_ context.Context, f *flow.HTTPFlow) error {
	if a.upload {
		a.complete.Add(1)
		a.done <- f.Request.RawContent == nil
	}
	return nil
}

func (a *bodyStreamHooks) Response(_ context.Context, f *flow.HTTPFlow) error {
	if !a.upload {
		a.complete.Add(1)
		a.done <- f.Response.RawContent == nil
	}
	return nil
}

func (a *bodyStreamHooks) prepare(message *httpmsg.Message) {
	a.headers.Add(1)
	if a.transform {
		message.StreamFunc = func(chunk []byte) [][]byte {
			if len(chunk) == 0 {
				a.final.Add(1)
			}
			return [][]byte{bytes.ToUpper(chunk)}
		}
	}
}

func TestLargeBodyStreaming(t *testing.T) {
	const bodySize = 100 << 20
	tests := map[string]struct{ upload bool }{
		"success: response": {},
		"success: upload":   {upload: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			hooks := &bodyStreamHooks{upload: tt.upload, done: make(chan bool, 2)}
			tail := make(chan struct{})
			releaseTail := sync.OnceFunc(func() { close(tail) })
			writeBody := func(w io.Writer) error {
				buf := bytes.Repeat([]byte{'x'}, 32<<10)
				remaining := bodySize - 1
				for remaining > 0 {
					n, err := w.Write(buf[:min(remaining, len(buf))])
					if err != nil {
						return err
					}
					if n == 0 {
						return io.ErrNoProgress
					}
					remaining -= n
				}
				select {
				case <-tail:
				case <-t.Context().Done():
					return t.Context().Err()
				case <-time.After(30 * time.Second):
					buf := make([]byte, 1<<20)
					return fmt.Errorf("streamed prefix did not reach its receiver:\n%s", buf[:runtime.Stack(buf, true)])
				}
				_, err := w.Write(buf[:1])
				return err
			}
			readBody := func(r io.Reader) error {
				var first [1]byte
				if _, err := io.ReadFull(r, first[:]); err != nil {
					return err
				}
				if first[0] != 'x' || hooks.headers.Load() != 1 {
					return fmt.Errorf("first body byte = %q, header hooks = %d", first, hooks.headers.Load())
				}
				if n, err := io.CopyN(io.Discard, r, bodySize-2); err != nil {
					return fmt.Errorf("streamed prefix = %d bytes: %w", n+1, err)
				}
				// Hold the last byte at the sender until the receiver has consumed
				// the prefix, proving the completion hook does not run early.
				if got := hooks.complete.Load(); got != 0 {
					return fmt.Errorf("completion hook fired %d times before the last body byte", got)
				}
				releaseTail()
				if _, err := io.ReadFull(r, first[:]); err != nil {
					return err
				}
				if first[0] != 'x' {
					return fmt.Errorf("last body byte = %q, want x", first)
				}
				if n, err := io.Copy(io.Discard, r); err != nil || n != 0 {
					return fmt.Errorf("trailing body bytes = %d, error = %v", n, err)
				}
				return nil
			}
			originDone := make(chan error, 1)
			origin := proxytest.StartOrigin(t, func(conn net.Conn) {
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					originDone <- err
					return
				}
				defer func() { _ = request.Body.Close() }()
				if tt.upload {
					err = readBody(request.Body)
					if err == nil {
						_, err = io.WriteString(conn, "HTTP/1.1 204 No Content\r\n\r\n")
					}
				} else {
					_, err = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", bodySize)
					if err == nil {
						err = writeBody(conn)
					}
				}
				originDone <- err
			})
			p := proxytest.Start(t, proxytest.WithOrigin("example.test", origin), proxytest.WithAddons(hooks), proxytest.WithOptions(map[string]any{
				"stream_large_bodies": new("1m"), "store_streamed_bodies": false,
			}))
			client := dial(t, p.Addr)
			t.Cleanup(releaseTail)

			runtime.GC()
			samples := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
			metrics.Read(samples)
			baseline := samples[0].Value.Uint64()
			stop := make(chan struct{})
			stopped := make(chan struct{})
			peakResult := make(chan uint64, 1)
			stopSampling := sync.OnceFunc(func() { close(stop); <-stopped })
			t.Cleanup(stopSampling)
			go func() {
				defer close(stopped)
				ticker := time.NewTicker(50 * time.Millisecond)
				defer ticker.Stop()
				peak := baseline
				for {
					select {
					case <-ticker.C:
						metrics.Read(samples)
						peak = max(peak, samples[0].Value.Uint64())
					case <-stop:
						metrics.Read(samples)
						peakResult <- max(peak, samples[0].Value.Uint64())
						return
					}
				}
			}()

			if tt.upload {
				if _, err := fmt.Fprintf(client, "POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nContent-Length: %d\r\n\r\n", bodySize); err != nil {
					t.Fatal(err)
				}
				if err := writeBody(client); err != nil {
					t.Fatal(err)
				}
			} else if _, err := io.WriteString(client, "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			if tt.upload {
				if response.StatusCode != http.StatusNoContent {
					t.Fatalf("upload response = %d", response.StatusCode)
				}
			} else {
				if response.StatusCode != http.StatusOK || response.ContentLength != bodySize {
					t.Fatalf("response = %d, length = %d", response.StatusCode, response.ContentLength)
				}
				if err := readBody(response.Body); err != nil {
					t.Fatal(err)
				}
			}
			if err := receive(t, originDone); err != nil {
				t.Fatalf("origin transfer: %v", err)
			}
			if rawNil := receive(t, hooks.done); !rawNil {
				t.Fatal("completion hook retained the streamed body")
			}
			if got := hooks.complete.Load(); got != 1 {
				t.Fatalf("completion hook count = %d, want 1", got)
			}
			stopSampling()
			growth := receive(t, peakResult) - baseline
			t.Logf("relayed %d bytes; peak heap growth %d bytes", bodySize, growth)
			if growth >= 50<<20 {
				t.Fatalf("peak heap growth = %d bytes, want below %d", growth, 50<<20)
			}
		})
	}
}

func TestStreamingTransforms(t *testing.T) {
	tests := map[string]struct{ upload bool }{
		"success: response": {},
		"success: request":  {upload: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			const input = "abc def 0123\r\n"
			const want = "ABC DEF 0123\r\n"
			hooks := &bodyStreamHooks{upload: tt.upload, transform: true, done: make(chan bool, 2)}
			originBody := make(chan []byte, 1)
			origin := proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.upload {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
					}
					originBody <- body
					w.WriteHeader(http.StatusNoContent)
				} else {
					_, _ = io.WriteString(w, input)
				}
			}))
			p := proxytest.Start(t, proxytest.WithOrigin("example.test", origin), proxytest.WithAddons(hooks))
			request := "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"
			if tt.upload {
				request = fmt.Sprintf("POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nContent-Length: %d\r\n\r\n%s", len(input), input)
			}
			response, body := httpExchange(t, dial(t, p.Addr), request)
			if tt.upload {
				if response.StatusCode != http.StatusNoContent {
					t.Fatalf("upload response = %d", response.StatusCode)
				}
				body = receive(t, originBody)
			} else if response.StatusCode != http.StatusOK {
				t.Fatalf("response = %d", response.StatusCode)
			}
			if diff := gocmp.Diff(want, string(body)); diff != "" {
				t.Fatalf("transformed body (-want +got):\n%s", diff)
			}
			if rawNil := receive(t, hooks.done); !rawNil {
				t.Fatal("completion hook retained transformed body")
			}
			if hooks.final.Load() != 1 || hooks.complete.Load() != 1 || hooks.headers.Load() != 1 {
				t.Fatalf("hook counts: headers=%d complete=%d final-empty=%d; want 1 each", hooks.headers.Load(), hooks.complete.Load(), hooks.final.Load())
			}
		})
	}
}
