// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build h2load

package httplayer

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

func requireLoadNetem(t *testing.T) {
	t.Helper()
	output, err := exec.CommandContext(t.Context(), "tc", "qdisc", "show", "dev", "lo").Output()
	if err != nil || !strings.Contains(string(output), "netem") {
		t.Skip("requires the isolated Linux runner with loopback netem installed")
	}
	fields := strings.Fields(string(output))
	var delay time.Duration
	for i, field := range fields {
		if field == "delay" && i+1 < len(fields) {
			delay, err = time.ParseDuration(fields[i+1])
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if delay != 50*time.Millisecond {
		t.Fatalf("loopback netem delay = %s, require 50 ms: %s", delay, output)
	}
	for _, name := range []string{"tcp_rmem", "tcp_wmem"} {
		value, err := os.ReadFile("/proc/sys/net/ipv4/" + name)
		if err != nil {
			t.Fatal(err)
		}
		limits := strings.Fields(string(value))
		if len(limits) != 3 {
			t.Fatalf("%s = %q", name, value)
		}
		maximum, err := strconv.ParseInt(limits[2], 10, 64)
		if err != nil || maximum < 64<<20 {
			t.Fatalf("%s maximum = %s, require at least 64 MiB: %v", name, limits[2], err)
		}
		t.Logf("%s=%s", name, strings.TrimSpace(string(value)))
	}
	t.Logf("qdisc: %s", strings.TrimSpace(string(output)))
}

func loadDirectDownload(t *testing.T, size, window int64) time.Duration {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	t.Cleanup(cancel)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ready := make(chan *loadHTTP2Peer, 1)
	chunk := make([]byte, 128<<10)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		var peer *loadHTTP2Peer
		initialized := make(chan struct{})
		peer = newLoadHTTP2Peer(t, ctx, conn, false, func(id uint32, fields []hpack.HeaderField, _ bool) {
			<-initialized
			bodySize := size
			for _, field := range fields {
				if field.Name == ":path" && field.Value == "/warm" {
					bodySize = int64(len(chunk))
				}
			}
			peer.workers.Go(func() {
				if peer.headers(id, []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-length", Value: strconv.FormatInt(bodySize, 10)}}, false) == nil {
					_ = peer.body(id, chunk, bodySize)
				}
			})
		}, nil)
		close(initialized)
		ready <- peer
	}()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := newLoadHTTP2Peer(t, ctx, conn, true, nil, nil, window, window)
	_ = await(t, ready)
	request := func(id uint32, path string) error {
		return client.headers(id, []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: listener.Addr().String()}, {Name: ":path", Value: path}}, true)
	}
	if err := request(1, "/warm"); err != nil {
		t.Fatal(err)
	}
	if got := await(t, client.finished); got != 1 {
		t.Fatalf("direct warmup stream = %d", got)
	}
	started := time.Now()
	if err := request(3, "/netem"); err != nil {
		t.Fatal(err)
	}
	if got := await(t, client.finished); got != 3 {
		t.Fatalf("direct completed stream = %d", got)
	}
	elapsed := time.Since(started)
	if got := client.bytes(3); got != size {
		t.Fatalf("direct bytes = %d, want %d", got, size)
	}
	return elapsed
}

func TestHTTP2LoadDirectPeer(t *testing.T) {
	tests := map[string]struct{ size, window int64 }{"success: direct reference uses matched fixed windows": {size: 256 << 20, window: 16 << 20}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if os.Getenv("MITMPROXY_GO_HTTP2_LOAD") != "1" {
				t.Fatal("h2load requires MITMPROXY_GO_HTTP2_LOAD=1 and an isolated runner")
			}
			t.Logf("direct reference: bytes=%d, window=%d, duration=%s", tt.size, tt.window, loadDirectDownload(t, tt.size, tt.window))
		})
	}
}

func TestHTTP2LoadNetem(t *testing.T) {
	requireLoadNetem(t)
	tests := map[string]struct{ size, window int64 }{"success: matched 16 MiB windows keep proxy throughput above 80 percent": {size: 256 << 20, window: 16 << 20}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			direct := loadDirectDownload(t, tt.size, tt.window)
			s := newLoadHTTP2Session(t, 128<<10, nil, 5*time.Minute, tt.window, tt.window)
			started := time.Now()
			if err := s.request(3, "GET", "/netem", true); err != nil {
				t.Fatal(err)
			}
			if got := await(t, s.client.finished); got != 3 {
				t.Fatalf("proxy completed stream = %d", got)
			}
			proxied := time.Since(started)
			if got := s.client.bytes(3); got != tt.size {
				t.Fatalf("proxy bytes = %d, want %d", got, tt.size)
			}
			ratio := float64(direct) / float64(proxied)
			t.Logf("256 MiB netem download, matched stream/connection windows=%d: direct=%s (%.3f MiB/s), proxy=%s (%.3f MiB/s), throughput ratio=%.6f, receive budget=%+v", tt.window, direct, float64(tt.size)/(1<<20)/direct.Seconds(), proxied, float64(tt.size)/(1<<20)/proxied.Seconds(), ratio, s.view.endpoint(t).Budget())
			if ratio < 0.8 {
				t.Errorf("proxy/direct throughput = %.6f, want at least 0.8", ratio)
			}
		})
	}
}
