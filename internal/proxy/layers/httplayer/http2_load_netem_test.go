// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build h2load

package httplayer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
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

func awaitLoadNetem(t *testing.T, client, origin *loadHTTP2Peer, ownerDone <-chan struct{}) (uint32, bool) {
	t.Helper()
	assertAlive := func() {
		for _, peer := range []*loadHTTP2Peer{client, origin} {
			peer.mu.Lock()
			err := peer.failure
			peer.mu.Unlock()
			if err != nil {
				t.Log(`NETEM {"phase":"measured-transfer","outcome":"protocol-failure"}`)
				t.Fatalf("netem protocol failure: %v", err)
			}
			select {
			case <-peer.done:
				t.Log(`NETEM {"phase":"measured-transfer","outcome":"protocol-failure"}`)
				t.Fatal("netem peer ended before measured completion")
			case <-peer.ctx.Done():
				t.Log(`NETEM {"phase":"measured-transfer","outcome":"protocol-failure"}`)
				t.Fatalf("netem peer context ended: %v", peer.ctx.Err())
			default:
			}
		}
		select {
		case <-ownerDone:
			t.Log(`NETEM {"phase":"measured-transfer","outcome":"protocol-failure"}`)
			t.Fatal("netem upstream owner ended before measured completion")
		default:
		}
	}
	timer := time.NewTimer(layertest.Timeout)
	defer timer.Stop()
	select {
	case id := <-client.finished:
		assertAlive()
		return id, true
	case <-client.failed:
	case <-origin.failed:
	case <-client.done:
	case <-origin.done:
	case <-client.ctx.Done():
	case <-origin.ctx.Done():
	case <-ownerDone:
	case <-timer.C:
		// A completion already queued at the deadline is still completion evidence.
		select {
		case id := <-client.finished:
			assertAlive()
			return id, true
		default:
		}
		assertAlive()
		return 0, false
	}
	assertAlive()
	t.Log(`NETEM {"phase":"measured-transfer","outcome":"protocol-failure"}`)
	t.Fatal("netem measured wait ended without a live peer")
	return 0, false
}

func logLoadNetemTimeout(t *testing.T, client, origin *loadHTTP2Peer, format string, args ...any) {
	t.Helper()
	// Serialize the receipt with failure recording so an already-failed peer cannot report a timeout.
	client.mu.Lock()
	defer client.mu.Unlock()
	origin.mu.Lock()
	defer origin.mu.Unlock()
	for _, peer := range []*loadHTTP2Peer{client, origin} {
		if peer.failure != nil {
			t.Log(`NETEM {"phase":"measured-transfer","outcome":"protocol-failure"}`)
			t.Fatalf("netem protocol failure: %v", peer.failure)
		}
	}
	t.Logf(format, args...)
}

func loadDirectDownload(t *testing.T, size, window int64) time.Duration {
	t.Helper()
	elapsed, err := runLoadDirectDownload(t, size, window, loadDirectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return elapsed
}

func runLoadDirectDownload(t *testing.T, size, window int64, options loadDirectOptions) (elapsed time.Duration, result error) {
	t.Helper()
	netem := strings.HasPrefix(t.Name(), "TestHTTP2LoadNetem/")
	if netem {
		t.Log(`NETEM {"phase":"direct-handshake"}`)
	}
	root := os.Getenv("NETWORK_GATE_OUTPUT")
	if root == "" {
		root = t.TempDir()
	}
	terminal := &loadDirectTerminal{root: root, receipt: loadDirectReceipt{Phase: "setup", ExpectedBytes: size, Outcome: "failed"}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	var listener net.Listener
	var originWorker sync.WaitGroup
	defer func() {
		terminal.fail(result)
		if err := terminal.publish(); err != nil {
			result = errors.Join(result, fmt.Errorf("write direct terminal sidecar: %w", err))
		}
		if options.beforeClose != nil {
			options.beforeClose(terminal)
		}
		cleanup := func() {
			cancel()
			if listener != nil {
				_ = listener.Close()
			}
			if terminal.client != nil {
				terminal.client.closeConn()
			}
			originWorker.Wait()
			if terminal.client != nil {
				terminal.client.close()
			}
			if terminal.origin != nil {
				terminal.origin.close()
			}
		}
		if result == nil {
			t.Cleanup(cleanup)
		} else {
			cleanup()
		}
	}()
	var err error
	if options.listen != nil {
		listener, err = options.listen()
	} else {
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
	}
	if err != nil {
		return 0, err
	}
	terminal.receipt.Phase = "direct-handshake"
	type originResult struct {
		peer *loadHTTP2Peer
		err  error
	}
	ready := make(chan originResult, 1)
	chunk := make([]byte, 128<<10)
	originWorker.Go(func() {
		conn, err := listener.Accept()
		if err != nil {
			terminal.fail(err)
			ready <- originResult{err: err}
			return
		}
		if options.originConn != nil {
			conn = options.originConn(conn)
		}
		var peer *loadHTTP2Peer
		initialized := make(chan struct{})
		peer = makeLoadHTTP2Peer(ctx, conn, func(id uint32, fields []hpack.HeaderField, _ bool) {
			<-initialized
			bodySize := size
			for _, field := range fields {
				if field.Name == ":path" && field.Value == "/warm" {
					bodySize = int64(len(chunk))
				}
			}
			peer.workers.Go(func() {
				if options.response != nil {
					peer.recordFailure(options.response(peer, id, bodySize))
					return
				}
				if peer.headers(id, []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-length", Value: strconv.FormatInt(bodySize, 10)}}, false) == nil {
					peer.recordFailure(peer.body(id, chunk, bodySize))
				}
			})
		}, nil, true)
		terminal.mu.Lock()
		terminal.origin = peer
		terminal.mu.Unlock()
		err = peer.setup(false)
		close(initialized)
		terminal.fail(err)
		ready <- originResult{peer: peer, err: err}
	})
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		return 0, err
	}
	if options.clientConn != nil {
		conn = options.clientConn(conn)
	}
	client := makeLoadHTTP2Peer(ctx, conn, nil, nil, true)
	terminal.client = client
	clientReady := make(chan error, 1)
	originWorker.Go(func() { clientReady <- client.setup(true, window, window) })
	var origin *loadHTTP2Peer
	clientStarted := false
	for origin == nil || !clientStarted {
		select {
		case clientErr := <-clientReady:
			if clientErr != nil {
				terminal.fail(clientErr)
				return 0, clientErr
			}
			clientStarted = true
			clientReady = nil
		case accepted := <-ready:
			if accepted.err != nil {
				return 0, accepted.err
			}
			origin = accepted.peer
			ready = nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	terminal.receipt.Phase = "direct-warmup"
	terminal.receipt.ExpectedBytes = int64(len(chunk))
	terminal.receipt.Stream = new(uint32(1))
	if netem {
		t.Log(`NETEM {"phase":"direct-warmup"}`)
	}
	request := func(id uint32, path string) error {
		return client.headers(id, []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: listener.Addr().String()}, {Name: ":path", Value: path}}, true)
	}
	if err := request(1, "/warm"); err != nil {
		return 0, err
	}
	wait := layertest.Timeout
	if options.wait > 0 {
		wait = options.wait
	}
	got, ok, err := awaitLoadDirect(ctx, client, origin, wait)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("direct warmup: %w", context.DeadlineExceeded)
	}
	if got != 1 {
		return 0, fmt.Errorf("direct warmup stream = %d", got)
	}
	terminal.receipt.Phase = "direct-transfer"
	terminal.receipt.ExpectedBytes = size
	terminal.receipt.Stream = new(uint32(3))
	started := time.Now()
	if err := request(3, "/netem"); err != nil {
		elapsed = time.Since(started)
		terminal.receipt.ElapsedNS = new(elapsed.Nanoseconds())
		return elapsed, err
	}
	if netem {
		t.Logf(`NETEM {"phase":"direct-transfer","leg":"direct","stream":3,"expected_bytes":%d,"window":%d}`, size, window)
	}
	completed, ok, err := awaitLoadDirect(ctx, client, origin, wait)
	elapsed = time.Since(started)
	terminal.receipt.ElapsedNS = new(elapsed.Nanoseconds())
	if err != nil {
		terminal.fail(err)
		terminal.receipt.Outcome = "protocol-failure"
		if netem {
			t.Log(`NETEM {"phase":"measured-transfer","outcome":"protocol-failure"}`)
		}
		return elapsed, fmt.Errorf("netem protocol failure: %w", err)
	}
	if !ok {
		terminal.receipt.Outcome = "measured-transfer-timeout"
		terminal.fail(context.DeadlineExceeded)
		if netem {
			logLoadNetemTimeout(t, client, origin, `NETEM {"phase":"measured-transfer-timeout","outcome":"measured-transfer-timeout","leg":"direct","last_phase":"direct-transfer","stream":3,"expected_bytes":%d,"window":%d,"actual_bytes":"unavailable","direct_bytes":"unavailable","proxy_bytes":"unavailable","progress_bytes":%d,"elapsed_ns":%d,"direct_duration_ns":"unavailable","proxy_duration_ns":"unavailable","ratio":"unavailable"}`, size, window, client.bytes(3), elapsed.Nanoseconds())
		}
		return elapsed, errors.New("netem measured transfer did not complete")
	}
	if completed != 3 {
		return elapsed, fmt.Errorf("direct completed stream = %d", completed)
	}
	if got := client.bytes(3); got != size {
		return elapsed, fmt.Errorf("direct bytes = %d, want %d", got, size)
	}
	terminal.receipt.Outcome = "success"
	if netem {
		t.Logf(`NETEM {"phase":"direct-complete","bytes":%d,"duration_ns":%d}`, size, elapsed.Nanoseconds())
	}
	return elapsed, nil
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
	t.Log(`NETEM {"phase":"setup"}`)
	requireLoadNetem(t)
	tests := map[string]struct{ size, window int64 }{"success: matched 16 MiB windows keep proxy throughput above 80 percent": {size: 256 << 20, window: 16 << 20}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			direct := loadDirectDownload(t, tt.size, tt.window)
			t.Log(`NETEM {"phase":"proxy-setup-warmup"}`)
			s := newLoadHTTP2Session(t, 128<<10, nil, 5*time.Minute, tt.window, tt.window)
			started := time.Now()
			if err := s.request(3, "GET", "/netem", true); err != nil {
				t.Fatal(err)
			}
			t.Logf(`NETEM {"phase":"proxy-transfer","leg":"proxy","stream":3,"expected_bytes":%d,"window":%d}`, tt.size, tt.window)
			got, ok := awaitLoadNetem(t, s.client, s.origin, s.view.endpoint(t).Done())
			if !ok {
				logLoadNetemTimeout(t, s.client, s.origin, `NETEM {"phase":"measured-transfer-timeout","outcome":"measured-transfer-timeout","leg":"proxy","last_phase":"proxy-transfer","stream":3,"expected_bytes":%d,"window":%d,"actual_bytes":"unavailable","direct_bytes":%d,"proxy_bytes":"unavailable","progress_bytes":%d,"elapsed_ns":%d,"direct_duration_ns":%d,"proxy_duration_ns":"unavailable","ratio":"unavailable"}`, tt.size, tt.window, tt.size, s.client.bytes(3), time.Since(started).Nanoseconds(), direct.Nanoseconds())
				t.Fatal("netem measured transfer did not complete")
			}
			if got != 3 {
				t.Fatalf("proxy completed stream = %d", got)
			}
			proxied := time.Since(started)
			if got := s.client.bytes(3); got != tt.size {
				t.Fatalf("proxy bytes = %d, want %d", got, tt.size)
			}
			ratio := float64(direct) / float64(proxied)
			outcome := "pass"
			if ratio < 0.8 {
				outcome = "below-floor"
			}
			t.Logf(`NETEM {"phase":"measurement-complete","outcome":%q,"stream":3,"expected_bytes":%d,"window":%d,"direct_bytes":%d,"proxy_bytes":%d,"direct_duration_ns":%d,"proxy_duration_ns":%d,"ratio":%.12g}`, outcome, tt.size, tt.window, tt.size, tt.size, direct.Nanoseconds(), proxied.Nanoseconds(), ratio)
			if ratio < 0.8 {
				t.Errorf("proxy/direct throughput = %.6f, want at least 0.8", ratio)
			}
		})
	}
}
