// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build h2load

package httplayer

import (
	"context"
	"crypto/tls"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/h3"
)

func TestHTTP3LoadTerminalReceipts(t *testing.T) {
	const childEnv = "MITMPROXY_GO_HTTP3_RECEIPT_CASE"
	if mode := os.Getenv(childEnv); mode != "" {
		runHTTP3ReceiptChild(t, mode)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		mode      string
		phase     string
		actual    int64
		validated int64
		cause     string
		success   bool
		available bool
	}{
		"success: transfer publishes before cleanup":                 {mode: "success", phase: "complete", actual: 8, validated: 8, cause: "none", success: true, available: true},
		"success: slow progress completes":                           {mode: "slow-success", phase: "complete", actual: 8, validated: 8, cause: "none", success: true, available: true},
		"error: handshake stall leaves connection state unavailable": {mode: "handshake-stall", phase: "handshake", cause: "deadline"},
		"error: truncated QPACK records the decoder failure":         {mode: "qpack", phase: "headers", cause: "EOF", available: true},
		"error: no start records fatal setup":                        {mode: "no-start", phase: "setup-opt-in", cause: "h2load requires"},
		"error: partial read preserves bytes before EOF":             {mode: "partial", phase: "body-read", actual: 4, cause: "unexpected EOF", available: true},
		"error: partial frame follows validated progress":            {mode: "partial-after-progress", phase: "body-read", actual: 6, validated: 4, cause: "unexpected EOF", available: true},
		"error: stalled live peer reaches deadline":                  {mode: "stall", phase: "body-read", cause: "deadline", available: true},
		"error: slow progress retains partial bytes at deadline":     {mode: "slow-timeout", phase: "body-read", actual: 6, validated: 4, cause: "deadline", available: true},
		"error: early connection close retains typed cause":          {mode: "early-close", phase: "headers", cause: "Application error 0x10e", available: true},
		"error: protocol reset retains typed cause":                  {mode: "reset", phase: "headers", cause: "304", available: true},
		"error: malformed HEADERS kind is recorded":                  {mode: "header-kind", phase: "headers", cause: "want HEADERS", available: true},
		"error: oversized frame is recorded":                         {mode: "header-length", phase: "headers", cause: "frame length =", available: true},
		"error: malformed DATA frame is recorded":                    {mode: "frame-kind", phase: "frame", cause: "frame kind=2", available: true},
		"error: malformed body is not validated":                     {mode: "body", phase: "body-validation", actual: 8, cause: "differs from origin", available: true},
		"error: routing helper fatal preserves original cause":       {mode: "helper", phase: "helper-control", cause: "Application error 0x10e", available: true},
		"error: closed client fails request creation":                {mode: "request-open", phase: "request-open:/download", cause: "Application error 0x10e", available: true},
		"error: worker parsing retains the malformed header cause":   {mode: "worker-read", phase: "origin-request-read", cause: "want HEADERS", available: true},
		"error: concurrent publishers retain the first real cause":   {mode: "concurrent-publish", phase: "origin-control", cause: "Application error 0x10e", available: true},
		"error: worker fatal preserves original write cause":         {mode: "worker", phase: "worker-write", cause: "Application error 0x10e", available: true},
		"error: owner cancellation is not cleanup closure":           {mode: "owner-cancel", phase: "owner-context", cause: "context canceled", available: true},
		"error: warmup reset has its own phase":                      {mode: "warmup-reset", cause: "canceled"},
		"error: EOF is not a late elapsed-limit success":             {mode: "elapsed-limit", phase: "elapsed-limit", actual: 8, validated: 8, cause: "elapsed limit", available: true},
		"error: sibling assertion precedes success publication":      {mode: "sibling-state", phase: "sibling-state", actual: 8, validated: 8, cause: "held request changed", available: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestHTTP3LoadTerminalReceipts$", "-test.v", "-test.timeout=15s", fmt.Sprintf("-test.cpu=%d", runtime.GOMAXPROCS(0)))
			cmd.Env = append(os.Environ(), childEnv+"="+test.mode)
			cmd.WaitDelay = time.Second
			output, err := cmd.CombinedOutput()
			if err != nil {
				if _, ok := errors.AsType[*exec.ExitError](err); !ok {
					t.Fatalf("diagnostic child failed: %v\n%s", err, output)
				}
			}
			text := string(output)
			if got := strings.Count(text, "HTTP3_TERMINAL "); got != 1 {
				t.Fatalf("terminal receipt count = %d, want 1\n%s", got, output)
			}
			if strings.Contains(text, "NETEM ") || strings.Index(text, "HTTP3_TERMINAL ") > strings.Index(text, "HTTP3_DIAGNOSTIC_CLEANUP") || !strings.Contains(text, "HTTP3_DIAGNOSTIC_CLEANUP") || strings.Contains(text, "HTTP3_DIAGNOSTIC_PEER_CLEANUP") && strings.Index(text, "HTTP3_TERMINAL ") > strings.Index(text, "HTTP3_DIAGNOSTIC_PEER_CLEANUP") {
				t.Fatalf("receipt did not precede cleanup in its own namespace:\n%s", output)
			}
			_, data, _ := strings.Cut(text, "HTTP3_TERMINAL ")
			data, _, _ = strings.Cut(data, "\n")
			var fields map[string]jsontext.Value
			if err := json.Unmarshal([]byte(data), &fields); err != nil {
				t.Fatalf("decode terminal receipt: %v\n%s", err, output)
			}
			for _, field := range []string{"phase", "stream", "outcome", "expected_bytes", "actual_read_bytes", "validated_payload_bytes", "elapsed_ns", "last_progress_offset", "terminal_cause_type", "terminal_cause", "client_quic", "origin_quic"} {
				if _, ok := fields[field]; !ok {
					t.Fatalf("receipt lacks %s\n%s", field, output)
				}
			}
			var receipt struct {
				Phase     string `json:"phase"`
				Stream    string `json:"stream"`
				Outcome   string `json:"outcome"`
				Expected  int64  `json:"expected_bytes"`
				Actual    int64  `json:"actual_read_bytes"`
				Validated int64  `json:"validated_payload_bytes"`
				Elapsed   int64  `json:"elapsed_ns"`
				Progress  int64  `json:"last_progress_offset"`
				CauseType string `json:"terminal_cause_type"`
				Cause     string `json:"terminal_cause"`
				Client    string `json:"client_quic"`
				Origin    string `json:"origin_quic"`
			}
			if err := json.Unmarshal([]byte(data), &receipt); err != nil {
				t.Fatal(err)
			}
			want := map[string]bool{"success": test.success, "fatal": !test.success, "outcome": true, "phase": true, "cause": true, "accounting": true, "quic": true, "typed": true, "elapsed": true, "frozen": true, "live": true, "boundary": true}
			got := map[string]bool{
				"success":    receipt.Outcome == "success",
				"fatal":      err != nil,
				"outcome":    receipt.Outcome == "success" || receipt.Outcome == "failure",
				"elapsed":    receipt.Elapsed >= 0,
				"frozen":     true,
				"live":       true,
				"boundary":   !strings.Contains(text, "first-cause elapsed was not frozen before owner unwound"),
				"phase":      test.phase == "" || receipt.Phase == test.phase,
				"cause":      strings.Contains(receipt.Cause, test.cause),
				"accounting": receipt.Actual == test.actual && receipt.Validated == test.validated && receipt.Progress == receipt.Actual && receipt.Expected == 8,
				"quic":       !test.available || strings.Contains(receipt.Client, "handshake=true") && strings.Contains(receipt.Origin, "handshake=true"),
				"typed":      receipt.CauseType != "" && (test.success || receipt.CauseType != "none") && !strings.Contains(receipt.Cause, "0x100"),
			}
			if _, frozen, ok := strings.Cut(text, "HTTP3_FROZEN_ELAPSED="); ok {
				frozen, _, _ = strings.Cut(frozen, "\n")
				ns, err := strconv.ParseInt(strings.TrimSpace(frozen), 10, 64)
				got["frozen"] = err == nil && receipt.Elapsed == ns
				if test.actual > 0 {
					got["elapsed"] = receipt.Elapsed > 0
				}
			}
			if test.mode == "stall" || test.mode == "slow-timeout" {
				got["live"] = strings.Contains(receipt.Client, "context=<nil>:<nil>") && strings.Contains(receipt.Origin, "context=<nil>:<nil>")
				got["elapsed"] = receipt.Elapsed > 0
			}
			if test.mode == "no-start" || test.mode == "handshake-stall" {
				got["quic"] = receipt.Client == "unavailable" && receipt.Origin == "unavailable" && receipt.Stream == "unavailable" && receipt.Elapsed == 0
			}
			if test.mode == "warmup-reset" {
				got["phase"] = strings.HasPrefix(receipt.Phase, "warmup-")
				got["accounting"] = receipt.Expected == http3LoadChunkSize && receipt.Actual == 0 && receipt.Validated == 0
			}
			if test.mode == "early-close" || test.mode == "helper" || test.mode == "worker" || test.mode == "request-open" || test.mode == "concurrent-publish" {
				got["typed"] = receipt.CauseType == fmt.Sprintf("%T", new(quic.ApplicationError)) && !strings.Contains(receipt.Cause, "0x100")
			}
			if test.mode == "reset" {
				got["typed"] = receipt.CauseType == fmt.Sprintf("%T", new(quic.StreamError)) && !strings.Contains(receipt.Cause, "0x100")
			}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Fatalf("terminal receipt (-want +got):\n%s\n%s", diff, output)
			}
			t.Logf("HTTP3_CERTIFIED mode=%s cpu=%d %s", test.mode, runtime.GOMAXPROCS(0), data)
		})
	}
}

func runHTTP3ReceiptChild(t *testing.T, mode string) {
	t.Helper()
	receipt := newLoadHTTP3Receipt(t, 8)
	defer receipt.publish()
	defer func() {
		receipt.mu.Lock()
		failed, frozen, elapsed := receipt.cause != nil, receipt.frozen, receipt.elapsed
		receipt.mu.Unlock()
		if failed && !frozen {
			t.Error("first-cause elapsed was not frozen before owner unwound")
		}
		if frozen {
			t.Logf("HTTP3_FROZEN_ELAPSED=%d", elapsed.Nanoseconds())
		}
	}()
	t.Cleanup(func() {
		t.Log("HTTP3_DIAGNOSTIC_CLEANUP")
		receipt.fail("cleanup", &quic.ApplicationError{ErrorCode: 0x100})
		receipt.publish()
	})
	if mode == "no-start" {
		t.Setenv("MITMPROXY_GO_HTTP2_LOAD", "0")
		newLoadHTTP3Session(t, new(streamAddon), receipt)
		return
	}
	if mode == "handshake-stall" {
		peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			receipt.fail("setup-stalled-peer", err)
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			receipt.fail("setup-client", err)
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = socket.Close() })
		transport := &quic.Transport{Conn: socket}
		t.Cleanup(func() { _ = transport.Close() })
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		_, err = transport.Dial(ctx, peer.LocalAddr(), &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, ServerName: "localhost", InsecureSkipVerify: true}, nil)
		if err == nil {
			t.Fatal("stalled peer unexpectedly completed the handshake")
		}
		receipt.fail("handshake", err)
		t.Fatal(err)
	}
	if mode == "warmup-reset" {
		t.Setenv("MITMPROXY_GO_HTTP2_LOAD", "1")
		observer := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
			if name == "requestheaders" && f.Request.Path == "/warm" {
				if err := f.Kill(); err != nil {
					receipt.fail("kill", err)
					t.Error(err)
				}
			}
		}}
		newLoadHTTP3Session(t, observer, receipt)
		t.Fatal("warmup cancellation unexpectedly completed")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	listener, target := newHTTP3RoutingListener(t, func(err error) { receipt.fail("setup-listener", err) })
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		receipt.fail("setup-socket", err)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	transport := &quic.Transport{Conn: socket}
	t.Cleanup(func() { _ = transport.Close() })
	client, err := transport.Dial(ctx, target, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, ServerName: "localhost", InsecureSkipVerify: true}, nil)
	if err != nil {
		receipt.fail("handshake", err)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0x100, "") })
	origin, err := listener.Accept(ctx)
	if err != nil {
		receipt.fail("handshake", err)
		t.Fatal(err)
	}
	receipt.client, receipt.origin = client, origin
	t.Cleanup(func() {
		t.Log("HTTP3_DIAGNOSTIC_PEER_CLEANUP")
		_ = origin.CloseWithError(0x100, "")
	})
	if mode == "concurrent-publish" {
		_ = origin.CloseWithError(0x10e, "controlled first-cause closure")
		_, cause := origin.OpenUniStreamSync(ctx)
		if cause == nil {
			t.Fatal("closed peer unexpectedly opened a stream")
		}
		receipt.fail("origin-control", cause)
		cancel()
		var workers sync.WaitGroup
		workers.Go(func() {
			receipt.fail("owner-context", context.Cause(ctx))
			receipt.publish()
		})
		workers.Go(func() {
			receipt.fail("cleanup", &quic.ApplicationError{ErrorCode: 0x100})
			receipt.publish()
		})
		workers.Wait()
		if receipt.cause != cause {
			t.Fatal("concurrent terminal paths replaced the original error")
		}
		t.Fatal(cause)
	}
	if mode == "helper" {
		_ = origin.CloseWithError(0x10e, "controlled helper closure")
		startHTTP3RoutingPeer(t, ctx, origin, func(err error) { receipt.fail("helper-control", err) })
		t.Fatal("routing helper unexpectedly succeeded")
	}
	if mode == "request-open" {
		_ = client.CloseWithError(0x10e, "controlled request-open closure")
		session := &loadHTTP3Session{ctx: ctx, client: client, receipt: receipt, authority: target.String()}
		session.request(t, "/download", true)
		t.Fatal("closed client unexpectedly opened a request")
	}
	if mode == "owner-cancel" {
		cancel()
		receipt.fail("owner-context", context.Cause(ctx))
		t.Fatal(context.Cause(ctx))
	}
	request, err := client.OpenStreamSync(ctx)
	if err != nil {
		receipt.fail("request", err)
		t.Fatal(err)
	}
	receipt.phaseStream("request", request)
	if mode == "worker-read" {
		writeHTTP3TestFrame(t, loadHTTP3Writer{request, receipt, "request-write"}, 0, nil)
	} else {
		writeHTTP3TestHeaders(t, loadHTTP3Writer{request, receipt, "request-write"}, []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/download"}})
	}
	if err := request.Close(); err != nil {
		receipt.fail("request-close", err)
		t.Fatal(err)
	}
	response, err := origin.AcceptStream(ctx)
	if err != nil {
		receipt.fail("origin-accept", err)
		t.Fatal(err)
	}
	if mode == "worker-read" {
		var workers sync.WaitGroup
		workers.Go(func() {
			defer receipt.publish()
			readLoadHTTP3Message(t, response, receipt)
		})
		workers.Wait()
		return
	}
	readLoadHTTP3Message(t, response, receipt)
	if mode == "worker" {
		_ = origin.CloseWithError(0x10e, "controlled worker closure")
		var workers sync.WaitGroup
		workers.Go(func() {
			defer receipt.publish()
			writeHTTP3TestFrame(t, loadHTTP3Writer{response, receipt, "worker-write"}, 0, make([]byte, 8))
		})
		workers.Wait()
		return
	}
	started := time.Now()
	receipt.started.Store(&started)
	deadline := 2 * time.Second
	if mode == "stall" || mode == "slow-timeout" {
		deadline = 100 * time.Millisecond
	}
	if err := request.SetReadDeadline(started.Add(deadline)); err != nil {
		receipt.fail("read-deadline", err)
		t.Fatal(err)
	}
	if mode == "early-close" {
		_ = origin.CloseWithError(0x10e, "controlled early peer closure")
		readLoadHTTP3Body(t, request, 8, receipt)
		return
	}
	if mode == "reset" {
		response.CancelWrite(0x130)
		readLoadHTTP3Body(t, request, 8, receipt)
		return
	}
	writer := loadHTTP3Writer{response, receipt, "origin-write"}
	switch mode {
	case "header-kind":
		writeHTTP3TestFrame(t, writer, 0, nil)
	case "qpack":
		writeHTTP3TestFrame(t, writer, 1, []byte{0, 0, 0xff})
	case "header-length":
		frame := quicvarint.Append(nil, 1)
		frame = quicvarint.Append(frame, h3.MaxHeaderBytes+1)
		if _, err := writer.Write(frame); err != nil {
			t.Fatal(err)
		}
	default:
		writeHTTP3TestHeaders(t, writer, []qpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-length", Value: "8"}})
		writeHTTP3ReceiptBody(t, ctx, mode, writer)
	}
	if mode != "stall" && mode != "slow-timeout" {
		if err := response.Close(); err != nil {
			receipt.fail("origin-close", err)
			t.Fatal(err)
		}
	}
	readLoadHTTP3Body(t, request, 8, receipt)
	elapsed := receipt.freezeElapsed()
	if mode == "elapsed-limit" {
		<-time.After(20 * time.Millisecond)
		if elapsed <= 10*time.Millisecond {
			t.Fatal("controlled slow peer did not exceed diagnostic elapsed limit")
		}
		receipt.fail("elapsed-limit", fmt.Errorf("diagnostic elapsed limit exceeded: %s", elapsed))
		t.Error("diagnostic elapsed limit exceeded")
		return
	}
	if mode == "sibling-state" {
		cause := errors.New("held request changed during sibling response")
		receipt.fail("sibling-state", cause)
		t.Fatal(cause)
	}
	receipt.complete()
}

func writeHTTP3ReceiptBody(t *testing.T, ctx context.Context, mode string, writer loadHTTP3Writer) {
	t.Helper()
	partial := func(size uint64, bytes int) {
		frame := quicvarint.Append(nil, 0)
		frame = quicvarint.Append(frame, size)
		frame = append(frame, make([]byte, bytes)...)
		if _, err := writer.Write(frame); err != nil {
			t.Fatal(err)
		}
	}
	switch mode {
	case "partial":
		partial(8, 4)
	case "partial-after-progress":
		writeHTTP3TestFrame(t, writer, 0, make([]byte, 4))
		partial(4, 2)
	case "stall":
		partial(8, 0)
	case "frame-kind":
		writeHTTP3TestFrame(t, writer, 2, nil)
	case "body":
		writeHTTP3TestFrame(t, writer, 0, []byte{0, 0, 0, 1, 0, 0, 0, 0})
	case "slow-success", "elapsed-limit", "slow-timeout":
		writeHTTP3TestFrame(t, writer, 0, make([]byte, 4))
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			writer.receipt.fail("owner-context", context.Cause(ctx))
			t.Fatal(context.Cause(ctx))
		}
		if mode == "slow-timeout" {
			partial(4, 2)
		} else {
			writeHTTP3TestFrame(t, writer, 0, make([]byte, 4))
		}
	default:
		writeHTTP3TestFrame(t, writer, 0, make([]byte, 8))
	}
}
