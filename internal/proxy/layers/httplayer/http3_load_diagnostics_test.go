// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build h2load

package httplayer

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"
)

func readLoadHTTP3Message(t *testing.T, reader io.Reader, receipt *loadHTTP3Receipt) ([]qpack.HeaderField, []byte, []qpack.HeaderField) {
	t.Helper()
	reader = loadHTTP3Reader{reader, receipt, "origin-request-read"}
	headers := readHTTP3TestHeaders(t, reader)
	var body []byte
	var trailers []qpack.HeaderField
	for {
		var first [1]byte
		_, err := io.ReadFull(reader, first[:])
		if errors.Is(err, io.EOF) {
			return headers, body, trailers
		}
		if err != nil {
			receipt.fail("origin-request-read", err)
			t.Fatal(err)
		}
		framed := loadHTTP3Reader{io.MultiReader(bytes.NewReader(first[:]), reader), receipt, "origin-request-frame"}
		if first[0] == 1 {
			trailers = readHTTP3TestHeaders(t, framed)
			continue
		}
		kind, payload := readHTTP3TestFrame(t, framed)
		if kind != 0 {
			receipt.fail("origin-request-frame", fmt.Errorf("message frame = %d, want DATA or trailers", kind))
			t.Fatalf("message frame = %d, want DATA or trailers", kind)
		}
		body = append(body, payload...)
	}
}

type loadHTTP3Receipt struct {
	mu        sync.Mutex
	phase     string
	stage     string
	stream    string
	expected  int64
	cause     error
	client    *quic.Conn
	origin    *quic.Conn
	completed bool
	published bool
	started   atomic.Pointer[time.Time]
	actual    atomic.Int64
	validated atomic.Int64
	elapsed   time.Duration
	frozen    bool
	publish   func()
}

func newLoadHTTP3Receipt(t *testing.T, expected int64) *loadHTTP3Receipt {
	r := &loadHTTP3Receipt{phase: "setup", stream: "unavailable", expected: expected}
	r.publish = sync.OnceFunc(func() {
		r.freezeElapsed()
		r.mu.Lock()
		defer r.mu.Unlock()
		r.published = true
		cause := r.cause
		if cause == nil && !r.completed {
			cause = errors.New("load owner exited before completing terminal assertions")
		}
		outcome, causeType, causeText := "success", "none", "none"
		if cause != nil {
			outcome, causeType, causeText = "failure", fmt.Sprintf("%T", cause), cause.Error()
		}
		validated, actual := r.validated.Load(), r.actual.Load()
		receipt := struct {
			Phase                 string `json:"phase"`
			Stream                string `json:"stream"`
			Outcome               string `json:"outcome"`
			ExpectedBytes         int64  `json:"expected_bytes"`
			ActualReadBytes       int64  `json:"actual_read_bytes"`
			ValidatedPayloadBytes int64  `json:"validated_payload_bytes"`
			ElapsedNS             int64  `json:"elapsed_ns"`
			LastProgressOffset    int64  `json:"last_progress_offset"`
			TerminalCauseType     string `json:"terminal_cause_type"`
			TerminalCause         string `json:"terminal_cause"`
			ClientQUIC            string `json:"client_quic"`
			OriginQUIC            string `json:"origin_quic"`
		}{r.phase, r.stream, outcome, r.expected, actual, validated, r.elapsed.Nanoseconds(), actual, causeType, causeText, loadHTTP3QUICState(r.client), loadHTTP3QUICState(r.origin)}
		data, err := json.Marshal(receipt)
		if err != nil {
			t.Errorf("encode HTTP3 terminal receipt: %v", err)
			return
		}
		t.Logf("HTTP3_TERMINAL %s", data)
	})
	return r
}

func loadHTTP3QUICState(conn *quic.Conn) string {
	if conn == nil {
		return "unavailable"
	}
	state := conn.ConnectionState()
	cause := context.Cause(conn.Context())
	return fmt.Sprintf("version=%s handshake=%t alpn=%s used_0rtt=%t gso=%t datagrams=%t/%t partial_reset=%t/%t context=%T:%v", state.Version, state.TLS.HandshakeComplete, state.TLS.NegotiatedProtocol, state.Used0RTT, state.GSO, state.SupportsDatagrams.Local, state.SupportsDatagrams.Remote, state.SupportsStreamResetPartialDelivery.Local, state.SupportsStreamResetPartialDelivery.Remote, cause, cause)
}

func (r *loadHTTP3Receipt) phaseStream(phase string, stream *quic.Stream) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cause != nil || r.published {
		return
	}
	r.phase, r.stream = r.stage+phase, "unavailable"
	if stream != nil {
		r.stream = strconv.FormatInt(int64(stream.StreamID()), 10)
	}
}

func (r *loadHTTP3Receipt) fail(phase string, err error) bool {
	if err == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cause == nil && !r.published {
		if phase != "" {
			r.phase = r.stage + phase
		}
		r.cause = err
		if !r.frozen {
			if started := r.started.Load(); started != nil {
				r.elapsed = time.Since(*started)
			}
			r.frozen = true
		}
		return true
	}
	return false
}

func (r *loadHTTP3Receipt) freezeElapsed() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.frozen {
		if started := r.started.Load(); started != nil {
			r.elapsed = time.Since(*started)
		}
		r.frozen = true
	}
	return r.elapsed
}

func (r *loadHTTP3Receipt) complete() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cause == nil && !r.published {
		r.phase, r.completed = "complete", true
	}
}

// I/O wrappers retain the original error before a shared helper calls FailNow.
// EOF at a frame boundary is completion; the framing helper still diagnoses truncation.
type loadHTTP3Reader struct {
	io.Reader
	receipt *loadHTTP3Receipt
	phase   string
}

func (r loadHTTP3Reader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		r.receipt.fail(r.phase, err)
	}
	return n, err
}

func (r loadHTTP3Reader) recordHTTP3Failure(err error) { r.receipt.fail(r.phase, err) }

type loadHTTP3Writer struct {
	io.Writer
	receipt *loadHTTP3Receipt
	phase   string
}

func (w loadHTTP3Writer) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	w.receipt.fail(w.phase, err)
	return n, err
}
