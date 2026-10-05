// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dump

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

type fidelityLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write appends log bytes while holding the buffer mutex.
func (l *fidelityLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// String returns the collected log text while holding the buffer mutex.
func (l *fidelityLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func writeHTTPBytes(w io.Writer, data string) error {
	for i := range len(data) {
		if _, err := io.WriteString(w, data[i:i+1]); err != nil {
			return err
		}
	}
	return nil
}

func TestHTTPAssemblyFidelity(t *testing.T) {
	const clean = "X-Foo: one\r\nx-bar: two\r\nX-FOO: three\r\n"
	// Pinned upstream test/mitmproxy/net/http/http1/test_read.py,
	// TestReadHeaders.test_read_continued, expects the joined field value
	// b"one\r\n two" from b"Header: one\r\n\ttwo\r\n".
	const folded = "Header: one\r\n\ttwo\r\nHeader2: three\r\n"
	const joined = "Header: one\r\n two\r\nHeader2: three\r\n"
	tests := map[string]struct {
		request, requestWire   string
		response, responseWire string
		count                  uint64
	}{
		"success: exact casing order and duplicates":      {request: clean, requestWire: clean, response: clean, responseWire: clean},
		"success: request continuation matches upstream":  {request: folded, requestWire: joined, response: clean, responseWire: clean, count: 1},
		"success: response continuation matches upstream": {request: clean, requestWire: clean, response: folded, responseWire: joined, count: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			// Use origin-form so routing does not itself change the request
			// line: the counter must reflect only the tested header bytes.
			request := "GET /fidelity HTTP/1.1\r\n" + tt.request + "Host: " + listener.Addr().String() + "\r\n\r\n"
			requestWire := "GET /fidelity HTTP/1.1\r\n" + tt.requestWire + "Host: " + listener.Addr().String() + "\r\n\r\n"
			response := "HTTP/1.1 200 OK\r\n" + tt.response + "Content-Length: 2\r\n\r\nok"
			responseWire := "HTTP/1.1 200 OK\r\n" + tt.responseWire + "Content-Length: 2\r\n\r\nok"
			originDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					originDone <- err
					return
				}
				defer func() { _ = conn.Close() }()
				if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					originDone <- err
					return
				}
				got := make([]byte, len(requestWire))
				if _, err := io.ReadFull(conn, got); err != nil {
					originDone <- err
					return
				}
				if diff := gocmp.Diff(requestWire, string(got)); diff != "" {
					originDone <- fmt.Errorf("origin request (-want +got):\n%s", diff)
					return
				}
				originDone <- writeHTTPBytes(conn, response)
			}()
			logs := new(fidelityLog)
			m, addr, _ := startHTTPDump(t, "regular", logs)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			client, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := writeHTTPBytes(client, request); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(responseWire))
			if _, err := io.ReadFull(client, got); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(responseWire, string(got)); diff != "" {
				t.Errorf("client response (-want +got):\n%s", diff)
			}
			if err := awaitHTTP(t, originDone); err != nil {
				t.Fatal(err)
			}
			if count := m.httpFidelity.Load(); count != tt.count {
				t.Errorf("http_fidelity = %d, want %d", count, tt.count)
			}
			var records []string
			for line := range strings.SplitSeq(logs.String(), "\n") {
				if strings.Contains(line, "http_fidelity=") {
					records = append(records, line)
				}
			}
			if len(records) != int(tt.count) {
				t.Fatalf("fidelity logs = %q, want %d records", records, tt.count)
			}
			if tt.count != 0 && (!strings.Contains(records[0], "["+client.LocalAddr().String()+"]") || !strings.Contains(records[0], "http_fidelity=1")) {
				t.Errorf("fidelity log lacks client prefix or total: %s", records[0])
			}
		})
	}
}
