// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"slices"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer/layertest"
	"github.com/zchee/mitmproxy-go/tlsparse"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func await[T any](t testing.TB, ch <-chan T) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(layertest.Timeout):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("operation did not complete:\n%s", buf[:n])
		var zero T
		return zero
	}
}

type pipeConn struct{ net.Conn }

func (c pipeConn) CloseWrite() error { return c.Close() }

// helloMessage uses the names and ALPN offers in upstream's
// client_hello_with_extensions; padding changes only its wire size.
func helloMessage(padding int) []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	extensions := []byte("\x00\x00\x00\x10\x00\x0e\x00\x00\x0bexample.com\x00\x10\x00\x0e\x00\x0c\x02h2\x08http/1.1")
	if padding != 0 {
		extensions = append(extensions, 0, 21, byte(padding>>8), byte(padding))
		extensions = append(extensions, make([]byte, padding)...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func helloRecords(message []byte, recordSize int) []byte {
	var wire []byte
	for len(message) != 0 {
		n := min(recordSize, len(message))
		wire = append(wire, 22, 3, 3, byte(n>>8), byte(n))
		wire = append(wire, message[:n]...)
		message = message[n:]
	}
	return wire
}

func TestReadClientHelloReplay(t *testing.T) {
	message := helloMessage(5000)
	tests := map[string]struct {
		recordSize int
		bytewise   bool
	}{
		"three records":                {recordSize: (len(message) + 2) / 3, bytewise: true},
		"small records":                {recordSize: 512, bytewise: true},
		"split handshake header":       {recordSize: 1, bytewise: true},
		"one read with trailing bytes": {recordSize: len(message)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			peer, raw := net.Pipe()
			t.Cleanup(func() { _ = peer.Close(); _ = raw.Close() })
			if err := raw.SetDeadline(time.Now().Add(layertest.Timeout)); err != nil {
				t.Fatal(err)
			}
			wire := append(helloRecords(message, tt.recordSize), []byte("trailing bytes")...)
			written := make(chan error, 1)
			go func() {
				var err error
				if tt.bytewise {
					for _, b := range wire {
						if _, err = peer.Write([]byte{b}); err != nil {
							break
						}
					}
				} else {
					_, err = peer.Write(wire)
				}
				_ = peer.Close()
				written <- err
			}()
			recorder := proxy.Record(pipeConn{raw})
			hello, err := readClientHello(recorder)
			if err != nil {
				t.Fatalf("readClientHello: %v", err)
			}
			if hello.SNI() != "example.com" {
				t.Errorf("SNI = %q, want example.com", hello.SNI())
			}
			if diff := gocmp.Diff([][]byte{[]byte("h2"), []byte("http/1.1")}, hello.ALPNProtocols()); diff != "" {
				t.Errorf("ALPN (-want +got):\n%s", diff)
			}
			recorder.StopRecording()
			got, err := io.ReadAll(recorder)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, wire) {
				t.Fatalf("replay differs: got %d bytes, want %d", len(got), len(wire))
			}
			if err := await(t, written); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadClientHelloErrors(t *testing.T) {
	tests := map[string]struct {
		wire []byte
		want error
	}{
		"empty record":        {wire: []byte("\x16\x03\x01\x00\x00"), want: tlsparse.ErrMalformed},
		"plaintext":           {wire: []byte("GET /"), want: tlsparse.ErrMalformed},
		"incomplete header":   {wire: []byte("\x16\x03"), want: io.EOF},
		"incomplete record":   {wire: []byte("\x16\x03\x01\x00\x05\x01\x00"), want: io.EOF},
		"oversized handshake": {wire: helloRecords([]byte{1, 1, 0, 0}, 4), want: tlsparse.ErrTooLarge},
		"wire recording cap":  {wire: helloRecords(helloMessage(30000), 1), want: proxy.ErrRecordSize},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			peer, raw := net.Pipe()
			t.Cleanup(func() { _ = peer.Close(); _ = raw.Close() })
			if err := raw.SetDeadline(time.Now().Add(layertest.Timeout)); err != nil {
				t.Fatal(err)
			}
			written := make(chan struct{})
			go func() { _, _ = peer.Write(tt.wire); _ = peer.Close(); close(written) }()
			hello, err := readClientHello(proxy.Record(pipeConn{raw}))
			if hello != nil || !errors.Is(err, tt.want) {
				t.Errorf("readClientHello = %v, %v; want nil, %v", hello, err, tt.want)
			}
			_ = raw.Close()
			await(t, written)
		})
	}
}
