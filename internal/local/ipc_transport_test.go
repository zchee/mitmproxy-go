// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	gocmp "github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
)

func TestReadIPC(t *testing.T) {
	bodyRead := errors.New("unexpected body read")
	tests := map[string]struct {
		reader   io.Reader
		expected []string
		wantErr  error
	}{
		"success: fragmented native frame": {
			reader:   iotest.OneByteReader(bytes.NewReader([]byte{0, 0, 0, 3, 0x0a, 1, 'x'})),
			expected: []string{"x"},
		},
		"success: empty message": {
			reader: bytes.NewReader([]byte{0, 0, 0, 0}),
		},
		"error: no prefix": {
			reader: bytes.NewReader(nil), wantErr: io.EOF,
		},
		"error: truncated prefix": {
			reader: bytes.NewReader([]byte{0, 0, 0}), wantErr: io.ErrUnexpectedEOF,
		},
		"error: truncated body": {
			reader: bytes.NewReader([]byte{0, 0, 0, 3, 0x0a, 1}), wantErr: io.ErrUnexpectedEOF,
		},
		"error: oversized prefix rejects before reading body": {
			reader:  io.MultiReader(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff}), iotest.ErrReader(bodyRead)),
			wantErr: errIPCMessageTooLarge,
		},
		"error: invalid protobuf body": {
			reader: bytes.NewReader([]byte{0, 0, 0, 2, 0x0a, 0x80}), wantErr: proto.Error,
		},
		"error: body read failure is preserved": {
			reader:  io.MultiReader(bytes.NewReader([]byte{0, 0, 0, 3}), iotest.ErrReader(bodyRead)),
			wantErr: bodyRead,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			message := new(InterceptConf)
			err := readIPC(test.reader, message)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("readIPC() error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil {
				if diff := gocmp.Diff(test.expected, message.Actions); diff != "" {
					t.Fatalf("actions (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestIPCFrameBoundaries(t *testing.T) {
	tests := map[string]struct {
		actions [][]string
		tail    string
	}{
		"success: consecutive native frames": {
			actions: [][]string{{"curl", "!42"}, {"wget"}},
		},
		"success: handshake preserves raw TCP payload": {
			actions: [][]string{{"curl"}}, tail: "raw TCP bytes",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var stream bytes.Buffer
			for _, actions := range test.actions {
				if err := writeIPC(&stream, &InterceptConf{Actions: actions}); err != nil {
					t.Fatal(err)
				}
			}
			stream.WriteString(test.tail)
			for _, expected := range test.actions {
				message := new(InterceptConf)
				if err := readIPC(&stream, message); err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(expected, message.Actions); diff != "" {
					t.Fatalf("actions (-want +got):\n%s", diff)
				}
			}
			if got := stream.String(); got != test.tail {
				t.Fatalf("handshake consumed subsequent stream bytes: got %q, want %q", got, test.tail)
			}
		})
	}
}

func TestWriteIPC(t *testing.T) {
	writeErr := errors.New("writer failed")
	tests := map[string]struct {
		writer  io.Writer
		message *Packet
		wantErr error
	}{
		"success: one complete frame": {
			writer: new(bytes.Buffer), message: &Packet{Data: []byte("reply")},
		},
		"error: oversized message writes nothing": {
			writer: new(bytes.Buffer), message: &Packet{Data: make([]byte, maxIPCMessageSize)},
			wantErr: errIPCMessageTooLarge,
		},
		"error: writer failure": {
			writer: failingIPCWriter{err: writeErr}, message: &Packet{}, wantErr: writeErr,
		},
		"error: short write": {
			writer: failingIPCWriter{}, message: &Packet{}, wantErr: io.ErrShortWrite,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := writeIPC(test.writer, test.message)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("writeIPC() error = %v, want %v", err, test.wantErr)
			}
			if output, ok := test.writer.(*bytes.Buffer); ok {
				if test.wantErr != nil {
					if output.Len() != 0 {
						t.Fatalf("oversized message wrote %d bytes", output.Len())
					}
					return
				}
				wire := output.Bytes()
				if len(wire) < 4 || binary.BigEndian.Uint32(wire[:4]) != uint32(len(wire)-4) {
					t.Fatalf("invalid native frame: %x", wire)
				}
				decoded := new(Packet)
				if err := readIPC(output, decoded); err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(test.message.Data, decoded.Data); diff != "" {
					t.Fatalf("packet data (-want +got):\n%s", diff)
				}
			}
		})
	}
}

type failingIPCWriter struct{ err error }

func (w failingIPCWriter) Write([]byte) (int, error) { return 0, w.err }
