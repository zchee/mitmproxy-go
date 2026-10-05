// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxy

import (
	"io"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// MaxRecordBytes bounds sniffed bytes and a single Peek request. A protocol
// that needs more must stop recording before continuing to read.
const MaxRecordBytes = layer.MaxRecordBytes

// ErrRecordSize reports a negative Peek size or an exhausted recording bound.
var ErrRecordSize = layer.ErrRecordSize

// Record wraps c with bounded recording and replay. Call StopRecording at a
// handover; a later handover may wrap the resulting connection again. Reads
// and recording operations belong to one goroutine; other net.Conn methods
// retain the concurrency guarantees of c.
func Record(c layer.Conn) layer.Recorder {
	return &recorder{Conn: c, recording: true}
}

type recorder struct {
	layer.Conn
	buf       []byte
	pos       int
	err       error
	recording bool
}

// Read replays buffered bytes or reads and records new transport bytes.
func (r *recorder) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.pos < len(r.buf) {
		n := copy(p, r.buf[r.pos:])
		r.pos += n
		if !r.recording {
			r.buf = r.buf[r.pos:]
			r.pos = 0
			if len(r.buf) == 0 {
				r.buf = nil
			}
		}
		return n, nil
	}
	if r.err != nil {
		err := r.err
		r.err = nil
		return 0, err
	}
	if r.recording {
		remaining := MaxRecordBytes - len(r.buf)
		if remaining == 0 {
			return 0, ErrRecordSize
		}
		p = p[:min(len(p), remaining)]
	}
	n, err := r.Conn.Read(p)
	if r.recording && n > 0 {
		r.buf = append(r.buf, p[:n]...)
		r.pos += n
	}
	return n, err
}

// Buffered returns the number of unread bytes in the recording buffer.
func (r *recorder) Buffered() int { return len(r.buf) - r.pos }

// Peek buffers and returns the next n bytes without consuming them, subject to the recording limit.
func (r *recorder) Peek(n int) ([]byte, error) {
	if n < 0 || n > MaxRecordBytes {
		return nil, ErrRecordSize
	}
	if r.pos+n > MaxRecordBytes {
		return r.buf[r.pos:], ErrRecordSize
	}
	for empty := 0; r.Buffered() < n; {
		if r.err != nil {
			return r.buf[r.pos:], r.err
		}
		// Allocate only a fixed read window, not a peer-provided length.
		var window [4096]byte
		count, err := r.Conn.Read(window[:min(len(window), n-r.Buffered())])
		r.buf = append(r.buf, window[:count]...)
		r.err = err
		if count == 0 && err == nil {
			empty++
			if empty == 100 {
				r.err = io.ErrNoProgress
			}
		} else {
			empty = 0
		}
	}
	return r.buf[r.pos : r.pos+n], nil
}

// StopRecording stops capturing new bytes and rewinds the buffer for replay.
func (r *recorder) StopRecording() {
	if r.recording {
		r.recording = false
		r.pos = 0
	}
}
