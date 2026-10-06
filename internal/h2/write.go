// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"bytes"
	"context"
	"io"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type writeKind uint8

const (
	writeInitial writeKind = iota
	writeHeaders
	writeData
	writeCredit
	writeReset
	writeGoAway
	writePing
	writeSettingsAck
	writeTableLimit
)

type writeFrame struct {
	kind     writeKind
	stream   uint32
	end      bool
	ack      bool
	payload  []byte
	fields   []hpack.HeaderField
	value    uint32
	code     http2.ErrCode
	maxFrame uint32
	request  *request
	length   int
}

type writeResult struct {
	frame *writeFrame
	err   error
}

func (e *Endpoint) writeFrames(ctx context.Context, input <-chan *writeFrame, output chan<- writeResult) {
	framer := http2.NewFramer(e.conn, nil)
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-input:
			writeCtx := ctx
			if frame.request != nil {
				writeCtx = frame.request.ctx
			}
			interrupted := make(chan struct{})
			stop := context.AfterFunc(writeCtx, func() {
				_ = e.conn.SetWriteDeadline(time.Unix(1, 0))
				close(interrupted)
			})
			err := e.writeFrame(framer, encoder, &block, frame)
			if !stop() {
				<-interrupted
			}
			if err == nil {
				_ = e.conn.SetWriteDeadline(time.Time{})
			}
			select {
			case output <- writeResult{frame: frame, err: err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}
}

func (e *Endpoint) writeFrame(f *http2.Framer, encoder *hpack.Encoder, block *bytes.Buffer, w *writeFrame) error {
	switch w.kind {
	case writeInitial:
		if e.cfg.Client {
			if _, err := io.WriteString(e.conn, http2.ClientPreface); err != nil {
				return err
			}
		}
		settings := []http2.Setting{{ID: http2.SettingMaxConcurrentStreams, Val: MaxConcurrentStreams}, {ID: http2.SettingInitialWindowSize, Val: InitialStreamWindow}, {ID: http2.SettingMaxFrameSize, Val: MaxFrameSize}}
		if e.cfg.Client {
			settings = append(settings, http2.Setting{ID: http2.SettingEnablePush, Val: 0})
		}
		if err := f.WriteSettings(settings...); err != nil {
			return err
		}
		return f.WriteWindowUpdate(0, (128<<20)-65535)
	case writeHeaders:
		block.Reset()
		for _, field := range w.fields {
			if err := encoder.WriteField(field); err != nil {
				return err
			}
		}
		payload := block.Bytes()
		first := min(len(payload), int(w.maxFrame))
		if err := f.WriteHeaders(http2.HeadersFrameParam{StreamID: w.stream, EndStream: w.end, EndHeaders: first == len(payload), BlockFragment: payload[:first]}); err != nil {
			return err
		}
		payload = payload[first:]
		for len(payload) > 0 {
			n := min(len(payload), int(w.maxFrame))
			if err := f.WriteContinuation(w.stream, n == len(payload), payload[:n]); err != nil {
				return err
			}
			payload = payload[n:]
		}
		return nil
	case writeData:
		return f.WriteData(w.stream, w.end, w.payload)
	case writeCredit:
		return f.WriteWindowUpdate(w.stream, w.value)
	case writeReset:
		return f.WriteRSTStream(w.stream, w.code)
	case writeGoAway:
		return f.WriteGoAway(w.stream, w.code, w.payload)
	case writePing:
		var data [8]byte
		copy(data[:], w.payload)
		return f.WritePing(w.ack, data)
	case writeSettingsAck:
		return f.WriteSettingsAck()
	case writeTableLimit:
		encoder.SetMaxDynamicTableSizeLimit(w.value)
		encoder.SetMaxDynamicTableSize(w.value)
		return nil
	default:
		return protocolError(http2.ErrCodeInternal, "h2: unknown internal write")
	}
}
