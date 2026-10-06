// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func upgradeSettings(settings ...http2.Setting) []byte {
	var payload []byte
	for _, setting := range settings {
		payload = binary.BigEndian.AppendUint16(payload, uint16(setting.ID))
		payload = binary.BigEndian.AppendUint32(payload, setting.Val)
	}
	return payload
}

func TestUpgradeConfiguration(t *testing.T) {
	tests := map[string]struct {
		client    bool
		request   UpgradeRequest
		wantCode  http2.ErrCode
		wantError string
	}{
		"success: empty settings and body":  {request: UpgradeRequest{Headers: requestFields()}},
		"success: unknown settings ignored": {request: UpgradeRequest{Headers: requestFields(), Settings: upgradeSettings(http2.Setting{ID: 0xff, Val: 123})}},
		"error: client role":                {client: true, request: UpgradeRequest{Headers: requestFields()}, wantError: "server"},
		"error: missing headers":            {wantError: "pseudo"},
		"error: truncated settings":         {request: UpgradeRequest{Headers: requestFields(), Settings: []byte{0}}, wantCode: http2.ErrCodeFrameSize},
		"error: invalid frame size":         {request: UpgradeRequest{Headers: requestFields(), Settings: upgradeSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 1})}, wantCode: http2.ErrCodeProtocol},
		"error: invalid window":             {request: UpgradeRequest{Headers: requestFields(), Settings: upgradeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 31})}, wantCode: http2.ErrCodeFlowControl},
		"error: invalid push":               {request: UpgradeRequest{Headers: requestFields(), Settings: upgradeSettings(http2.Setting{ID: http2.SettingEnablePush, Val: 2})}, wantCode: http2.ErrCodeProtocol},
		"error: oversized body":             {request: UpgradeRequest{Headers: requestFields(), Body: make([]byte, InitialStreamWindow+1)}, wantError: strconv.Itoa(InitialStreamWindow)},
		"error: body length mismatch":       {request: UpgradeRequest{Headers: append(requestFields(), hpack.HeaderField{Name: "content-length", Value: "1"})}, wantError: "InvalidBodyLengthError"},
		"error: invalid body length":        {request: UpgradeRequest{Headers: append(requestFields(), hpack.HeaderField{Name: "content-length", Value: "invalid"})}, wantError: "content-length"},
		"error: invalid header":             {request: UpgradeRequest{Headers: append(requestFields(), hpack.HeaderField{Name: "X-Foo", Value: "bar"})}, wantCode: http2.ErrCodeProtocol},
		"error: oversized header":           {request: UpgradeRequest{Headers: append(requestFields(), hpack.HeaderField{Name: "x-large", Value: strings.Repeat("x", maxHeaderBytes)})}, wantCode: http2.ErrCodeEnhanceYourCalm},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			conn, peer := net.Pipe()
			defer func() { _ = conn.Close(); _ = peer.Close() }()
			e, err := New(conn, Config{Client: test.client, ValidateInboundHeaders: true, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}, Upgrade: &test.request})
			if test.wantCode != 0 || test.wantError != "" {
				if err == nil || e != nil {
					t.Fatalf("New = %v, %v", e, err)
				}
				if test.wantError != "" && !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("New error = %v, want %q", err, test.wantError)
				}
				if test.wantCode != 0 {
					code := http2.ErrCodeNo
					if protocol, ok := errors.AsType[*ProtocolError](err); ok {
						code = protocol.Code
					}
					if connection, ok := errors.AsType[http2.ConnectionError](err); ok {
						code = http2.ErrCode(connection)
					}
					if code != test.wantCode {
						t.Fatalf("New error = %v, want code %v", err, test.wantCode)
					}
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUpgradeSeededRequest(t *testing.T) {
	tests := map[string]struct{ size int }{
		"success: empty body":          {},
		"success: short body":          {size: 17},
		"success: multiple chunks":     {size: ChunkSize + 17},
		"success: full receive window": {size: InitialStreamWindow},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fields := append(requestFields(), hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(test.size)})
			body := bytes.Repeat([]byte("b"), test.size)
			p := newPipePeer(t, Config{Upgrade: &UpgradeRequest{Headers: fields, Body: body}})
			head, err := p.endpoint.Receive(p.ctx)
			if err != nil || head.Kind != Headers || head.EndStream != (test.size == 0) || head.Identity.Stream != 1 {
				t.Fatalf("seeded head = %+v, %v", head, err)
			}
			if diff := cmp.Diff(fields, head.Headers); diff != "" {
				t.Fatal(diff)
			}
			p.settings(t)
			p.headers(t, 3, true, requestFields())
			next, err := p.endpoint.Receive(p.ctx)
			if err != nil || next.Identity.Stream != 3 {
				t.Fatalf("next head = %+v, %v", next, err)
			}
			var received []byte
			for len(received) < test.size {
				event, err := p.endpoint.ReceiveStream(p.ctx, head.Identity)
				if err != nil {
					t.Fatal(err)
				}
				if event.Kind != Data || event.Receipt == nil || event.Receipt.OriginalBytes() != len(event.Data) || cap(event.Data) != ChunkSize || len(event.Data) > ChunkSize {
					t.Fatalf("body chunk = %+v", event)
				}
				received = append(received, event.Data...)
				if event.EndStream != (len(received) == test.size) {
					t.Fatalf("body end = %v at %d/%d", event.EndStream, len(received), test.size)
				}
				if !event.Receipt.Complete() || event.Receipt.Complete() {
					t.Fatal("receipt not settled exactly once")
				}
			}
			if diff := cmp.Diff(body, received, cmp.Comparer(func(a, b []byte) bool { return bytes.Equal(a, b) })); diff != "" {
				t.Fatal(diff)
			}
			if _, err := p.endpoint.ReceiveStream(p.ctx, head.Identity); !errors.Is(err, io.EOF) {
				t.Fatalf("body EOF = %v", err)
			}
			if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: head.Identity, Headers: []hpack.HeaderField{{Name: ":status", Value: "200"}}, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			response := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameHeaders && f.stream == 1 })
			if !response.flags.Has(http2.FlagHeadersEndStream) {
				t.Fatalf("response = %+v", response)
			}
		})
	}
}

func TestUpgradeReceiptCancellation(t *testing.T) {
	p := newPipePeer(t, Config{Upgrade: &UpgradeRequest{Headers: requestFields(), Body: bytes.Repeat([]byte("b"), ChunkSize+1)}})
	p.settings(t)
	head, err := p.endpoint.Receive(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	data, err := p.endpoint.ReceiveStream(p.ctx, head.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.endpoint.CancelStream(head.Identity, http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	if data.Receipt.Complete() {
		t.Fatal("cancelled upgrade receipt returned credit")
	}
	if got := p.endpoint.Budget(); got.Granted != 0 {
		t.Fatalf("cancelled upgrade reservation = %+v", got)
	}
	reset, err := p.endpoint.ReceiveStream(p.ctx, head.Identity)
	if err != nil || reset.Kind != Reset {
		t.Fatalf("cancelled upgrade event = %+v, %v", reset, err)
	}
	p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameRSTStream })
}

func TestUpgradeSettingsBeforeClientPreface(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close(); _ = peer.Close() }()
	cfg := Config{Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}, Upgrade: &UpgradeRequest{Headers: requestFields(), Settings: upgradeSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 32768}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 40000})}}
	e, err := New(conn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// New owns the configuration; caller changes cannot affect Run.
	cfg.Upgrade.Settings[5] = 1
	cfg.Upgrade.Headers[0].Value = "changed"
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	go func() {
		_ = e.Run(ctx)
		_ = conn.Close()
	}()
	t.Cleanup(func() { cancel(); _ = conn.Close(); _ = peer.Close(); <-e.Done() })
	fr := http2.NewFramer(peer, peer)
	for range 2 {
		if _, err := fr.ReadFrame(); err != nil {
			t.Fatal(err)
		}
	}
	head, err := e.Receive(ctx)
	if err != nil || head.Headers[0].Value != "GET" {
		t.Fatalf("head = %+v, %v", head, err)
	}
	sent := make(chan error, 1)
	go func() {
		sent <- e.Send(ctx, Event{Kind: Headers, Identity: head.Identity, Headers: []hpack.HeaderField{{Name: ":status", Value: "200"}}})
	}()
	if frame, err := fr.ReadFrame(); err != nil || frame.Header().Type != http2.FrameHeaders {
		t.Fatalf("response = %v, %v", frame, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	go func() { sent <- e.Send(ctx, Event{Kind: Data, Identity: head.Identity, Data: make([]byte, 40000)}) }()
	for _, size := range []uint32{32768, 7232} {
		frame, err := fr.ReadFrame()
		if err != nil || frame.Header().Type != http2.FrameData || frame.Header().Length != size {
			t.Fatalf("DATA = %v, %v; want length %d", frame, err, size)
		}
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(peer, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535}); err != nil {
		t.Fatal(err)
	}
	if frame, err := fr.ReadFrame(); err != nil || !frame.Header().Flags.Has(http2.FlagSettingsAck) {
		t.Fatalf("SETTINGS ack = %v, %v", frame, err)
	}
	go func() {
		sent <- e.Send(ctx, Event{Kind: Data, Identity: head.Identity, Data: make([]byte, 20000), EndStream: true})
	}()
	for _, size := range []uint32{16384, 3616} {
		frame, err := fr.ReadFrame()
		if err != nil || frame.Header().Type != http2.FrameData || frame.Header().Length != size {
			t.Fatalf("updated DATA = %v, %v", frame, err)
		}
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeStreamReuse(t *testing.T) {
	tests := map[string]struct{ finish bool }{
		"error: half closed stream reuse": {},
		"error: closed stream reuse":      {finish: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newPipePeer(t, Config{Upgrade: &UpgradeRequest{Headers: requestFields()}})
			p.settings(t)
			head, err := p.endpoint.Receive(p.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if test.finish {
				if err := p.endpoint.Send(p.ctx, Event{Kind: Headers, Identity: head.Identity, Headers: []hpack.HeaderField{{Name: ":status", Value: "200"}}, EndStream: true}); err != nil {
					t.Fatal(err)
				}
			}
			p.headers(t, 1, true, requestFields())
			wire := p.frame(t, func(f wireFrame) bool { return f.kind == http2.FrameGoAway })
			if wire.code != http2.ErrCodeProtocol {
				t.Fatalf("reuse GOAWAY = %+v", wire)
			}
		})
	}
}

func TestUpgradePrefaceRequired(t *testing.T) {
	tests := map[string]struct{ preface bool }{
		"error: missing preface":        {},
		"error: missing first settings": {preface: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			clock := &testClock{now: time.Unix(0, 0), scheduled: make(chan struct{}, 16)}
			conn, peer := net.Pipe()
			e, err := New(conn, Config{Clock: clock, Descriptor: layer.EndpointDescriptor{Identity: "endpoint"}, Upgrade: &UpgradeRequest{Headers: requestFields()}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			go func() {
				_ = e.Run(ctx)
				_ = conn.Close()
			}()
			t.Cleanup(func() { cancel(); _ = conn.Close(); _ = peer.Close(); <-e.Done() })
			fr := http2.NewFramer(peer, peer)
			for range 2 {
				if _, err := fr.ReadFrame(); err != nil {
					t.Fatal(err)
				}
			}
			if test.preface {
				if _, err := io.WriteString(peer, http2.ClientPreface); err != nil {
					t.Fatal(err)
				}
			}
			<-clock.scheduled
			clock.advance(layer.HeadReadTimeout)
			for {
				if _, err := fr.ReadFrame(); err != nil {
					break
				}
			}
			<-e.Done()
			protocol, ok := errors.AsType[*ProtocolError](e.endError())
			if !ok || !protocol.Timeout() {
				t.Fatalf("missing preface = %v", e.endError())
			}
		})
	}
}
