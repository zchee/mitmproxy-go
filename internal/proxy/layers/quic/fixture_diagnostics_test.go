// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

var packetDiagnosticFixtures sync.Map

type closeFixtureDiagnostics struct {
	mu     sync.Mutex
	events [64]string
	count  uint64
}

func (d *closeFixtureDiagnostics) record(format string, args ...any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	event := fmt.Sprintf(format, args...)
	d.events[d.count%uint64(len(d.events))] = event[:min(len(event), 1024)]
	d.count++
}

func (d *closeFixtureDiagnostics) history() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out strings.Builder
	for i := d.count - min(d.count, uint64(len(d.events))); i < d.count; i++ {
		fmt.Fprintf(&out, "%d: %s\n", i, d.events[i%uint64(len(d.events))])
	}
	return out.String()
}

func (d *closeFixtureDiagnostics) report(t *testing.T) {
	t.Helper()
	if t.Failed() {
		buf := make([]byte, 1<<20)
		t.Logf("bounded QUIC close history:\n%s\ngoroutines:\n%s", d.history(), buf[:runtime.Stack(buf, true)])
	}
}

// Run observes the existing acquisition/recorder path without replacing it.
func (l *configFixtureLayer) Run(ctx context.Context, c *layer.Context) error {
	value, ok := packetDiagnosticFixtures.Load(c.Data.Options)
	if !ok {
		return l.RawQuicLayer.Run(ctx, c)
	}
	d := value.(*closeFixtureDiagnostics)
	copyContext := *c
	copyContext.ClientPackets = &closeDiagnosticRecorder{PacketRecorder: c.ClientPackets, diagnostics: d, side: "proxy-client"}
	copyContext.OpenPackets = func(ctx context.Context, server *connection.Server) (layer.PacketTransport, *connection.Server, error) {
		packets, metadata, err := c.OpenPackets(ctx, server)
		d.record("origin acquisition result=%T: %v", err, err)
		if err != nil {
			return packets, metadata, err
		}
		return &closeDiagnosticPackets{PacketTransport: packets, diagnostics: d, side: "proxy-origin"}, metadata, nil
	}
	err := l.RawQuicLayer.Run(ctx, &copyContext)
	d.record("raw owner returned=%T: %v context=%v", err, err, context.Cause(ctx))
	return err
}

type closeDiagnosticPackets struct {
	layer.PacketTransport
	diagnostics *closeFixtureDiagnostics
	side        string
}

func (p *closeDiagnosticPackets) WriteTo(data []byte, addr net.Addr) (int, error) {
	p.diagnostics.record("%s actual WriteTo begin bytes=%d peer=%v", p.side, len(data), addr)
	n, err := p.PacketTransport.WriteTo(data, addr)
	p.diagnostics.record("%s actual WriteTo complete bytes=%d/%d result=%T: %v", p.side, n, len(data), err, err)
	return n, err
}

func (p *closeDiagnosticPackets) ReadFrom(data []byte) (int, net.Addr, error) {
	n, addr, err := p.PacketTransport.ReadFrom(data)
	p.diagnostics.record("%s input bytes=%d peer=%v result=%T: %v", p.side, n, addr, err, err)
	return n, addr, err
}

type closeDiagnosticRecorder struct {
	layer.PacketRecorder
	diagnostics *closeFixtureDiagnostics
	side        string
}

func (p *closeDiagnosticRecorder) WriteTo(data []byte, addr net.Addr) (int, error) {
	p.diagnostics.record("%s actual WriteTo begin bytes=%d peer=%v", p.side, len(data), addr)
	n, err := p.PacketRecorder.WriteTo(data, addr)
	p.diagnostics.record("%s actual WriteTo complete bytes=%d/%d result=%T: %v", p.side, n, len(data), err, err)
	return n, err
}

func closeEventDescription(closed qlog.ConnectionClosed) string {
	application, transport := "none", "none"
	if closed.ApplicationError != nil {
		application = fmt.Sprintf("%#x", uint64(*closed.ApplicationError))
	}
	if closed.ConnectionError != nil {
		transport = fmt.Sprintf("%#x", uint64(*closed.ConnectionError))
	}
	return fmt.Sprintf("initiator=%v application=%s transport=%s trigger=%v reason=%q", closed.Initiator, application, transport, closed.Trigger, closed.Reason[:min(len(closed.Reason), 256)])
}

type closeTargetTrace struct{ diagnostics *closeFixtureDiagnostics }

func (t *closeTargetTrace) AddProducer() qlogwriter.Recorder { return t }
func (*closeTargetTrace) SupportsSchemas(string) bool        { return true }
func (*closeTargetTrace) Close() error                       { return nil }

func (t *closeTargetTrace) RecordEvent(event qlogwriter.Event) {
	if closed, ok := event.(qlog.ConnectionClosed); ok {
		t.diagnostics.record("target close %s", closeEventDescription(closed))
	}
}

func TestQUICCloseDiagnosticHistory(t *testing.T) {
	d := &closeFixtureDiagnostics{}
	for i := range 100 {
		d.record("event=%d", i)
	}
	if got := d.history(); strings.Count(got, "\n") != 64 || !strings.HasPrefix(got, "36: event=36\n") || !strings.HasSuffix(got, "99: event=99\n") {
		t.Fatalf("bounded chronological history=%q", got)
	}
}
