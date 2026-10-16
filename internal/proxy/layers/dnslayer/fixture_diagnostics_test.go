// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnslayer

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type retentionDiagnostics struct {
	mu     sync.Mutex
	events [64]string
	count  uint64
}

func (d *retentionDiagnostics) record(format string, args ...any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	event := fmt.Sprintf(format, args...)
	d.events[d.count%uint64(len(d.events))] = event[:min(len(event), 1024)]
	d.count++
}

func (d *retentionDiagnostics) history() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out strings.Builder
	for i := d.count - min(d.count, uint64(len(d.events))); i < d.count; i++ {
		fmt.Fprintf(&out, "%d: %s\n", i, d.events[i%uint64(len(d.events))])
	}
	return out.String()
}

func (d *retentionDiagnostics) attach(s *session, side string) {
	s.diagnostics = d
	if s.udp {
		s.client = &retentionDiagnosticPeer{Conn: s.client, diagnostics: d, side: side}
		s.context.ClientPackets = &retentionDiagnosticPackets{PacketRecorder: s.context.ClientPackets, diagnostics: d, side: side}
	}
}

func (d *retentionDiagnostics) report(t *testing.T, s *session, id *int, stage *string) {
	t.Helper()
	if !t.Failed() {
		return
	}
	finished := false
	select {
	case <-s.finished:
		finished = true
	default:
	}
	buf := make([]byte, 1<<20)
	t.Logf("DNS retention id=%d stage=%s done_queued=%d finished=%t\nbounded history:\n%s\ngoroutines:\n%s", *id, *stage, len(s.done), finished, d.history(), buf[:runtime.Stack(buf, true)])
}

type retentionDiagnosticPeer struct {
	net.Conn
	diagnostics *retentionDiagnostics
	side        string
}

func diagnosticDNSID(data []byte) string {
	if len(data) < 2 {
		return "short"
	}
	return fmt.Sprint(binary.BigEndian.Uint16(data[:2]))
}

func (p *retentionDiagnosticPeer) Write(data []byte) (int, error) {
	id := diagnosticDNSID(data)
	p.diagnostics.record("%s peer write begin id=%s bytes=%d local=%v remote=%v", p.side, id, len(data), p.LocalAddr(), p.RemoteAddr())
	n, err := p.Conn.Write(data)
	p.diagnostics.record("%s peer write complete id=%s bytes=%d/%d cause=%T: %v", p.side, id, n, len(data), err, err)
	return n, err
}

type retentionDiagnosticPackets struct {
	layer.PacketRecorder
	diagnostics *retentionDiagnostics
	side        string
}

func (p *retentionDiagnosticPackets) ReadFrom(data []byte) (int, net.Addr, error) {
	p.diagnostics.record("%s tuple input wait local=%v remote=%v", p.side, p.LocalAddr(), p.RemoteAddr())
	n, addr, err := p.PacketRecorder.ReadFrom(data)
	p.diagnostics.record("%s tuple input complete id=%s bytes=%d peer=%v cause=%T: %v", p.side, diagnosticDNSID(data[:n]), n, addr, err, err)
	return n, addr, err
}

func (p *retentionDiagnosticPackets) WriteTo(data []byte, addr net.Addr) (int, error) {
	id := diagnosticDNSID(data)
	p.diagnostics.record("%s owner output begin id=%s bytes=%d peer=%v", p.side, id, len(data), addr)
	n, err := p.PacketRecorder.WriteTo(data, addr)
	p.diagnostics.record("%s owner output complete id=%s bytes=%d/%d cause=%T: %v", p.side, id, n, len(data), err, err)
	return n, err
}

func TestDNSRetentionDiagnosticHistory(t *testing.T) {
	d := &retentionDiagnostics{}
	for i := range 100 {
		d.record("id=%d", i)
	}
	if got := d.history(); strings.Count(got, "\n") != 64 || !strings.HasPrefix(got, "36: id=36\n") || !strings.HasSuffix(got, "99: id=99\n") {
		t.Fatalf("bounded chronological history=%q", got)
	}
}
