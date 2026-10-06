// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build h2load

package httplayer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/master"
)

const loadBodySize = 64 << 20

// The peers retain one framing buffer, not response bodies, so the heap row
// measures the proxy's buffered DATA instead of a client's receive history.
type loadHTTP2Peer struct {
	conn           net.Conn
	ctx            context.Context
	cancel         context.CancelFunc
	reader, writer *http2.Framer
	writeMu        sync.Mutex
	mu             sync.Mutex
	creditChanged  chan struct{}
	connCredit     int64
	initialCredit  int64
	streamCredit   map[uint32]int64
	frameSize      int64
	received       map[uint32]int64
	withholdAfter  int64
	withholdExcept uint32
	paused         bool
	stopped        chan struct{}
	noticeID       uint32
	notices        chan time.Time
	firstData      chan time.Time
	finished       chan uint32
	ready          chan struct{}
	done           chan struct{}
	workers        sync.WaitGroup
	onHead         func(uint32, []hpack.HeaderField, bool)
	onEnd          func(uint32)
}

func newLoadHTTP2Peer(t *testing.T, ctx context.Context, conn net.Conn, client bool, onHead func(uint32, []hpack.HeaderField, bool), onEnd func(uint32), windows ...int64) *loadHTTP2Peer {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	p := &loadHTTP2Peer{conn: conn, ctx: ctx, cancel: cancel, reader: http2.NewFramer(nil, conn), writer: http2.NewFramer(conn, nil), connCredit: 65535, initialCredit: 65535, frameSize: 16384, creditChanged: make(chan struct{}), streamCredit: make(map[uint32]int64), received: make(map[uint32]int64), stopped: make(chan struct{}), notices: make(chan time.Time, 2), firstData: make(chan time.Time, 1), finished: make(chan uint32, 256), ready: make(chan struct{}), done: make(chan struct{}), onHead: onHead, onEnd: onEnd}
	p.reader.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	t.Cleanup(func() { p.cancel(); _ = conn.Close(); <-p.done; p.workers.Wait() })
	if client {
		if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
			t.Fatal(err)
		}
	} else {
		prefix := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(conn, prefix); err != nil {
			t.Fatal(err)
		}
		if string(prefix) != http2.ClientPreface {
			t.Fatal("wrong client preface")
		}
	}
	initialWindow, connectionWindow := int64(1<<20), int64(16<<20)
	if client {
		connectionWindow = 132 << 20
	}
	if len(windows) == 2 {
		initialWindow, connectionWindow = windows[0], windows[1]
	}
	go p.read()
	if err := p.write(func(f *http2.Framer) error {
		return f.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(initialWindow)}, http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100}, http2.Setting{ID: http2.SettingMaxFrameSize, Val: 128 << 10})
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.write(func(f *http2.Framer) error { return f.WriteWindowUpdate(0, uint32(connectionWindow-65535)) }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return p
}

func (p *loadHTTP2Peer) write(fn func(*http2.Framer) error) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return fn(p.writer)
}

func (p *loadHTTP2Peer) read() {
	defer close(p.done)
	defer p.cancel()
	acknowledged := false
	for {
		p.mu.Lock()
		paused := p.paused
		p.mu.Unlock()
		if paused {
			close(p.stopped)
			<-p.ctx.Done()
			return
		}
		frame, err := p.reader.ReadFrame()
		if err != nil {
			return
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if frame.IsAck() {
				if !acknowledged {
					close(p.ready)
					acknowledged = true
				}
				continue
			}
			p.mu.Lock()
			err = frame.ForeachSetting(func(s http2.Setting) error {
				switch s.ID {
				case http2.SettingInitialWindowSize:
					delta := int64(s.Val) - p.initialCredit
					p.initialCredit = int64(s.Val)
					for id := range p.streamCredit {
						p.streamCredit[id] += delta
					}
				case http2.SettingMaxFrameSize:
					p.frameSize = int64(s.Val)
				}
				return nil
			})
			close(p.creditChanged)
			p.creditChanged = make(chan struct{})
			p.mu.Unlock()
			if err != nil || p.write(func(f *http2.Framer) error { return f.WriteSettingsAck() }) != nil {
				return
			}
		case *http2.WindowUpdateFrame:
			p.mu.Lock()
			if frame.StreamID == 0 {
				p.connCredit += int64(frame.Increment)
			} else {
				p.streamCredit[frame.StreamID] += int64(frame.Increment)
			}
			close(p.creditChanged)
			p.creditChanged = make(chan struct{})
			p.mu.Unlock()
		case *http2.MetaHeadersFrame:
			if p.onHead != nil {
				p.onHead(frame.StreamID, frame.Fields, frame.StreamEnded())
			}
			if frame.StreamEnded() {
				p.end(frame.StreamID)
			}
		case *http2.DataFrame:
			n := int64(len(frame.Data()))
			p.mu.Lock()
			p.received[frame.StreamID] += n
			refundStream := p.withholdAfter == 0 || frame.StreamID == p.withholdExcept || p.received[frame.StreamID] < p.withholdAfter
			notify := p.noticeID == frame.StreamID && n > 0
			p.mu.Unlock()
			if notify {
				select {
				case p.notices <- time.Now():
				case <-p.ctx.Done():
					return
				}
			}
			if n != 0 {
				if p.write(func(f *http2.Framer) error { return f.WriteWindowUpdate(0, uint32(n)) }) != nil {
					return
				}
				if refundStream && p.write(func(f *http2.Framer) error { return f.WriteWindowUpdate(frame.StreamID, uint32(n)) }) != nil {
					return
				}
			}
			if frame.StreamEnded() {
				p.end(frame.StreamID)
			}
		case *http2.PingFrame:
			if !frame.IsAck() && p.write(func(f *http2.Framer) error { return f.WritePing(true, frame.Data) }) != nil {
				return
			}
		}
	}
}

func (p *loadHTTP2Peer) end(id uint32) {
	if p.onEnd != nil {
		p.onEnd(id)
	}
	select {
	case p.finished <- id:
	case <-p.ctx.Done():
	}
}

func (p *loadHTTP2Peer) headers(id uint32, fields []hpack.HeaderField, end bool) error {
	p.mu.Lock()
	if _, ok := p.streamCredit[id]; !ok {
		p.streamCredit[id] = p.initialCredit
	}
	p.mu.Unlock()
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			return err
		}
	}
	return p.write(func(f *http2.Framer) error {
		return f.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: end})
	})
}

func (p *loadHTTP2Peer) data(id uint32, data []byte, end bool) error {
	for len(data) > 0 {
		p.mu.Lock()
		n := min(int64(len(data)), p.frameSize, p.connCredit, p.streamCredit[id])
		if n <= 0 {
			changed := p.creditChanged
			p.mu.Unlock()
			select {
			case <-changed:
				continue
			case <-p.ctx.Done():
				return p.ctx.Err()
			}
		}
		p.connCredit -= n
		p.streamCredit[id] -= n
		p.mu.Unlock()
		last := int(n) == len(data)
		if err := p.write(func(f *http2.Framer) error { return f.WriteData(id, last && end, data[:n]) }); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func (p *loadHTTP2Peer) body(id uint32, chunk []byte, size int64) error {
	for remaining := size; remaining > 0; {
		n := min(int64(len(chunk)), remaining)
		if err := p.data(id, chunk[:n], n == remaining); err != nil {
			return err
		}
		remaining -= n
	}
	return nil
}

func (p *loadHTTP2Peer) bytes(id uint32) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.received[id]
}

func (p *loadHTTP2Peer) totalBytes() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var total int64
	for _, n := range p.received {
		total += n
	}
	return total
}

var loadLayerNumber atomic.Uint64

type loadHTTP2View struct {
	mu      sync.Mutex
	origins *httpOrigins
}

type loadHTTP2Layer struct {
	view *loadHTTP2View
	kind hookdata.LayerKind
}

func (l *loadHTTP2Layer) Kind() hookdata.LayerKind { return l.kind }
func (l *loadHTTP2Layer) Run(ctx context.Context, c *layer.Context) error {
	c.Client.StopRecording()
	settings, err := protocolSettings(ctx, c, nil)
	if err != nil {
		return err
	}
	origins := newHTTPOrigins(ctx)
	defer origins.stop()
	l.view.mu.Lock()
	l.view.origins = origins
	l.view.mu.Unlock()
	return (&httpLayer{route: routeConfig{mode: modeRegular, validateInboundHeaders: true}}).runHTTP2(ctx, c, settings, origins, newWireStore(), nil)
}

func (v *loadHTTP2View) endpoint(t *testing.T) *h2.Endpoint {
	t.Helper()
	v.mu.Lock()
	origins := v.origins
	v.mu.Unlock()
	if origins == nil {
		t.Fatal("HTTP owner not started")
	}
	origins.mu.Lock()
	defer origins.mu.Unlock()
	if len(origins.entries) != 1 {
		t.Fatalf("origin connections = %d, want 1", len(origins.entries))
	}
	for _, origin := range origins.entries {
		if origin.h2 != nil {
			return origin.h2
		}
	}
	t.Fatal("origin is not HTTP/2")
	return nil
}

type loadOriginProtocol struct{}

func (*loadOriginProtocol) Name() string { return "load_origin_protocol" }
func (*loadOriginProtocol) ServerConnect(_ context.Context, data *hookdata.ServerConnection) error {
	// This origin explicitly accepts cleartext prior knowledge, not TLS ALPN.
	data.Server.ALPN = []byte("h2")
	return nil
}

type loadHTTP2Session struct {
	client    *loadHTTP2Peer
	origin    *loadHTTP2Peer
	view      *loadHTTP2View
	authority string
	ctx       context.Context
	cancel    context.CancelFunc
}

func newLoadHTTP2Session(t *testing.T, chunkSize int, addon any, timeout time.Duration, windows ...int64) *loadHTTP2Session {
	t.Helper()
	if os.Getenv("MITMPROXY_GO_HTTP2_LOAD") != "1" {
		t.Fatal("h2load requires MITMPROXY_GO_HTTP2_LOAD=1 and an isolated runner")
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)
	m := master.New(master.Config{Logger: slog.New(slog.DiscardHandler)})
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	})
	cfg := proxy.Config{Manager: m.Addons, Options: m.Options, Connections: new(proxy.Connections), Logger: slog.New(slog.DiscardHandler)}
	serverAddon, err := proxyserver.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Do(ctx, func(ctx context.Context) error {
		if err := m.Addons.Add(ctx, serverAddon, &loadOriginProtocol{}); err != nil {
			return err
		}
		if err := m.Options.Update(ctx, map[string]any{"stream_large_bodies": new("1m"), "connection_strategy": "lazy", "http2_ping_keepalive": 0}); err != nil {
			return err
		}
		if addon != nil {
			return m.Addons.Add(ctx, addon)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	originReady := make(chan *loadHTTP2Peer, 1)
	chunk := make([]byte, chunkSize)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		var peer *loadHTTP2Peer
		initialized := make(chan struct{})
		uploads := make(map[uint32]bool)
		peer = newLoadHTTP2Peer(t, ctx, conn, false, func(id uint32, fields []hpack.HeaderField, end bool) {
			<-initialized
			var method, path string
			for _, field := range fields {
				switch field.Name {
				case ":method":
					method = field.Value
				case ":path":
					path = field.Value
				}
			}
			if method == "POST" {
				uploads[id] = true
				return
			}
			size := int64(loadBodySize)
			if path == "/warm" {
				size = int64(chunkSize)
			}
			if path == "/small" {
				size = 4 << 20
			}
			if path == "/sse" {
				size = 200
			}
			if path == "/netem" {
				size = 256 << 20
			}
			peer.workers.Go(func() {
				fields := []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-length", Value: strconv.FormatInt(size, 10)}}
				if path == "/sse" {
					fields = append(fields, hpack.HeaderField{Name: "content-type", Value: "text/event-stream"})
				}
				if peer.headers(id, fields, false) != nil {
					return
				}
				if path == "/sse" {
					select {
					case peer.firstData <- time.Now():
					case <-ctx.Done():
						return
					}
					if peer.data(id, chunk[:100], false) != nil {
						return
					}
					timer := time.NewTimer(500 * time.Millisecond)
					defer timer.Stop()
					select {
					case <-timer.C:
						select {
						case peer.firstData <- time.Now():
						case <-ctx.Done():
							return
						}
						_ = peer.data(id, chunk[:100], true)
					case <-ctx.Done():
					}
					return
				}
				_ = peer.body(id, chunk, size)
			})
		}, func(id uint32) {
			<-initialized
			if !uploads[id] {
				return
			}
			peer.workers.Go(func() { _ = peer.headers(id, []hpack.HeaderField{{Name: ":status", Value: "204"}}, true) })
		})
		close(initialized)
		originReady <- peer
	}()
	view := new(loadHTTP2View)
	kind := hookdata.LayerKind(fmt.Sprintf("test_load_http_%d", loadLayerNumber.Add(1)))
	layer.Register(kind, func(*layer.Context, hookdata.LayerSpec, layer.Layer) (layer.Layer, error) {
		return &loadHTTP2Layer{view: view, kind: kind}, nil
	})
	handler, err := proxy.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	clientListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientListener.Close() })
	handlerDone := make(chan error, 1)
	go func() {
		conn, err := clientListener.Accept()
		if err != nil {
			handlerDone <- err
			return
		}
		handlerDone <- handler.Handle(ctx, conn, "regular", hookdata.LayerSpec{Kind: kind})
	}()
	t.Cleanup(func() {
		cancel()
		_ = clientListener.Close()
		if err := await(t, handlerDone); err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
		view.mu.Lock()
		view.origins = nil
		view.mu.Unlock()
	})
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", clientListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := newLoadHTTP2Peer(t, ctx, conn, true, nil, nil, windows...)
	session := &loadHTTP2Session{client: client, view: view, authority: listener.Addr().String(), ctx: ctx, cancel: cancel}
	if err := session.request(1, "GET", "/warm", true); err != nil {
		t.Fatal(err)
	}
	session.origin = await(t, originReady)
	if got := await(t, client.finished); got != 1 {
		t.Fatalf("warmup stream = %d", got)
	}
	return session
}

func (s *loadHTTP2Session) request(id uint32, method, path string, end bool) error {
	fields := []hpack.HeaderField{{Name: ":method", Value: method}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: s.authority}, {Name: ":path", Value: path}}
	if method == "POST" {
		fields = append(fields, hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(loadBodySize)})
	}
	return s.client.headers(id, fields, end)
}

func loadHeap() uint64 {
	runtime.GC()
	samples := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	metrics.Read(samples)
	return samples[0].Value.Uint64()
}

func TestHTTP2LoadLargeTransfer(t *testing.T) {
	tests := map[string]struct{ chunk int }{"success: 64 MiB in each direction": {chunk: 128 << 10}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newLoadHTTP2Session(t, tt.chunk, nil, 30*time.Second)
			started := time.Now()
			if err := s.request(3, "POST", "/upload", false); err != nil {
				t.Fatal(err)
			}
			if err := s.request(5, "GET", "/download", true); err != nil {
				t.Fatal(err)
			}
			uploadDone := make(chan error, 1)
			go func() { uploadDone <- s.client.body(3, make([]byte, tt.chunk), loadBodySize) }()
			for range 2 {
				_ = await(t, s.client.finished)
			}
			if err := await(t, uploadDone); err != nil {
				t.Fatal(err)
			}
			if got := s.client.bytes(5); got != loadBodySize {
				t.Errorf("download bytes = %d", got)
			}
			if got := s.origin.totalBytes(); got != loadBodySize {
				t.Errorf("upload bytes = %d", got)
			}
			t.Logf("concurrent upload/download: %d bytes each, duration=%s, source budget=%+v", loadBodySize, time.Since(started), s.view.endpoint(t).Budget())
		})
	}
}

func TestHTTP2LoadHeapStalls(t *testing.T)      { loadHTTP2Stalls(t, 128<<10) }
func TestHTTP2LoadHeapSmallWindow(t *testing.T) { loadHTTP2Stalls(t, 1<<10) }

func loadHTTP2Stalls(t *testing.T, chunkSize int) {
	t.Helper()
	tests := map[string]struct{ chunk int }{fmt.Sprintf("success: DATA chunk size %d", chunkSize): {chunk: chunkSize}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newLoadHTTP2Session(t, tt.chunk, nil, 5*time.Minute)
			endpoint := s.view.endpoint(t)
			assertAlive := func() {
				for name, done := range map[string]<-chan struct{}{"upstream owner": endpoint.Done(), "client framer": s.client.done, "origin framer": s.origin.done} {
					select {
					case <-done:
						t.Fatalf("%s ended before heap measurement", name)
					default:
					}
				}
			}
			assertAlive()
			baseline := loadHeap()
			s.client.mu.Lock()
			s.client.withholdAfter = 8 << 20
			s.client.withholdExcept = 201
			s.client.mu.Unlock()
			for i := range 99 {
				if err := s.request(uint32(3+2*i), "GET", "/stalled", true); err != nil {
					t.Fatal(err)
				}
			}
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for {
				budget := endpoint.Budget()
				if budget.Granted > 128<<20 || budget.Maximum > 128<<20 {
					t.Fatalf("source receive grants exceed cap: %+v", budget)
				}
				stalled, exhausted := 0, 0
				s.client.mu.Lock()
				for i := range 99 {
					if s.client.received[uint32(3+2*i)] >= 8<<20 {
						stalled++
					}
				}
				s.client.mu.Unlock()
				s.origin.mu.Lock()
				for id, credit := range s.origin.streamCredit {
					if id != 1 && credit == 0 {
						exhausted++
					}
				}
				s.origin.mu.Unlock()
				if budget.Granted == 127<<20 && stalled == 99 && exhausted == 99 {
					t.Logf("charged queues confirmed: %d stalled client streams, %d exhausted origin stream windows, source budget=%+v", stalled, exhausted, budget)
					break
				}
				select {
				case <-ticker.C:
				case <-s.ctx.Done():
					t.Fatalf("99-stream ceiling not reached: stalled=%d exhausted=%d budget=%+v", stalled, exhausted, budget)
				}
			}
			assertAlive()
			loaded := loadHeap()
			delta := int64(loaded) - int64(baseline)
			if delta > 160<<20 {
				t.Fatalf("heap growth = %d bytes, budget=%+v", delta, endpoint.Budget())
			}
			started := time.Now()
			if err := s.request(201, "GET", "/small", true); err != nil {
				t.Fatal(err)
			}
			if got := await(t, s.client.finished); got != 201 {
				t.Fatalf("completed stream = %d", got)
			}
			elapsed := time.Since(started)
			if elapsed > 2*time.Second {
				t.Errorf("isolated 100th-stream response duration = %s", elapsed)
			}
			if got := s.client.bytes(201); got != 4<<20 {
				t.Errorf("100th-stream response bytes = %d", got)
			}
			t.Logf("DATA chunk=%d: heap baseline=%d loaded=%d growth=%d; 100th response=%s; source budget=%+v", tt.chunk, baseline, loaded, delta, elapsed, endpoint.Budget())
		})
	}
}
