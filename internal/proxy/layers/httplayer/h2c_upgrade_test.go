// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

type upgradeHookCounts struct {
	flow   *flow.HTTPFlow
	counts map[string]int
}

func (a *upgradeHookCounts) count(name string, f *flow.HTTPFlow) {
	if f.Request.Path == "/upgrade" {
		a.flow = f
		a.counts[name]++
	}
}

func (a *upgradeHookCounts) RequestHeaders(_ context.Context, f *flow.HTTPFlow) error {
	a.count("requestheaders", f)
	return nil
}

func (a *upgradeHookCounts) Request(_ context.Context, f *flow.HTTPFlow) error {
	a.count("request", f)
	return nil
}

func (a *upgradeHookCounts) ResponseHeaders(_ context.Context, f *flow.HTTPFlow) error {
	a.count("responseheaders", f)
	return nil
}

func (a *upgradeHookCounts) Response(_ context.Context, f *flow.HTTPFlow) error {
	a.count("response", f)
	return nil
}

func TestH2CUpgradePreservesStreamOneAndHooks(t *testing.T) {
	tests := map[string]struct {
		size     int
		settings string
		upgrade  bool
	}{
		"success: empty seeded request and buffered preface": {settings: "", upgrade: true},
		"success: seeded request body spans multiple chunks": {size: h2.ChunkSize + 17, settings: "", upgrade: true},
		"success: oversized seed stays HTTP1":                {size: h2.InitialStreamWindow + 1, settings: ""},
		"error: malformed settings are not upgraded":         {settings: "not!base64"},
		"error: truncated settings are not upgraded":         {settings: "AA"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				text := r.URL.Path + ":" + strconv.Itoa(len(data))
				w.Header().Set("Content-Length", strconv.Itoa(len(text)))
				if _, err := io.WriteString(w, text); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(origin.Close)
			counts := &upgradeHookCounts{counts: make(map[string]int)}
			p := proxytest.Start(t, proxytest.WithOrigin("origin.test", &proxytest.Origin{Addr: origin.Listener.Addr().String()}), proxytest.WithOptions(map[string]any{"connection_strategy": "lazy"}), proxytest.WithAddons(counts))
			conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp4", p.Addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var suffix bytes.Buffer
			suffix.WriteString(http2.ClientPreface)
			if err := http2.NewFramer(&suffix, nil).WriteSettings(); err != nil {
				t.Fatal(err)
			}
			head := fmt.Sprintf("POST http://origin.test/upgrade HTTP/1.1\r\nHost: origin.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: %s\r\nContent-Length: %d\r\n\r\n", tt.settings, tt.size)
			wire := append([]byte(head), bytes.Repeat([]byte{'a'}, tt.size)...)
			if tt.upgrade {
				wire = append(wire, suffix.Bytes()...)
			}
			if _, err := conn.Write(wire); err != nil {
				t.Fatal(err)
			}
			buffered := bufio.NewReader(conn)
			response, err := http.ReadResponse(buffered, &http.Request{Method: "POST"})
			if err != nil {
				t.Fatal(err)
			}
			if !tt.upgrade {
				if response.StatusCode == 101 {
					t.Fatal("ineligible request was upgraded")
				}
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
				if tt.size > h2.InitialStreamWindow && (response.StatusCode != 200 || string(body) != "/upgrade:"+strconv.Itoa(tt.size)) {
					t.Fatalf("oversized fallback = %d %q", response.StatusCode, body)
				}
				return
			}
			if response.StatusCode != 101 {
				t.Fatalf("upgrade response = %d", response.StatusCode)
			}
			framer := http2.NewFramer(conn, buffered)
			framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
			readBody := func(id uint32) string {
				var result bytes.Buffer
				for {
					frame, err := framer.ReadFrame()
					if err != nil {
						t.Fatal(err)
					}
					switch frame := frame.(type) {
					case *http2.SettingsFrame:
						if !frame.IsAck() {
							if err := framer.WriteSettingsAck(); err != nil {
								t.Fatal(err)
							}
						}
					case *http2.MetaHeadersFrame:
						if frame.StreamID == id && frame.StreamEnded() {
							return result.String()
						}
					case *http2.DataFrame:
						if frame.StreamID == id {
							result.Write(frame.Data())
							if frame.StreamEnded() {
								return result.String()
							}
						}
					case *http2.RSTStreamFrame:
						t.Fatalf("stream %d reset: %s", frame.StreamID, frame.ErrCode)
					case *http2.GoAwayFrame:
						t.Fatalf("GOAWAY: %s %q", frame.ErrCode, frame.DebugData())
					}
				}
			}
			if got := readBody(1); got != "/upgrade:"+strconv.Itoa(tt.size) {
				t.Errorf("seeded stream response = %q", got)
			}
			var block bytes.Buffer
			encoder := hpack.NewEncoder(&block)
			for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "origin.test"}, {Name: ":path", Value: "/second"}} {
				if err := encoder.WriteField(field); err != nil {
					t.Fatal(err)
				}
			}
			if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			if got := readBody(3); got != "/second:0" {
				t.Errorf("following stream response = %q", got)
			}
			if err := p.Master.Do(t.Context(), func(context.Context) error {
				want := map[string]int{"requestheaders": 1, "request": 1, "responseheaders": 1, "response": 1}
				if diff := gocmp.Diff(want, counts.counts); diff != "" {
					t.Errorf("stream-1 hook counts (-want +got):\n%s", diff)
				}
				if counts.flow == nil || counts.flow.Request.HTTPVersion != "HTTP/2.0" || counts.flow.Response == nil {
					t.Error("upgrade did not preserve a completed HTTP/2 flow")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
