// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowview

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/tools/console/external"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

func TestMain(m *testing.M) {
	if os.Getenv("MITMPROXY_FLOWVIEW_EDITOR_FIXTURE") == "1" {
		path := os.Args[len(os.Args)-1]
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "hello: true\n" {
			os.Exit(2)
		}
		if err := os.WriteFile(path, []byte("hello: false"), 0o600); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fixture(t *testing.T) *flow.HTTPFlow {
	t.Helper()
	request, err := httpmsg.MakeRequest("POST", "https://example.test/path", []byte("body\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := httpmsg.MakeResponse(200, []byte("response\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f := flow.NewHTTPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 1), connection.NewServer(nil), false)
	f.Request, f.Response = request, response
	return f
}

func testPalette(t *testing.T) style.Palette {
	t.Helper()
	p, err := style.NewPalette("solarized_dark", true)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func plain(lines []string) string { return ansi.Strip(strings.Join(lines, "\n")) }
func contains(t *testing.T, text, want string) {
	t.Helper()
	if !strings.Contains(text, want) {
		t.Fatalf("missing %q in %q", want, text)
	}
}

func TestConsoleFlowView(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"test_flowview": {func(t *testing.T) {
				m := New(t.Context(), nil)
				m.SetSnapshot(contract.Snapshot{Focused: fixture(t)})
				for range 3 {
					m.Update(tea.KeyPressMsg{Code: tea.KeyTab})
					if m.View() == "" {
						t.Fatal("empty tab")
					}
				}
			}},
			"test_edit": {func(t *testing.T) {
				f := fixture(t)
				f.Request.RawContent = []byte{0x81, 0xa5, 'h', 'e', 'l', 'l', 'o', 0xc3}
				f.Request.Headers.Set("content-type", "application/msgpack")
				s, err := external.Capture(f, "request-body (MsgPack)", contract.DetailOptions{})
				if err != nil {
					t.Fatal(err)
				}
				data, err := s.Bytes()
				if err != nil {
					t.Fatal(err)
				}
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv("MITMPROXY_EDITOR", `"`+executable+`"`)
				t.Setenv("MITMPROXY_FLOWVIEW_EDITOR_FIXTURE", "1")
				process, err := external.Prepare(t.Context(), external.Request{Data: data})
				if err != nil {
					t.Fatal(err)
				}
				result := process.Complete(process.Command.Run())
				if result.Err != nil {
					t.Fatal(result.Err)
				}
				edit, err := s.PrepareBytes(result.Data, false)
				if err != nil {
					t.Fatal(err)
				}
				edit.Apply(f, edit.Target)
				if diff := gocmp.Diff([]byte{0x81, 0xa5, 'h', 'e', 'l', 'l', 'o', 0xc2}, f.Request.RawContent); diff != "" {
					t.Fatal(diff)
				}
			}},
			"test_content_missing_returns_error": {func(t *testing.T) {
				f := fixture(t)
				f.Request.RawContent = nil
				title, lines, _ := Content(f, f.Request, "raw", contract.DetailOptions{}, testPalette(t))
				if title != "" || plain(lines) != "[content missing]" {
					t.Fatalf("%q %q", title, plain(lines))
				}
			}},
			"test_empty_content_request_and_response": {func(t *testing.T) {
				f := fixture(t)
				f.Request.RawContent = []byte{}
				f.Response.RawContent = []byte{}
				_, req, _ := Content(f, f.Request, "raw", contract.DetailOptions{}, testPalette(t))
				_, resp, _ := Content(f, f.Response, "raw", contract.DetailOptions{}, testPalette(t))
				if plain(req) != "No request content" || plain(resp) != "No content" {
					t.Fatalf("%q %q", plain(req), plain(resp))
				}
				f.Request.SetQuery([][2]string{{"a", "b"}})
				_, req, _ = Content(f, f.Request, "auto", contract.DetailOptions{}, testPalette(t))
				contains(t, plain(req), "a")
			}},
			"test_content_view_fullcontents_true_uses_unlimited_limit": {func(t *testing.T) {
				f := fixture(t)
				f.Request.RawContent = []byte(strings.Repeat("line\n", 50) + "last")
				_, cut, _ := Content(f, f.Request, "raw", contract.DetailOptions{LineCutoff: 2}, testPalette(t))
				_, full, _ := Content(f, f.Request, "raw", contract.DetailOptions{LineCutoff: 2, FullContents: true}, testPalette(t))
				if strings.Contains(plain(cut), "last") {
					t.Fatal("cutoff ignored")
				}
				contains(t, plain(full), "last")
			}},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
	t.Run("tabs", func(t *testing.T) {
		tests := map[string]struct {
			make func(*testing.T) flow.Flow
			want []string
		}{
			"http":      {func(t *testing.T) flow.Flow { return fixture(t) }, []string{"Request", "Response", "Detail"}},
			"websocket": {func(t *testing.T) flow.Flow { f := fixture(t); f.WebSocket = &websocket.Data{}; return f }, []string{"Request", "Response", "WebSocket Messages", "Detail"}},
			"tcp":       {func(*testing.T) flow.Flow { return flow.NewTCPFlow(nil, nil, false) }, []string{"TCP Stream", "Detail"}},
			"udp":       {func(*testing.T) flow.Flow { return flow.NewUDPFlow(nil, nil, false) }, []string{"UDP Stream", "Detail"}},
			"dns":       {func(*testing.T) flow.Flow { return flow.NewDNSFlow(nil, nil, false) }, []string{"Request", "Response", "Detail"}},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				f := tt.make(t)
				if diff := gocmp.Diff(tt.want, Tabs(f)); diff != "" {
					t.Fatal(diff)
				}
				m := New(t.Context(), nil)
				m.SetSnapshot(contract.Snapshot{Focused: f})
				for range len(tt.want) {
					if m.View() == "" {
						t.Fatal("empty view")
					}
					m.Update(tea.KeyPressMsg{Code: tea.KeyTab})
				}
				m.search[0].Term = "remember"
				m.Resize(80, 8)
				if _, consumed := m.Update(tea.MouseClickMsg{Button: tea.MouseLeft, X: 79, Y: 0}); !consumed || m.tab != len(tt.want)-1 {
					t.Fatal("tab header hit testing lost the last tab")
				}
				m.Update(contract.Action{Kind: "nav", Value: "next"})
				if m.tab != 0 || m.search[0].Term != "remember" {
					t.Fatal("admitted navigation lost per-tab search state")
				}
				m.search[0].Focus = 1000
				m.SetSnapshot(contract.Snapshot{Focused: f})
				if m.search[0].Focus >= max(1, len(m.lines)) {
					t.Fatal("snapshot retained an out-of-bounds search cursor")
				}
			})
		}
	})
}

type customView struct {
	text     string
	metadata *contentviews.Metadata
}

func (v customView) Name() string                                         { return "Custom" }
func (v customView) SyntaxHighlight() string                              { return "yaml" }
func (v customView) RenderPriority([]byte, contentviews.Metadata) float64 { return 99 }
func (v customView) Prettify(_ []byte, m contentviews.Metadata) (string, error) {
	if v.metadata != nil {
		*v.metadata = m
	}
	return v.text, nil
}

func (v customView) Reencode(text string, m contentviews.Metadata) ([]byte, error) {
	if v.metadata != nil {
		*v.metadata = m
	}
	return []byte(text), nil
}

func TestConsoleContentView(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		t.Run("test_contentview_flowview", func(t *testing.T) {
			r := &contentviews.Registry{}
			r.Register(contentviews.Raw{})
			f := fixture(t)
			m := New(t.Context(), nil)
			snapshot := contract.Snapshot{Focused: f, Detail: contract.DetailOptions{Registry: r, DefaultContentView: "auto"}}
			m.SetSnapshot(snapshot)
			contains(t, ansi.Strip(m.View()), "body")
			r.Register(customView{text: "test1"})
			m.SetSnapshot(snapshot)
			contains(t, ansi.Strip(m.View()), "test1")
			r.Register(customView{text: "test2"})
			m.SetSnapshot(snapshot)
			contains(t, ansi.Strip(m.View()), "test2")
		})
	})
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"chunk_styles": {func(t *testing.T) {
				r := &contentviews.Registry{}
				r.Register(customView{text: "key: true\ncount: 42\n"})
				f := fixture(t)
				_, lines, errs := Content(f, f.Request, "custom", contract.DetailOptions{Registry: r}, testPalette(t))
				if len(errs) > 0 {
					t.Fatal(errs)
				}
				contains(t, plain(lines), "key: true")
				if !strings.Contains(strings.Join(lines, ""), "\x1b[") {
					t.Fatal("syntax styles missing")
				}
			}},
			"registry_change": {func(t *testing.T) {
				r := &contentviews.Registry{}
				r.Register(customView{text: "old"})
				f := fixture(t)
				m := New(t.Context(), nil)
				s := contract.Snapshot{Focused: f, Detail: contract.DetailOptions{Registry: r}}
				m.SetSnapshot(s)
				contains(t, plain(m.lines), "old")
				r.Register(customView{text: "new"})
				s.RegistryGeneration++
				m.SetSnapshot(s)
				contains(t, plain(m.lines), "new")
			}},
			"metadata_definitions": {func(t *testing.T) {
				var metadata contentviews.Metadata
				r := &contentviews.Registry{}
				r.Register(customView{text: "ok", metadata: &metadata})
				f := fixture(t)
				_, _, errs := Content(f, f.Request, "custom", contract.DetailOptions{Registry: r, ProtobufDefinitions: "/operator/definitions.proto"}, testPalette(t))
				if len(errs) > 0 || metadata.HTTPRequest != f.Request || metadata.Flow != f || metadata.ProtobufDefinitions != "/operator/definitions.proto" {
					t.Fatalf("metadata=%+v errors=%v", metadata, errs)
				}
				tcpFlow := flow.NewTCPFlow(f.ClientConn, f.ServerConn, false)
				tcpFlow.Messages = []*tcp.Message{tcp.NewMessage(true, []byte("tcp original"))}
				udpFlow := flow.NewUDPFlow(f.ClientConn, f.ServerConn, false)
				udpFlow.Messages = []*udp.Message{udp.NewMessage(false, []byte("udp original"))}
				wsFlow := fixture(t)
				wsFlow.WebSocket = &websocket.Data{Messages: []*websocket.Message{websocket.NewMessage(websocket.OpBinary, true, []byte("ws original"))}}
				tests := map[string]struct {
					flow                     flow.Flow
					part, protocol, original string
				}{
					"request":   {f, "request-body", "http", "body\n"},
					"response":  {f, "response-body", "http", "response\n"},
					"tcp":       {tcpFlow, "tcp-message", "tcp", "tcp original"},
					"udp":       {udpFlow, "udp-message", "udp", "udp original"},
					"websocket": {wsFlow, "websocket-message", "websocket", "ws original"},
				}
				for name, tt := range tests {
					s, err := external.Capture(tt.flow, tt.part+" (Custom)", contract.DetailOptions{Registry: r, ProtobufDefinitions: "/operator/definitions.proto"})
					if err != nil {
						t.Fatal(name, err)
					}
					if _, err := s.PrepareBytes([]byte("replacement"), false); err != nil {
						t.Fatal(name, err)
					}
					if metadata.Flow != s.Flow || metadata.Protocol != tt.protocol || string(metadata.OriginalData) != tt.original || metadata.ProtobufDefinitions != "/operator/definitions.proto" {
						t.Fatalf("%s: incomplete edit metadata: %+v", name, metadata)
					}
					if metadata.TCPMessage != nil && !metadata.TCPMessage.FromClient || metadata.UDPMessage != nil && metadata.UDPMessage.FromClient || metadata.WebSocketMessage != nil && !metadata.WebSocketMessage.FromClient {
						t.Fatal(name, "message direction lost")
					}
				}
			}},
			"fallback_cutoff": {func(t *testing.T) {
				r := &contentviews.Registry{}
				r.Register(customView{text: strings.Repeat("x", 300000)})
				f := fixture(t)
				_, lines, errs := Content(f, f.Request, "custom", contract.DetailOptions{Registry: r}, testPalette(t))
				if len(errs) == 0 {
					t.Fatal("missing highlight refusal")
				}
				if len(plain(lines)) != 300000 {
					t.Fatal("refusal truncated data")
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func TestConsoleFlowDetail(t *testing.T) {
	t.Run("details", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"comment": {func(t *testing.T) {
				f := fixture(t)
				f.Comment = "note\x1b]52;bad"
				text := plain(Detail(f, testPalette(t)))
				contains(t, text, "Comment: note")
				if strings.Contains(text, "\x1b") {
					t.Fatal("control injected")
				}
			}},
			"metadata": {func(t *testing.T) {
				f := fixture(t)
				f.Metadata = state.NewMap(1)
				f.Metadata.Set("tag", "value")
				contains(t, plain(Detail(f, testPalette(t))), "tag:")
			}},
			"connections": {func(t *testing.T) {
				f := fixture(t)
				f.ClientConn = connection.NewClient(connection.Address{Host: "127.0.0.1", Port: 1234}, connection.Address{}, 1)
				f.ClientConn.SNI = new("example.test")
				f.ClientConn.ALPN = []byte("h2")
				f.ServerConn = connection.NewServer(&connection.Address{Host: "example.test", Port: 443})
				f.ServerConn.Peername = &connection.Address{Host: "127.0.0.2", Port: 443}
				text := plain(Detail(f, testPalette(t)))
				contains(t, text, "127.0.0.1:1234")
				contains(t, text, "example.test:443")
				contains(t, text, "ALPN: h2")
			}},
			"certificate": {func(t *testing.T) {
				pub, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "cert.example"}, NotBefore: time.Unix(1, 0), NotAfter: time.Unix(2, 0)}
				der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
				if err != nil {
					t.Fatal(err)
				}
				f := fixture(t)
				f.ServerConn = connection.NewServer(&connection.Address{Host: "example.test", Port: 443})
				f.ServerConn.Peername = f.ServerConn.Address
				f.ServerConn.CertificateList = [][]byte{der}
				text := plain(Detail(f, testPalette(t)))
				contains(t, text, "Server Certificate:")
				contains(t, text, "cert.example")
				contains(t, text, "SHA256 digest")
			}},
			"timing": {func(t *testing.T) {
				f := fixture(t)
				f.Request.TimestampStart = 2
				f.Request.TimestampEnd = nil
				f.Response.TimestampStart = 3
				f.Response.TimestampEnd = new(4.0)
				text := plain(Detail(f, testPalette(t)))
				contains(t, text, "Request complete: –")
				if strings.Index(text, "First request byte") > strings.Index(text, "First response byte") {
					t.Fatal("timing not sorted")
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func TestConsoleSearch(t *testing.T) {
	t.Run("search", func(t *testing.T) {
		tests := map[string]struct {
			focus int
			back  bool
			term  string
			want  int
			found bool
		}{"forward": {0, false, "match", 1, true}, "backward": {2, true, "match", 1, true}, "wrap": {2, false, "match", 1, true}, "missing": {0, false, "absent", 0, false}}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				s := Search{Term: tt.term, Focus: tt.focus}
				found := s.Find([]string{"first", "match", "last"}, tt.back)
				if found != tt.found || s.Focus != tt.want {
					t.Fatalf("found=%v focus=%d", found, s.Focus)
				}
			})
		}
	})
}
