// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/quic-go/qpack"
	quic "github.com/quic-go/quic-go"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/addons/tlsconfig"
	"github.com/zchee/mitmproxy-go/addons/updatealtsvc"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/modeserver"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

// Selection is explicit until the separate QUIC routing change lands. Packet
// and byte origin acquisition below are supplied only by the real Handler.
type http3HandlerSelector struct{ tcpClient, h2Client bool }

func (*http3HandlerSelector) Name() string { return "http3handlerselector" }

func (a *http3HandlerSelector) NextLayer(_ context.Context, data *hookdata.NextLayer) error {
	data.Context.Server.TransportProtocol = connection.UDP
	data.Context.Server.TLS = true
	data.Context.Server.ALPNOffers = [][]byte{[]byte("h3")}
	if a.h2Client {
		data.Context.Client.ALPN = []byte("h2")
	}
	if a.tcpClient {
		data.Layer = hookdata.LayerStack{{Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeTransparent}}
	} else {
		data.Layer = hookdata.LayerStack{{Kind: hookdata.LayerHTTP3}}
	}
	return nil
}

func TestHTTP3DefaultHandlerPairing(t *testing.T) {
	tests := map[string]struct {
		tcpClient  bool
		tcpOrigin  bool
		keepAltSvc bool
		httpsMode  bool
		h2Client   bool
		h2Origin   bool
	}{
		"reverse HTTPS serves HTTP3 on UDP":       {httpsMode: true},
		"HTTP2 client to HTTP3 origin":            {tcpClient: true, h2Client: true},
		"HTTP3 client to HTTP2 origin":            {tcpOrigin: true, h2Origin: true},
		"HTTP1 client to HTTP3 origin":            {tcpClient: true},
		"HTTP3 client to HTTP1 origin":            {tcpOrigin: true},
		"HTTP3 listener rewrites Alt-Svc":         {},
		"HTTP3 listener preserves Alt-Svc option": {keepAltSvc: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			runCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			originListener, target := newHTTP3RoutingListener(t)
			var reroute connection.Address
			var tcpRoots *x509.CertPool
			if test.tcpOrigin {
				origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if test.h2Origin && r.ProtoMajor != 2 {
						t.Errorf("origin negotiated HTTP/%d instead of HTTP/2", r.ProtoMajor)
					}
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					if _, err := w.Write(body); err != nil {
						t.Error(err)
					}
				}))
				if test.h2Origin {
					origin.EnableHTTP2 = true
					origin.StartTLS()
					tcpRoots = x509.NewCertPool()
					tcpRoots.AddCert(origin.Certificate())
				} else {
					origin.Start()
				}
				t.Cleanup(origin.Close)
				addr := origin.Listener.Addr().(*net.TCPAddr)
				reroute = connection.Address{Host: addr.IP.String(), Port: addr.Port}
			}
			seen := make(chan *flow.HTTPFlow, 1)
			_, master := newTestStream(t, &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if name == "requestheaders" && test.tcpOrigin {
					f.Request.Scheme, f.Request.Host, f.Request.Port = "http", reroute.Host, reroute.Port
					if test.h2Origin {
						f.Request.Scheme = "https"
					}
					f.Request.SetHostHeader(reroute.String())
					f.ServerConn.TransportProtocol = connection.TCP
				}
				if name == "response" {
					seen <- f
				}
			}})
			connections := &proxy.Connections{}
			cfg := proxy.Config{Manager: master.Addons, Options: master.Options, Connections: connections, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			defaults, err := proxyserver.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			security := tlsconfig.New(master.Options)
			confdir := t.TempDir()
			if err := master.Do(ctx, func(ctx context.Context) error {
				if err := master.Addons.Add(ctx, defaults); err != nil {
					return err
				}
				if err := master.Options.Set(ctx, "confdir="+confdir, "ssl_insecure=true"); err != nil {
					return err
				}
				if err := master.Addons.Add(ctx, security); err != nil {
					return err
				}
				if err := security.Configure(ctx, map[string]struct{}{"confdir": {}}); err != nil {
					return err
				}
				if err := master.Addons.Add(ctx, updatealtsvc.New(master.Options)); err != nil {
					return err
				}
				if test.h2Origin {
					if err := master.Addons.Add(ctx, &http3TCPOriginTLS{roots: tcpRoots}); err != nil {
						return err
					}
				}
				if err := master.Addons.Add(ctx, &http3HandlerSelector{tcpClient: test.tcpClient, h2Client: test.h2Client}); err != nil {
					return err
				}
				return master.Options.Set(ctx, "connection_strategy=lazy", "keep_alt_svc_header="+strconv.FormatBool(test.keepAltSvc))
			}); err != nil {
				t.Fatal(err)
			}
			handler, err := proxy.NewHandler(cfg)
			if err != nil {
				t.Fatal(err)
			}
			scheme := "http3"
			if test.tcpClient || test.httpsMode {
				scheme = "https"
			}
			mode, err := modespec.Parse("reverse:" + scheme + "://" + target.String())
			if err != nil {
				t.Fatal(err)
			}
			instance, err := modeserver.New(mode, modeserver.Config{Handler: handler, ListenHost: "127.0.0.1", ListenPort: new(0), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
			if err != nil {
				t.Fatal(err)
			}
			if err := instance.Start(runCtx); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); connections.Close(); _ = instance.Stop() }()
			addresses := instance.ListenAddrs()
			if len(addresses) == 0 {
				t.Fatal("HTTP3 listener did not bind")
			}
			address := addresses[0]
			var workers sync.WaitGroup
			defer func() { cancel(); workers.Wait() }()
			workers.Go(func() {
				origin, err := originListener.Accept(runCtx)
				if err != nil {
					return
				}
				startHTTP3RoutingPeer(t, runCtx, origin)
				if test.tcpOrigin {
					<-runCtx.Done()
					return
				}
				stream, err := origin.AcceptStream(runCtx)
				if err != nil {
					t.Error(err)
					return
				}
				_, body, _ := readHTTP3TestMessage(t, stream)
				writeHTTP3TestHeaders(t, stream, []qpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-length", Value: strconv.Itoa(len(body))}, {Name: "alt-svc", Value: `h3="origin.example:443"`}})
				writeHTTP3TestFrame(t, stream, 0, body)
				if err := stream.Close(); err != nil {
					t.Error(err)
				}
			})
			var body []byte
			if test.tcpClient {
				client, err := (&net.Dialer{}).DialContext(ctx, "tcp", address.String())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = client.Close() }()
				if test.h2Client {
					engine, err := h2.New(client.(*net.TCPConn), h2.Config{Client: true, Descriptor: layer.EndpointDescriptor{Identity: "default handler client", Protocol: "h2"}, ValidateInboundHeaders: true})
					if err != nil {
						t.Fatal(err)
					}
					workers.Go(func() { _ = engine.Run(runCtx) })
					id, err := engine.OpenStream(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if err := engine.Send(ctx, h2.Event{Kind: h2.Headers, Identity: id, Headers: []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "localhost"}, {Name: ":path", Value: "/echo"}, {Name: "content-length", Value: "3"}}}); err != nil {
						t.Fatal(err)
					}
					if err := engine.Send(ctx, h2.Event{Kind: h2.Data, Identity: id, Data: []byte("abc"), EndStream: true}); err != nil {
						t.Fatal(err)
					}
					for {
						event, err := engine.ReceiveStream(ctx, id)
						if err != nil {
							t.Fatal(err)
						}
						if event.Err != nil {
							t.Fatal(event.Err)
						}
						if event.Kind == h2.Headers && event.Headers[0].Value != "200" {
							t.Fatal("HTTP2 response status:", event)
						}
						body = append(body, event.Data...)
						if event.Receipt != nil {
							event.Receipt.Complete()
						}
						if event.EndStream {
							break
						}
					}
				} else {
					write(t, client.(*net.TCPConn), "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc")
					response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "POST"})
					if err != nil {
						t.Fatal(err)
					}
					body, err = io.ReadAll(response.Body)
					if err != nil {
						t.Fatal(err)
					}
					_ = response.Body.Close()
					if response.StatusCode != 200 {
						t.Fatal("default Handler response:", response.StatusCode)
					}
				}
			} else {
				socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = socket.Close() }()
				transport := &quic.Transport{Conn: socket}
				defer func() { _ = transport.Close() }()
				peerAddress, err := net.ResolveUDPAddr("udp4", address.String())
				if err != nil {
					t.Fatal(err)
				}
				client, err := transport.Dial(ctx, peerAddress, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, ServerName: "localhost", InsecureSkipVerify: true}, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = client.CloseWithError(0x100, "") }()
				startHTTP3RoutingPeer(t, runCtx, client)
				request, err := client.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				writeHTTP3TestHeaders(t, request, []qpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "localhost"}, {Name: ":path", Value: "/echo"}, {Name: "content-length", Value: "3"}})
				writeHTTP3TestFrame(t, request, 0, []byte("abc"))
				if err := request.Close(); err != nil {
					t.Fatal(err)
				}
				fields, received, _ := readHTTP3TestMessage(t, request)
				body = received
				if fields[0].Value != "200" {
					t.Fatal("default Handler response:", fields)
				}
				if !test.tcpOrigin {
					want := `h3=":` + strconv.Itoa(address.Port) + `"`
					if test.keepAltSvc {
						want = `h3="origin.example:443"`
					}
					var altSvc string
					for _, field := range fields {
						if field.Name == "alt-svc" {
							altSvc = field.Value
						}
					}
					if diff := gocmp.Diff(want, altSvc); diff != "" {
						t.Fatal(diff)
					}
				}
			}
			if diff := gocmp.Diff("abc", string(body)); diff != "" {
				t.Fatal(diff)
			}
			select {
			case f := <-seen:
				if err := master.Do(ctx, func(context.Context) error {
					if f.Error != nil {
						return errors.New(f.Error.Msg)
					}
					if test.tcpOrigin && f.ServerConn.TransportProtocol != connection.TCP {
						return fmt.Errorf("origin transport = %s", f.ServerConn.TransportProtocol)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			cancel()
		})
	}
}
