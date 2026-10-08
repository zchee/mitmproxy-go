// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/quic-go/qpack"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

type http3TCPOriginSockets struct {
	*pipePool
	address string
}

func (p *http3TCPOriginSockets) Open(ctx context.Context, server *connection.Server, opts layer.OpenOptions) (layer.Conn, *connection.Server, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.address)
	if err != nil {
		return nil, nil, err
	}
	p.t.Cleanup(func() { _ = conn.Close() })
	var transport layer.Conn = conn.(*net.TCPConn)
	if opts.Setup != nil {
		transport, err = opts.Setup(ctx, transport, server)
		if err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
	}
	return transport, server, nil
}

type http3TCPOriginTLS struct{ roots *x509.CertPool }

func (a *http3TCPOriginTLS) TLSStartServer(_ context.Context, data *hookdata.TLS) error {
	data.Config = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, RootCAs: a.roots, ServerName: "example.com"}
	return nil
}

func TestHTTP3ConsumerHTTP2Origin(t *testing.T) {
	tests := map[string]struct{ streamed bool }{
		"buffered request and response": {},
		"streamed request and response": {streamed: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := http3TestContext(t)
			protocol := make(chan int, 1)
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				protocol <- r.ProtoMajor
				if _, err := w.Write(body); err != nil {
					t.Error(err)
				}
			}))
			origin.EnableHTTP2 = true
			origin.StartTLS()
			t.Cleanup(origin.Close)
			_, portText, err := net.SplitHostPort(origin.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			seen := make(chan *flow.HTTPFlow, 1)
			addon := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				switch name {
				case "requestheaders":
					f.Request.Host, f.Request.Port = "example.com", port
					f.ServerConn.TransportProtocol = connection.TCP
					f.Request.Stream = test.streamed
				case "responseheaders":
					f.Response.Stream = test.streamed
				case "response":
					seen <- f
				}
			}}
			fixture, master := newTestStream(t, addon)
			roots := x509.NewCertPool()
			roots.AddCert(origin.Certificate())
			if err := master.Do(ctx, func(ctx context.Context) error {
				fixture.c.Data.Server.Address = &connection.Address{Host: "bootstrap.test", Port: 443}
				return master.Addons.Add(ctx, &http3TCPOriginTLS{roots: roots})
			}); err != nil {
				t.Fatal(err)
			}
			fixture.c.Pool = &http3TCPOriginSockets{pipePool: newPipePool(t), address: origin.Listener.Addr().String()}
			fixture.c.Record = proxy.Record
			fixture.c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
			peer, client := newHTTP3ConsumerPeer(t, ctx, false)
			_, server := newHTTP3ConsumerPeer(t, ctx, true)
			runCtx, cancel := context.WithCancel(ctx)
			joined := make(chan struct{})
			consumer := &httpLayer{route: routeConfig{mode: modeTransparent, validateInboundHeaders: true}}
			go func() { defer close(joined); _ = consumer.RunQUIC(runCtx, fixture.c, client, server) }()
			defer func() { cancel(); <-joined }()
			request, err := peer.conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			writeHTTP3TestHeaders(t, request, []qpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "bootstrap.test"}, {Name: ":path", Value: "/echo"}, {Name: "content-length", Value: "3"}})
			writeHTTP3TestFrame(t, request, 0, []byte("abc"))
			if err := request.Close(); err != nil {
				t.Fatal(err)
			}
			fields, body, _ := readHTTP3TestMessage(t, request)
			if fields[0].Value != "200" {
				t.Fatalf("HTTP3 response = %v %q", fields, body)
			}
			if diff := gocmp.Diff("abc", string(body)); diff != "" {
				t.Fatal(diff)
			}
			select {
			case version := <-protocol:
				if version != 2 {
					t.Fatalf("origin negotiated HTTP/%d", version)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			select {
			case f := <-seen:
				if err := master.Do(ctx, func(context.Context) error {
					if f.Request.HTTPVersion != "HTTP/3" || f.Response.HTTPVersion != "HTTP/2.0" || f.ServerConn.TransportProtocol != connection.TCP {
						return fmt.Errorf("mixed flow metadata: %s/%s/%s", f.Request.HTTPVersion, f.Response.HTTPVersion, f.ServerConn.TransportProtocol)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
