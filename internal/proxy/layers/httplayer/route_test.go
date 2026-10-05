// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/options"
)

func routeRequest(t *testing.T, method, target, version string, headers httpmsg.Headers) *httpmsg.Request {
	t.Helper()
	request := &httpmsg.Request{Method: method, HTTPVersion: version, Headers: headers}
	if method == "CONNECT" {
		request.Authority = target
	} else {
		scheme, host, port, path, err := httpmsg.ParseURLBytes([]byte(target))
		if err != nil {
			// An origin-form target carries no scheme or host.
			request.Path = target
		} else {
			request.Scheme = scheme
			request.Host = host
			request.Port = port
			request.Path = path
			request.Authority = httpmsg.HostPort(scheme, host, port)
		}
	}
	return request
}

func TestValidateRequest(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mode     httpMode
		validate bool
		request  *httpmsg.Request
		want     string
	}{
		"success: plain request passes": {
			mode:     modeRegular,
			validate: true,
			request:  routeRequest(t, "GET", "http://example.com/", "HTTP/1.1", nil),
		},
		"success: smuggling candidate accepted when validation is off": {
			mode: modeRegular,
			request: routeRequest(t, "POST", "http://example.com/", "HTTP/1.1", httpmsg.Headers{
				{Name: []byte("Transfer-Encoding"), Value: []byte("chunked")},
				{Name: []byte("Content-Length"), Value: []byte("3")},
			}),
		},
		"error: invalid scheme": {
			mode:     modeRegular,
			validate: true,
			request: &httpmsg.Request{
				Method: "GET", Scheme: "ftp", Host: "example.com", Port: 21,
				Path: "/", HTTPVersion: "HTTP/1.1",
			},
			want: "Invalid request scheme: ftp",
		},
		"error: connect in transparent mode": {
			mode:     modeTransparent,
			validate: true,
			request:  routeRequest(t, "CONNECT", "example.com:443", "HTTP/1.1", nil),
			want: "mitmproxy received an HTTP CONNECT request even though it is not running in " +
				"regular/upstream mode. This usually indicates a misconfiguration, " +
				"please see the mitmproxy mode documentation for details.",
		},
		"error: ambiguous framing refused": {
			mode:     modeRegular,
			validate: true,
			request: routeRequest(t, "POST", "http://example.com/", "HTTP/1.1", httpmsg.Headers{
				{Name: []byte("Transfer-Encoding"), Value: []byte("chunked")},
				{Name: []byte("Content-Length"), Value: []byte("3")},
			}),
			want: "Received message with both transfer-encoding and content-length headers from client, " +
				"refusing to prevent request smuggling attacks. " +
				"Disable the validate_inbound_headers option to skip this security check.",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := validateRequest(tt.mode, tt.request, tt.validate)
			if got != tt.want {
				t.Fatalf("validateRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestInboundValidationDefault builds the layer as an assembly without the
// proxyserver addon would: when nothing registers validate_inbound_headers,
// ambiguous framing is still refused, as with upstream's default; only an
// explicit false turns the check off.
func TestInboundValidationDefault(t *testing.T) {
	const refused = "Received message with both transfer-encoding and content-length headers from client, " +
		"refusing to prevent request smuggling attacks. " +
		"Disable the validate_inbound_headers option to skip this security check."
	tests := map[string]struct {
		register, value bool
		want            string
	}{
		"error: unregistered option validates":      {want: refused},
		"error: registered true validates":          {register: true, value: true, want: refused},
		"success: registered false skips the check": {register: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opts := options.New()
			if tt.register {
				if err := opts.Add(t.Context(), "validate_inbound_headers", options.TypeBool, tt.value, "Validate inbound headers."); err != nil {
					t.Fatal(err)
				}
			}
			c := &layer.Context{Data: &hookdata.Context{
				Client:  connection.NewClient(connection.Address{}, connection.Address{}, 1),
				Server:  connection.NewServer(nil),
				Options: opts,
			}}
			l, err := newHTTPLayer(c, hookdata.LayerSpec{HTTPMode: hookdata.HTTPModeRegular}, nil)
			if err != nil {
				t.Fatal(err)
			}
			route := l.(*httpLayer).exchangeRoute(c)
			request := routeRequest(t, "POST", "http://example.com/", "HTTP/1.1", httpmsg.Headers{
				{Name: []byte("Transfer-Encoding"), Value: []byte("chunked")},
				{Name: []byte("Content-Length"), Value: []byte("3")},
			})
			if got := validateRequest(route.mode, request, route.validateInboundHeaders); got != tt.want {
				t.Fatalf("validateRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeRequest(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		route     routeConfig
		clientTLS bool
		server    *connection.Server
		request   *httpmsg.Request
		want      *httpmsg.Request
		wantErr   string
	}{
		"success: transparent target from server metadata": {
			route: routeConfig{mode: modeTransparent},
			server: &connection.Server{
				Address: &connection.Address{Host: "example.com", Port: 443},
				TLS:     true,
			},
			request: &httpmsg.Request{Method: "GET", Path: "/x", HTTPVersion: "HTTP/1.1"},
			want: &httpmsg.Request{
				Method: "GET", Scheme: "https", Host: "example.com", Port: 443,
				Path: "/x", HTTPVersion: "HTTP/1.1",
			},
		},
		"success: regular absolute form becomes origin form": {
			route:   routeConfig{mode: modeRegular},
			server:  &connection.Server{},
			request: routeRequest(t, "GET", "http://example.com/x", "HTTP/1.1", nil),
			want: &httpmsg.Request{
				Method: "GET", Scheme: "http", Host: "example.com", Port: 80,
				Path: "/x", HTTPVersion: "HTTP/1.1",
			},
		},
		"success: host header fills a missing target": {
			route:  routeConfig{mode: modeRegular},
			server: &connection.Server{},
			request: &httpmsg.Request{
				Method: "GET", Path: "/x", HTTPVersion: "HTTP/1.1",
				Headers: httpmsg.Headers{{Name: []byte("Host"), Value: []byte("example.com:8080")}},
			},
			want: &httpmsg.Request{
				Method: "GET", Scheme: "http", Host: "example.com", Port: 8080,
				Path: "/x", HTTPVersion: "HTTP/1.1",
				Headers: httpmsg.Headers{{Name: []byte("Host"), Value: []byte("example.com:8080")}},
			},
		},
		"success: host header port defaults by client tls": {
			route:     routeConfig{mode: modeRegular},
			clientTLS: true,
			server:    &connection.Server{},
			request: &httpmsg.Request{
				Method: "GET", Path: "/x", HTTPVersion: "HTTP/1.1",
				Headers: httpmsg.Headers{{Name: []byte("Host"), Value: []byte("example.com")}},
			},
			want: &httpmsg.Request{
				Method: "GET", Scheme: "https", Host: "example.com", Port: 443,
				Path: "/x", HTTPVersion: "HTTP/1.1",
				Headers: httpmsg.Headers{{Name: []byte("Host"), Value: []byte("example.com")}},
			},
		},
		"success: reverse mode rewrites the host header": {
			route: routeConfig{mode: modeTransparent, reverse: true},
			server: &connection.Server{
				Address: &connection.Address{Host: "backend.example", Port: 8080},
			},
			request: &httpmsg.Request{
				Method: "GET", Path: "/x", HTTPVersion: "HTTP/1.1",
				Headers: httpmsg.Headers{{Name: []byte("Host"), Value: []byte("public.example")}},
			},
			want: &httpmsg.Request{
				Method: "GET", Scheme: "http", Host: "backend.example", Port: 8080,
				Path: "/x", HTTPVersion: "HTTP/1.1",
				Headers: httpmsg.Headers{{Name: []byte("Host"), Value: []byte("backend.example:8080")}},
			},
		},
		"success: reverse mode keeps the host header when asked": {
			route: routeConfig{mode: modeTransparent, reverse: true, keepHostHeader: true},
			server: &connection.Server{
				Address: &connection.Address{Host: "backend.example", Port: 8080},
			},
			request: &httpmsg.Request{
				Method: "GET", Path: "/x", HTTPVersion: "HTTP/1.1",
				Headers: httpmsg.Headers{{Name: []byte("Host"), Value: []byte("public.example")}},
			},
			want: &httpmsg.Request{
				Method: "GET", Scheme: "http", Host: "backend.example", Port: 8080,
				Path: "/x", HTTPVersion: "HTTP/1.1",
				Headers: httpmsg.Headers{{Name: []byte("Host"), Value: []byte("public.example")}},
			},
		},
		"error: no host header and no target": {
			route:   routeConfig{mode: modeRegular},
			server:  &connection.Server{},
			request: &httpmsg.Request{Method: "GET", Path: "/x", HTTPVersion: "HTTP/1.1"},
			wantErr: "HTTP request has no host header, destination unknown.",
		},
		"error: malformed host header": {
			route:  routeConfig{mode: modeRegular},
			server: &connection.Server{},
			request: &httpmsg.Request{
				Method: "GET", Path: "/x", HTTPVersion: "HTTP/1.1",
				Headers: httpmsg.Headers{{Name: []byte("Host"), Value: []byte("example.com:not-a-port")}},
			},
			wantErr: "HTTP request has no host header, destination unknown.",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gotErr := normalizeRequest(tt.route, tt.clientTLS, tt.server, tt.request)
			if gotErr != tt.wantErr {
				t.Fatalf("normalizeRequest() = %q, want %q", gotErr, tt.wantErr)
			}
			if tt.wantErr != "" {
				return
			}
			if diff := gocmp.Diff(tt.want, tt.request); diff != "" {
				t.Fatalf("normalized request differs (-want +got):\n%s", diff)
			}
		})
	}
}
