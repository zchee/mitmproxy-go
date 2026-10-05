// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"testing"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/http1"
)

func TestLayerFidelity(t *testing.T) {
	tests := map[string]struct {
		request      string
		requestWire  string
		response     string
		responseWire string
		hook         string
		reverse      bool
		continue100  bool
		count        uint64
	}{
		"success: metadata normalization preserves bytes": {
			request:     "GET /x HTTP/1.1\r\nHost:\torigin.test\r\nX-FOO:  padded\r\n\r\n",
			requestWire: "GET /x HTTP/1.1\r\nHost:\torigin.test\r\nX-FOO:  padded\r\n\r\n",
		},
		"success: absolute target and folded field count independently": {
			request:     "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\nX-Long: a\r\n\tb\r\n\r\n",
			requestWire: "GET /x HTTP/1.1\r\nHost: origin.test\r\nX-Long: a\r\n b\r\n\r\n",
			count:       2,
		},
		"success: reverse host and folded field count independently": {
			request:     "GET /x HTTP/1.1\r\nHost: client.test\r\nX-Long: a\r\n\tb\r\n\r\n",
			requestWire: "GET /x HTTP/1.1\r\nHost: origin.test\r\nX-Long: a\r\n b\r\n\r\n",
			reverse:     true, count: 2,
		},
		"success: expect removal counts as proxy rewrite": {
			request:     "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\nExpect: 100-continue\r\nX-Long: a\r\n\tb\r\n\r\n",
			requestWire: "GET /x HTTP/1.1\r\nHost: origin.test\r\nX-Long: a\r\n b\r\n\r\n",
			continue100: true, count: 3,
		},
		"success: requestheaders edit excludes entire emission": {
			request:     "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\nX-Long: a\r\n\tb\r\n\r\n",
			requestWire: "GET /edited HTTP/1.1\r\nHost: origin.test\r\nX-Long: a\r\n b\r\n\r\n",
			hook:        "requestheaders",
		},
		"success: request edit excludes entire emission": {
			request:     "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\nX-Long: a\r\n\tb\r\n\r\n",
			requestWire: "GET /edited HTTP/1.1\r\nHost: origin.test\r\nX-Long: a\r\n b\r\n\r\n",
			hook:        "request",
		},
		"success: response fold is counted": {
			request:      "GET /x HTTP/1.1\r\nHost: origin.test\r\n\r\n",
			requestWire:  "GET /x HTTP/1.1\r\nHost: origin.test\r\n\r\n",
			response:     "HTTP/1.1 204 No Content\r\nX-Long: a\r\n\tb\r\n\r\n",
			responseWire: "HTTP/1.1 204 No Content\r\nX-Long: a\r\n b\r\n\r\n",
			count:        1,
		},
		"success: responseheaders edit excludes response only": {
			request:      "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n",
			requestWire:  "GET /x HTTP/1.1\r\nHost: origin.test\r\n\r\n",
			response:     "HTTP/1.1 204 No Content\r\nX-Long: a\r\n\tb\r\n\r\n",
			responseWire: "HTTP/1.1 204 Edited\r\nX-Long: a\r\n b\r\n\r\n",
			hook:         "responseheaders", count: 1,
		},
		"success: response edit excludes response only": {
			request:      "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n",
			requestWire:  "GET /x HTTP/1.1\r\nHost: origin.test\r\n\r\n",
			response:     "HTTP/1.1 204 No Content\r\nX-Long: a\r\n\tb\r\n\r\n",
			responseWire: "HTTP/1.1 204 Edited\r\nX-Long: a\r\n b\r\n\r\n",
			hook:         "response", count: 1,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if name != tt.hook {
					return
				}
				if name == "requestheaders" || name == "request" {
					f.Request.Path = "/edited"
				} else {
					f.Response.Reason = "Edited"
				}
			}}
			s := newLayerSession(t, a, "connection_strategy=lazy")
			counter := new(http1.FidelityCounter)
			s.c.HTTPFidelity = counter
			mode := hookdata.HTTPModeRegular
			if tt.reverse {
				s.c.Data.Client.ProxyMode = "reverse:http://origin.test"
				s.c.Data.Server = connection.NewServer(&connection.Address{Host: "origin.test", Port: 80})
				mode = hookdata.HTTPModeTransparent
			}
			s.start(mode)
			write(t, s.client, tt.request)
			if tt.continue100 {
				expectRead(t, s.client, "HTTP/1.1 100 Continue\r\n\r\n")
			}
			origin := await(t, s.pool.origins)
			expectRead(t, origin, tt.requestWire)
			response, responseWire := tt.response, tt.responseWire
			if response == "" {
				response = "HTTP/1.1 204 No Content\r\n\r\n"
				responseWire = response
			}
			write(t, origin, response)
			expectRead(t, s.client, responseWire)
			if err := s.client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if err := await(t, s.done); err != nil {
				t.Fatal(err)
			}
			if got := counter.Load(); got != tt.count {
				t.Fatalf("emitted normalization count = %d, want %d", got, tt.count)
			}
		})
	}
}
