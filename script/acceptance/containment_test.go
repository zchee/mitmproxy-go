// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package acceptance_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOwnedForwarderContainment(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct {
			mismatch bool
		}{
			"host_mismatch_no_origin": {mismatch: true},
			"matching_host_forwards":  {},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				var connections, requests atomic.Int64
				origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
					}
					equal(t, "contained payload", string(body))
					_, _ = io.WriteString(w, "owned response")
				}))
				origin.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateNew {
						connections.Add(1)
					}
				}
				origin.Start()
				t.Cleanup(origin.Close)
				reports := make(chan error, 1)
				upstream, route := guardedUpstreamWithReport(t, origin.URL, func(err error) { reports <- err })
				proxy, err := url.Parse(upstream)
				if err != nil {
					t.Fatal(err)
				}
				transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
				t.Cleanup(transport.CloseIdleConnections)
				client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, origin.URL+"/containment", strings.NewReader("contained payload"))
				if err != nil {
					t.Fatal(err)
				}
				if tt.mismatch {
					req.Host = "unexpected.invalid"
				}
				res, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = res.Body.Close() }()
				body, err := io.ReadAll(res.Body)
				if err != nil {
					t.Fatal(err)
				}
				requested := req.Host
				if !strings.Contains(requested, ":") {
					requested += ":80"
				}
				equal(t, []string{requested}, route.destinations())
				if tt.mismatch {
					equal(t, http.StatusBadGateway, res.StatusCode)
					equal(t, "unexpected upstream host\n", string(body))
					equal(t, int64(0), connections.Load())
					equal(t, int64(0), requests.Load())
					want := fmt.Sprintf("upstream requested host %q, want %q (mapped to %s)", req.Host, req.URL.Host, req.URL.Host)
					equal(t, want, receive(t, reports).Error())
				} else {
					equal(t, http.StatusOK, res.StatusCode)
					equal(t, "owned response", string(body))
					equal(t, int64(1), connections.Load())
					equal(t, int64(1), requests.Load())
				}
				select {
				case report := <-reports:
					t.Fatalf("unexpected forwarding failure: %v", report)
				default:
				}
			})
		}
	})
}
