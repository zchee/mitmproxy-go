// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest_test

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestRequestHeaderControlValidation(t *testing.T) {
	tests := map[string]struct {
		validate bool
		field    string
		status   int
	}{
		"error: bare CR with validation":      {validate: true, field: "X: a\rContent-Length: 9\r\n", status: http.StatusBadRequest},
		"success: bare CR without validation": {field: "X: a\rContent-Length: 9\r\n", status: http.StatusOK},
		"success: obs-fold with validation":   {validate: true, field: "X: first\r\n second\r\n", status: http.StatusOK},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			received := make(chan []byte, 1)
			origin := proxytest.StartOrigin(t, func(conn net.Conn) {
				reader := bufio.NewReader(conn)
				var head []byte
				for {
					line, err := reader.ReadBytes('\n')
					if err != nil {
						return
					}
					head = append(head, line...)
					if bytes.Equal(line, []byte("\r\n")) {
						break
					}
				}
				received <- head
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			})
			p := proxytest.Start(t, proxytest.WithOrigin("example.test", origin), proxytest.WithOptions(map[string]any{
				"validate_inbound_headers": tt.validate,
			}))
			response, body := httpExchange(t, dial(t, p.Addr), "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n"+tt.field+"\r\n")
			if diff := gocmp.Diff(tt.status, response.StatusCode); diff != "" {
				t.Fatalf("response (-want +got):\n%s\n%s", diff, body)
			}
			if tt.status == http.StatusBadRequest {
				if !strings.Contains(string(body), "invalid header value") {
					t.Fatalf("error body = %q", body)
				}
				return
			}
			if got := receive(t, received); !bytes.Contains(got, []byte(tt.field)) {
				t.Fatalf("origin head = %q, want original field %q", got, tt.field)
			}
		})
	}
}
