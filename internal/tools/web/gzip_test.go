// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestWebGzip(t *testing.T) {
	tests := map[string]struct {
		size                                 int
		media, accept, encoded, path, method string
		status                               int
		compress                             bool
		flush                                bool
	}{
		"small":           {size: 1023, media: "application/json", accept: "gzip"},
		"threshold":       {size: 1024, media: "application/json", accept: "gzip", compress: true},
		"dump":            {size: 1 << 20, media: "application/octet-stream", accept: "gzip", compress: true},
		"text":            {size: 2048, media: "text/custom; charset=UTF-8", accept: "gzip", compress: true},
		"identity":        {size: 2048, media: "application/json", accept: "identity"},
		"no_accept":       {size: 2048, media: "application/json"},
		"already_encoded": {size: 2048, media: "application/json", accept: "gzip", encoded: "br"},
		"noncompressible": {size: 2048, media: "image/png", accept: "gzip"},
		"empty":           {media: "application/json", accept: "gzip"},
		"error":           {size: 2048, media: "text/html", accept: "gzip", status: 500, compress: true},
		"head":            {size: 2048, media: "application/json", accept: "gzip", method: "HEAD"},
		"upgrade_bypass":  {media: "application/json", accept: "gzip", path: "/updates", status: 101},
		"flush":           {size: 20, media: "application/json", accept: "gzip", compress: true, flush: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			body := bytes.Repeat([]byte("x"), test.size)
			handler := withGzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", test.media)
				w.Header().Set("Vary", "Origin")
				if test.encoded != "" {
					w.Header().Set("Content-Encoding", test.encoded)
				}
				if test.status != 0 {
					w.WriteHeader(test.status)
				}
				if test.method != "HEAD" {
					_, _ = w.Write(body)
				}
				if test.flush {
					w.(http.Flusher).Flush()
				}
			}))
			method := test.method
			if method == "" {
				method = "GET"
			}
			path := test.path
			if path == "" {
				path = "/"
			}
			request := httptest.NewRequestWithContext(t.Context(), method, path, nil)
			request.Header.Set("Accept-Encoding", test.accept)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			encoding := response.Header().Get("Content-Encoding")
			if (encoding == "gzip") != test.compress {
				t.Fatalf("encoding=%q want gzip=%v", encoding, test.compress)
			}
			if path != "/updates" && response.Header().Get("Vary") != "Origin, Accept-Encoding" {
				t.Fatalf("Vary=%q", response.Header().Get("Vary"))
			}
			if path == "/updates" && response.Header().Get("Vary") != "Origin" {
				t.Fatal("upgrade headers transformed")
			}
			got := response.Body.Bytes()
			if test.compress {
				reader, err := gzip.NewReader(bytes.NewReader(got))
				if err != nil {
					t.Fatal(err)
				}
				got, err = io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if method == "HEAD" {
				body = nil
			}
			if diff := gocmp.Diff(body, got); diff != "" && (len(body) != 0 || len(got) != 0) {
				t.Fatal(diff)
			}
		})
	}
	t.Run("canceled_request", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		request := httptest.NewRequestWithContext(ctx, "GET", "/", nil)
		request.Header.Set("Accept-Encoding", "gzip")
		response := httptest.NewRecorder()
		withGzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Err() == nil {
				t.Fatal("request cancellation lost")
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, strings.Repeat("x", 2048))
		})).ServeHTTP(response, request)
		if response.Header().Get("Content-Encoding") != "gzip" {
			t.Fatal("gzip response missing")
		}
	})
	t.Run("GET_HEAD_errors", func(t *testing.T) {
		h := newRouteHarness(t)
		for _, method := range []string{"GET", "HEAD"} {
			response, body := h.fetch(t, method, "/flows/42", nil, "")
			if response.StatusCode != 405 {
				t.Fatal(response.StatusCode)
			}
			want := ""
			if method != "HEAD" {
				want = fmt.Sprintf("<html><title>%d: %s</title><body>%d: %s</body></html>", 405, "Method Not Allowed", 405, "Method Not Allowed")
			}
			if string(body) != want {
				t.Fatalf("error body=%q want=%q", body, want)
			}
		}
	})
}
