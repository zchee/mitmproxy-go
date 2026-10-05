// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestHTTPOrigin(t *testing.T) {
	requests := make(chan string, 2)
	origin := proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Proto + " " + r.RequestURI
		w.Header().Set("Trailer", "X-Finished")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "origin body")
		w.Header().Set("X-Finished", "yes")
	}))
	if origin.CA != nil || origin.Leaf != nil {
		t.Fatal("plaintext HTTP origin unexpectedly has a certificate")
	}
	conn := dial(t, origin.Addr)
	reader := bufio.NewReader(conn)
	for range 2 {
		if _, err := io.WriteString(conn, "GET /resource?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusCreated || response.Proto != "HTTP/1.1" || response.Close {
			t.Fatalf("response = %+v", response)
		}
		if diff := gocmp.Diff("origin body", string(body)); diff != "" {
			t.Fatal(diff)
		}
		if diff := gocmp.Diff("yes", response.Trailer.Get("X-Finished")); diff != "" {
			t.Fatal(diff)
		}
		if diff := gocmp.Diff("HTTP/1.1 /resource?q=1", <-requests); diff != "" {
			t.Fatal(diff)
		}
	}
}

func TestHTTPOriginCleanup(t *testing.T) {
	var conn net.Conn
	t.Run("origin lifetime", func(t *testing.T) {
		started := make(chan struct{})
		origin := proxytest.StartHTTPOrigin(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			close(started)
			<-r.Context().Done()
		}))
		var err error
		conn, err = (&net.Dialer{}).DialContext(t.Context(), "tcp", origin.Addr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, "GET /wait HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		receive(t, started)
	})
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("HTTP origin cleanup did not close the accepted connection: %v", err)
	}
}
