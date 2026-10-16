// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build integration && unix

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	yaml "go.yaml.in/yaml/v4"

	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
)

func TestSocks5CLI(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Fatalf("SOCKS executable acceptance requires curl: %v", err)
	}
	tests := map[string]struct {
		network, address, host, option string
	}{
		"proxy resolves domain": {"tcp", "[::]:0", "localhost", "--socks5-hostname"},
		"client supplies IPv4":  {"tcp4", "127.0.0.1:0", "127.0.0.1", "--socks5"},
		"client supplies IPv6":  {"tcp6", "[::1]:0", "::1", "--socks5"},
	}
	for name, route := range tests {
		t.Run(name, func(t *testing.T) {
			tests := map[string]struct{ tls bool }{
				"HTTP": {}, "HTTPS": {tls: true},
			}
			for name, protocol := range tests {
				t.Run(name, func(t *testing.T) {
					tests := map[string]struct {
						configured, supplied string
						exit                 int
					}{
						"no authentication":    {},
						"accepted credentials": {configured: "cli-user:cli-password", supplied: "cli-user:cli-password"},
						"wrong credentials":    {configured: "cli-user:cli-password", supplied: "cli-user:incorrect", exit: 97},
						"missing credentials":  {configured: "cli-user:cli-password", exit: 97},
					}
					for name, auth := range tests {
						t.Run(name, func(t *testing.T) {
							confdir := t.TempDir()
							store, err := certs.FromStore(confdir, "mitmproxy", 2048, nil)
							if err != nil {
								t.Fatal(err)
							}
							entry, err := store.GetCert("localhost", []certs.GeneralName{certs.DNSName("localhost"), certs.IPAddress(netip.MustParseAddr("127.0.0.1")), certs.IPAddress(netip.IPv6Loopback())}, "", "")
							if err != nil {
								t.Fatal(err)
							}
							ca := filepath.Join(confdir, "mitmproxy-ca-cert.pem")
							type observedRequest struct {
								Path, Host, ProxyAuth, Authorization string
								Hook                                 []string
							}
							requests := make(chan observedRequest, 3)
							origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								select {
								case requests <- observedRequest{r.URL.Path, r.Host, r.Header.Get("Proxy-Authorization"), r.Header.Get("Authorization"), r.Header.Values("X-Socks-Request")}:
								default:
									t.Error("origin received more than two requests")
								}
								_, _ = io.WriteString(w, r.URL.Path+"\n")
							}))
							if err := origin.Listener.Close(); err != nil {
								t.Fatal(err)
							}
							origin.Listener, err = net.Listen(route.network, route.address)
							if err != nil {
								t.Fatalf("required %s origin: %v", route.network, err)
							}
							scheme := "http"
							if protocol.tls {
								scheme = "https"
								origin.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{entry.Cert.X509().Raw}, PrivateKey: entry.PrivateKey}}}
								origin.StartTLS()
							} else {
								origin.Start()
							}
							defer origin.Close()
							port := origin.Listener.Addr().(*net.TCPAddr).Port
							authority := net.JoinHostPort(route.host, strconv.Itoa(port))
							capture := filepath.Join(t.TempDir(), "flows.mitm")
							args := []string{
								"--mode", "socks5", "--set", "confdir=" + confdir, "--set", "save_stream_file=" + capture,
								"--set", "ssl_verify_upstream_trusted_ca=" + ca,
								"--set", "modify_headers=|~q|X-Socks-Request|request-hook",
								"--set", "modify_headers=|~s|X-Socks-Response|response-hook",
							}
							if auth.configured != "" {
								args = append(args, "--proxyauth", auth.configured)
							}
							proxy, address, output := servingChild(t, args...)
							headers := filepath.Join(t.TempDir(), "headers.txt")
							curlArgs := []string{
								"-q", "--silent", "--show-error", "--fail", "--http1.1", "--noproxy", "", "--max-time", "20",
								route.option, address, "--cacert", ca, "--dump-header", headers,
							}
							if auth.supplied != "" {
								curlArgs = append(curlArgs, "--proxy-user", auth.supplied)
							}
							curlArgs = append(curlArgs, scheme+"://"+authority+"/first", scheme+"://"+authority+"/second")
							ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
							defer cancel()
							client := exec.CommandContext(ctx, curl, curlArgs...)
							var body, diagnostic bytes.Buffer
							client.Stdout, client.Stderr = &body, &diagnostic
							err = client.Run()
							exit := 0
							if failure, ok := errors.AsType[*exec.ExitError](err); ok {
								exit = failure.ExitCode()
							} else if err != nil {
								t.Fatal(err)
							}
							stopServingChild(t, proxy, output)
							if exit != auth.exit {
								t.Fatalf("curl exit=%d want=%d; stderr=%s", exit, auth.exit, diagnostic.String())
							}
							file, err := os.Open(capture)
							if err != nil {
								t.Fatal(err)
							}
							defer func() { _ = file.Close() }()
							var flows []*flow.HTTPFlow
							for recorded, err := range flowio.NewReader(file).All() {
								if err != nil {
									t.Fatal(err)
								}
								f, ok := recorded.(*flow.HTTPFlow)
								if !ok {
									t.Fatalf("unexpected emitted flow type %T", recorded)
								}
								flows = append(flows, f)
							}
							if auth.exit != 0 {
								if len(flows) != 0 || len(requests) != 0 || body.Len() != 0 {
									t.Fatalf("refused credentials forwarded traffic: flows=%d requests=%d body_bytes=%d", len(flows), len(requests), body.Len())
								}
								t.Logf("curl exit=%d; origin requests=0; emitted flows=0; mitmdump exit=0", exit)
								return
							}
							if diff := gocmp.Diff("/first\n/second\n", body.String()); diff != "" {
								t.Fatalf("curl response (-want +got):\n%s", diff)
							}
							if len(flows) != 2 || len(requests) != 2 {
								t.Fatalf("completed exchanges: flows=%d requests=%d, want two of each", len(flows), len(requests))
							}
							heads, err := os.ReadFile(headers)
							if err != nil {
								t.Fatal(err)
							}
							if strings.Count(strings.ToLower(string(heads)), "x-socks-response: response-hook") != 2 || strings.Contains(strings.ToLower(string(heads)), "authenticate:") {
								t.Fatal("curl did not receive exactly two response-hook markers without an authentication challenge")
							}
							for i, f := range flows {
								path := []string{"/first", "/second"}[i]
								want := observedRequest{Path: path, Host: authority, Hook: []string{"request-hook"}}
								if diff := gocmp.Diff(want, <-requests); diff != "" {
									t.Fatalf("origin exchange (-want +got):\n%s", diff)
								}
								if f.Error != nil || f.Request == nil || f.Response == nil || f.ServerConn == nil || f.ServerConn.Address == nil || f.ClientConn == nil {
									t.Fatal("saved exchange lacks successful HTTP/connection state")
								}
								if f.ServerConn.Address.Host != route.host || f.ServerConn.Address.Port != port || f.ClientConn.ProxyMode != "socks5" || f.ClientConn.ID != flows[0].ClientConn.ID {
									t.Fatal("saved original SOCKS destination, mode, or same-client reuse changed")
								}
								if f.Response.StatusCode != http.StatusOK || string(f.Response.RawContent) != path+"\n" || f.Request.Path != path || f.Request.Scheme != scheme {
									t.Fatal("saved request/response does not match the origin exchange")
								}
								if !gocmp.Equal([]string{"request-hook"}, f.Request.Headers.GetAll("X-Socks-Request")) || !gocmp.Equal([]string{"response-hook"}, f.Response.Headers.GetAll("X-Socks-Response")) {
									t.Fatal("saved request/response hook effects are missing or duplicated")
								}
								value, authenticated := f.Metadata.Get("proxyauth")
								if authenticated != (auth.configured != "") || authenticated && !gocmp.Equal([]any{"cli-user", "cli-password"}, value) {
									t.Fatal("saved SOCKS authentication metadata was not reused")
								}
							}
							t.Logf("curl exit=0; origin requests=2; emitted HTTP flows=2; request/response hook effects=2/2; same SOCKS client; destination=%s; mitmdump exit=0", authority)
						})
					}
				})
			}
		})
	}
	t.Run("completion and options unchanged", func(t *testing.T) {
		confdir := t.TempDir()
		var baseline map[string]any
		tests := map[string]struct{ mode string }{"regular": {"regular"}, "socks5": {"socks5"}}
		for _, name := range []string{"regular", "socks5"} {
			out, stderr, code := goRun(t, "--set", "confdir="+confdir, "--mode", tests[name].mode, "--options")
			if code != 0 {
				t.Fatalf("%s options exit=%d: %s", name, code, stderr)
			}
			var parsed map[string]any
			if err := yaml.Load([]byte(out), &parsed); err != nil {
				t.Fatal(err)
			}
			if !gocmp.Equal([]any{name}, parsed["mode"]) {
				t.Fatal("requested mode was not published in the option listing")
			}
			delete(parsed, "mode")
			if name == "regular" {
				baseline = parsed
			} else if diff := gocmp.Diff(baseline, parsed); diff != "" {
				t.Fatalf("SOCKS changed option defaults (-regular +socks5):\n%s", diff)
			}
		}
		before, stderr, code := goRun(t, "__complete", "--")
		if code != 0 {
			t.Fatalf("default completion exit=%d: %s", code, stderr)
		}
		after, stderr, code := goRun(t, "--mode", "socks5", "__complete", "--")
		if code != 0 {
			t.Fatalf("SOCKS completion exit=%d: %s", code, stderr)
		}
		if diff := gocmp.Diff(before, after); diff != "" {
			t.Fatalf("SOCKS changed completion flags (-before +after):\n%s", diff)
		}
	})
}
