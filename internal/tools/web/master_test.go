// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

func newWebMaster(t *testing.T) *Master {
	t.Helper()
	opts := options.New()
	if err := opts.Update(t.Context(), map[string]any{"confdir": t.TempDir(), "server": false}); err != nil {
		t.Fatal(err)
	}
	m, err := New(t.Context(), Config{Options: opts, Stdin: io.NopCloser(strings.NewReader("")), Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		return m.Options.Update(ctx, map[string]any{"web_port": 0, "web_open_browser": false, "web_password": "master-test"})
	}); err != nil {
		t.Fatal(err)
	}
	return m
}

func startWebMaster(t *testing.T, m *Master) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- m.Run(t.Context()) }()
	select {
	case <-m.Ready():
	case err := <-done:
		t.Fatalf("Run before Ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("web listener did not become ready")
	}
	return done
}

func stopWebMaster(t *testing.T, m *Master, done <-chan error) {
	t.Helper()
	m.Shutdown()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("web master did not join shutdown")
	}
}

func masterRequest(t *testing.T, m *Master, method, path, body, password string) *http.Response {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), method, "http://"+m.WebAddr().String()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if password != "" {
		r.Header.Set("Authorization", "Bearer "+password)
	}
	response, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}

type finalWebLog struct{ logger *slog.Logger }

func (a *finalWebLog) Done(ctx context.Context) error {
	a.logger.InfoContext(ctx, "final web lifecycle entry")
	return nil
}

func TestWebMaster(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]struct{}{"test_reuse": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := listener.Close(); err != nil {
						t.Error(err)
					}
				}()
				port := listener.Addr().(*net.TCPAddr).Port
				m := newWebMaster(t)
				if err := m.Do(t.Context(), func(ctx context.Context) error { return m.Options.Update(ctx, map[string]any{"web_port": port}) }); err != nil {
					t.Fatal(err)
				}
				err = m.Run(t.Context())
				if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("--set web_port=%d", port+2)) || !strings.Contains(err.Error(), "Web server failed to listen on") {
					t.Fatalf("listen conflict: %v", err)
				}
			})
		}
	})
	tests := map[string]struct{ run func(*testing.T) }{
		"constructor": {run: func(t *testing.T) {
			m := newWebMaster(t)
			if m.WebAddr() != nil {
				t.Fatal("constructor opened a listener")
			}
			select {
			case <-m.Ready():
				t.Fatal("constructor announced Ready")
			default:
			}
			if m.Handler() == nil || m.View == nil || m.Events == nil || m.ProxyServer == nil {
				t.Fatal("incomplete frontend assembly")
			}
			if m.Addons.Get("dumper") != nil || m.Addons.Get("keepserving") != nil {
				t.Fatal("dump-only addons registered")
			}
		}},
		"addon_order": {run: func(t *testing.T) {
			m := newWebMaster(t)
			var got []string
			for _, a := range m.Addons.Chain() {
				got = append(got, fmt.Sprintf("%T", a))
			}
			want := []string{"*core.Core", "*browser.Browser", "*block.Block", "*stripdnshttpsrecords.StripDNSHTTPSRecords", "*blocklist.BlockList", "*anticache.AntiCache", "*anticomp.AntiComp", "*clientplayback.ClientPlayback", "*commandhistory.Addon", "*comment.Comment", "*cut.Addon", "*disableh2c.DisableH2C", "*export.Addon", "*onboarding.Onboarding", "*proxyauth.ProxyAuth", "*proxyserver.ProxyServer", "*dnsresolver.DnsResolver", "*nextlayer.NextLayer", "*serverplayback.ServerPlayback", "*mapremote.MapRemote", "*maplocal.MapLocal", "*modifybody.ModifyBody", "*modifyheaders.ModifyHeaders", "*stickyauth.StickyAuth", "*stickycookie.StickyCookie", "*save.Save", "*savehar.Addon", "*tlsconfig.TLSConfig", "*upstreamauth.UpstreamAuth", "*updatealtsvc.UpdateAltSvc", "*web.WebAddon", "*webauth.WebAuth", "*intercept.Intercept", "*readfile.ReadFile", "*web.StaticViewer", "*view.View", "*eventstore.EventStore", "*errorcheck.ErrorCheck"}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Fatalf("addon order (-want +got):\n%s", diff)
			}
		}},
		"http_lifecycle": {run: func(t *testing.T) {
			m := newWebMaster(t)
			f := testflow.TFlow(testflow.WithResponse)
			if err := m.Do(t.Context(), func(ctx context.Context) error { m.View.Add(ctx, []flow.Flow{f}); return nil }); err != nil {
				t.Fatal(err)
			}
			done := startWebMaster(t, m)
			if got := m.Options.Int("web_port"); got != m.WebAddr().(*net.TCPAddr).Port {
				t.Fatalf("web_port=%d actual=%s", got, m.WebAddr())
			}
			for _, password := range []string{"", "wrong", "master-test"} {
				response := masterRequest(t, m, "GET", "/flows", "", password)
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				want := 403
				if password == "master-test" {
					want = 200
				}
				if response.StatusCode != want {
					t.Fatalf("auth status=%d want=%d", response.StatusCode, want)
				}
				if want == 200 && !strings.Contains(string(body), f.ID) {
					t.Fatalf("missing actual stored flow: %s", body)
				}
			}
			stopWebMaster(t, m, done)
			if _, err := net.DialTimeout("tcp", m.WebAddr().String(), time.Second); err == nil {
				t.Fatal("listener survived shutdown")
			}
		}},
		"shutdown_request": {run: func(t *testing.T) {
			m := newWebMaster(t)
			entered := make(chan struct{})
			if err := m.Do(t.Context(), func(context.Context) error {
				return m.Commands.Register("web.wait", func(ctx context.Context) string { close(entered); <-ctx.Done(); return "cancelled" })
			}); err != nil {
				t.Fatal(err)
			}
			done := startWebMaster(t, m)
			login := masterRequest(t, m, "GET", "/", "", "")
			cookies := login.Cookies()
			_, _ = io.Copy(io.Discard, login.Body)
			_ = login.Body.Close()
			requestDone := make(chan struct{})
			go func() {
				defer close(requestDone)
				r, err := http.NewRequestWithContext(t.Context(), "POST", "http://"+m.WebAddr().String()+"/commands/web.wait", strings.NewReader(`{"arguments":[]}`))
				if err != nil {
					return
				}
				r.Header.Set("Authorization", "Bearer master-test")
				r.Header.Set("Content-Type", "application/json")
				for _, cookie := range cookies {
					r.AddCookie(cookie)
					if cookie.Name == "_mitmproxy_xsrf" {
						r.Header.Set("X-XSRFToken", cookie.Value)
					}
				}
				response, _ := http.DefaultClient.Do(r)
				if response != nil {
					_ = response.Body.Close()
				}
			}()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("real command did not enter dispatch")
			}
			stopWebMaster(t, m, done)
			select {
			case <-requestDone:
			case <-time.After(10 * time.Second):
				t.Fatal("HTTP request survived shutdown")
			}
		}},
		"debug": {run: testWebDebug},
		"done_log": {run: func(t *testing.T) {
			m := newWebMaster(t)
			if err := m.Addons.Add(t.Context(), &finalWebLog{logger: m.Logger()}); err != nil {
				t.Fatal(err)
			}
			done := startWebMaster(t, m)
			if err := m.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			stopWebMaster(t, m, done)
			if err := m.Do(t.Context(), func(context.Context) error {
				found := 0
				for _, record := range m.Events.Records() {
					if strings.Contains(record.Entry.Msg, "add_log event has been deprecated") {
						t.Fatal("built-in store emitted a legacy-hook warning")
					}
					if strings.HasSuffix(record.Entry.Msg, "final web lifecycle entry") {
						found++
					}
				}
				if found != 1 {
					t.Fatalf("Done-time log entries after Close=%d want=1", found)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}},
		"stream_shutdown": {run: func(t *testing.T) {
			m := newWebMaster(t)
			done := startWebMaster(t, m)
			if err := m.eventLogs.Flush(t.Context()); err != nil {
				t.Fatal(err)
			}
			p := openWebPeer(t, m.WebURL(), "master-test")
			p.barrier(t)
			m.Shutdown()
			closed := false
			for range 16 {
				frame, err := p.ws.ReadFrame()
				if err != nil {
					t.Fatal(err)
				}
				if frame.Header.Opcode == gows.OpcodeText {
					continue
				}
				if frame.Header.Opcode != gows.OpcodeClose {
					t.Fatalf("shutdown frame=%+v", frame.Header)
				}
				body, err := gows.ParseClose(frame.Payload)
				if err != nil || body.Code != gows.CloseGoingAway {
					t.Fatalf("shutdown close=%+v error=%v", body, err)
				}
				if err := p.ws.WriteFrame(gows.OpcodeClose, true, frame.Payload, false); err != nil {
					t.Fatal(err)
				}
				closed = true
				break
			}
			if !closed {
				t.Fatal("owned stream did not send its shutdown close")
			}
			stopWebMaster(t, m, done)
		}},
		"early_shutdown": {run: testWebEarlyShutdown},
		"run_once": {run: func(t *testing.T) {
			m := newWebMaster(t)
			done := startWebMaster(t, m)
			if err := m.Run(t.Context()); err == nil {
				t.Fatal("second Run accepted")
			}
			stopWebMaster(t, m, done)
		}},
		"startup_errorcheck": {run: func(t *testing.T) {
			m := newWebMaster(t)
			m.Logger().ErrorContext(t.Context(), "deliberate startup failure")
			if err := m.Run(t.Context()); err == nil {
				t.Fatal("startup error ignored")
			}
			if m.WebAddr() != nil {
				t.Fatal("web listener opened after failed errorcheck")
			}
		}},
	}
	for name, tt := range tests {
		t.Run(name, tt.run)
	}
}
