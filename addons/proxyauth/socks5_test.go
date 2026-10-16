// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyauth

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"weak"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestSocks5Auth(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	file := filepath.Join(t.TempDir(), "htpasswd")
	if err := os.WriteFile(file, []byte("test:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		spec           *string
		user, password string
		valid          bool
	}{
		"dispatch accepts configured credentials": {new("test:test"), "test", "test", true},
		"wrong password":           {new("test:test"), "test", "wrong", false},
		"wrong user":               {new("test:test"), "wrong", "test", false},
		"any credentials":          {new("any"), "arbitrary", "p:a:s:s", true},
		"any empty credentials":    {new("any"), "", "", true},
		"single empty credentials": {new(":"), "", "", true},
		"htpasswd accepts":         {new("@" + file), "test", "test", true},
		"htpasswd rejects":         {new("@" + file), "test", "wrong", false},
		"disabled":                 {nil, "test", "test", false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p, manager, _ := newAuth(t, tt.spec)
			data := &hookdata.Socks5Auth{Client: testflow.TFlow().ClientConn, Username: tt.user, Password: tt.password}
			if err := manager.Hook(t.Context(), addon.Socks5AuthHook{Data: data}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.valid, data.Valid); diff != "" {
				t.Fatalf("socks5_auth dispatch validity (-want +got):\n%s", diff)
			}
			cached, ok := p.authenticated.Load(weak.Make(data.Client))
			if ok != tt.valid {
				t.Fatalf("cache present = %v, want %v", ok, tt.valid)
			}
			if tt.valid {
				if diff := gocmp.Diff([2]string{tt.user, tt.password}, cached); diff != "" {
					t.Fatal(diff)
				}
			}
			runtime.KeepAlive(data.Client)
		})
	}
}

func TestSocks5AuthenticatedRequests(t *testing.T) {
	tests := map[string]struct{ mode string }{
		"HTTP over SOCKS":  {"socks5"},
		"HTTPS over SOCKS": {"socks5"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p, manager, opts := newAuth(t, new("test:test"))
			first := testflow.TFlow()
			first.ClientConn.ProxyMode = tt.mode
			data := &hookdata.Socks5Auth{Client: first.ClientConn, Username: "test", Password: "test"}
			if err := manager.Hook(t.Context(), addon.Socks5AuthHook{Data: data}); err != nil {
				t.Fatal(err)
			}
			if !data.Valid {
				t.Fatal("SOCKS authentication rejected")
			}
			for i := range 2 {
				f := testflow.TFlow()
				f.ClientConn = first.ClientConn
				if name == "HTTPS over SOCKS" {
					f.ClientConn.TLS = true
					f.Request.Scheme = "https"
				}
				if err := manager.Hook(t.Context(), addon.RequestHeadersHook{Flow: f}); err != nil {
					t.Fatal(err)
				}
				if f.Response != nil {
					t.Fatalf("request %d challenged an authenticated SOCKS client", i)
				}
				got, ok := f.Metadata.Get("proxyauth")
				if !ok {
					t.Fatal("cached credentials absent from HTTP metadata")
				}
				if diff := gocmp.Diff([]any{"test", "test"}, got); diff != "" {
					t.Fatal(diff)
				}
				got.([]any)[0] = "changed"
			}
			other := testflow.TFlow()
			other.ClientConn.ProxyMode = "socks5"
			if err := manager.Hook(t.Context(), addon.RequestHeadersHook{Flow: other}); err != nil {
				t.Fatal(err)
			}
			if other.Response == nil || other.Response.StatusCode != 401 {
				t.Fatal("another client inherited SOCKS authentication")
			}
			// Reconfiguration does not mutate the immutable accepted-client pair.
			if err := manager.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{"proxyauth": new("other:secret")})
			}); err != nil {
				t.Fatal(err)
			}
			p.authenticated.Delete(weak.Make(first.ClientConn))
			if _, ok := p.authenticated.Load(weak.Make(first.ClientConn)); ok {
				t.Fatal("weak-client cleanup retained its cache entry")
			}
			runtime.KeepAlive(first.ClientConn)
		})
	}
}
