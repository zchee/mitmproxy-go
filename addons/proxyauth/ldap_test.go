// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyauth

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
)

func TestLDAPReadLimit(t *testing.T) {
	tests := map[string]struct{ limit int64 }{
		"empty budget": {0}, "short budget": {4}, "full budget": {16},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = server.Close() }()
				_, _ = io.WriteString(server, strings.Repeat("x", 16))
			}()
			limited := &limitedLDAPConn{Conn: client, reader: io.LimitedReader{R: client, N: tt.limit}}
			got, err := io.ReadAll(limited)
			if err != nil || string(got) != strings.Repeat("x", int(tt.limit)) {
				t.Fatalf("bounded read = %q, %v", got, err)
			}
			if _, err := limited.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("exhausted budget = %v, want EOF", err)
			}
			_ = client.Close()
			await(t, done)
		})
	}
}

func TestLDAPPort(t *testing.T) {
	tests := map[string]struct {
		port     string
		accepted bool
	}{
		"minimum": {"1", true}, "maximum": {"65535", true},
		"sign": {"+389", true}, "leading zero": {"0389", true},
		"zero": {"0", false}, "negative": {"-1", false}, "too large": {"65536", false},
		"underscore": {"3_89", false}, "whitespace": {" 389", false}, "unicode": {"３８９", false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parseLDAPSpec("ldap:host:" + tt.port + ":dn:password:base")
			if (err == nil) != tt.accepted {
				t.Fatalf("port %q: accepted = %v, want %v", tt.port, err == nil, tt.accepted)
			}
		})
	}
}

func TestLDAPDiagnosticRedaction(t *testing.T) {
	tests := map[string]struct{ spec, field string }{
		"field count":   {"ldap:server:private-password", "field count"},
		"scheme":        {"ldapss:server:dn:private-password:base", "scheme"},
		"port":          {"ldap:server:bad:dn:private-password:base", "port"},
		"search filter": {"ldap:server:dn:private-password:base?bad=x", "search filter"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parseLDAPSpec(tt.spec)
			if err == nil || !strings.Contains(err.Error(), tt.field) || strings.Contains(err.Error(), "private-password") {
				t.Fatalf("diagnostic must identify the field without credentials: %v", err)
			}
		})
	}
}

func TestLDAPUnreachable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	_, manager, _ := newAuth(t, new("ldap:"+address+":cn=admin:secret:dc=example"))
	f := requestWithAuth("user", "password")
	if err := manager.Hook(t.Context(), addon.RequestHeadersHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if f.Response == nil || f.Response.StatusCode != 407 {
		t.Fatal("unreachable LDAP did not fail closed")
	}
	if !strings.Contains(logs.String(), "LDAP authentication failed") {
		t.Fatal("missing LDAP failure log")
	}
}

func TestLDAPReleasesDispatchAndCancels(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan struct{})
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = peer.Close() }()
		close(accepted)
		_, _ = io.Copy(io.Discard, peer)
	}()
	_, manager, opts := newAuth(t, new("ldap:"+listener.Addr().String()+":cn=admin:secret:dc=example"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	f := requestWithAuth("user", "password")
	go func() {
		defer close(done)
		if err := manager.Hook(ctx, addon.RequestHeadersHook{Flow: f}); err != nil {
			t.Error(err)
		}
	}()
	await(t, accepted)
	changed := make(chan struct{})
	go func() {
		defer close(changed)
		if err := setAuth(t, manager, opts, new("replacement:password")); err != nil {
			t.Error(err)
		}
	}()
	await(t, changed)
	cancel()
	await(t, done)
	await(t, peerDone)
	if f.Response == nil || f.Response.StatusCode != 407 {
		t.Fatal("canceled LDAP exchange did not fail closed")
	}
	replacement := requestWithAuth("replacement", "password")
	if err := manager.Hook(t.Context(), addon.RequestHeadersHook{Flow: replacement}); err != nil {
		t.Fatal(err)
	}
	if replacement.Response != nil {
		t.Fatal("in-flight LDAP overwrote replacement configuration")
	}
}

func await(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		t.Fatalf("operation did not complete\n%s", stack[:n])
	}
}

// Upstream test_ldap and test_ldap_username_sanitization. Real LDAP binding
// is covered by TestLDAPIntegration instead of upstream's mocked service.
func TestLDAPSpec(t *testing.T) {
	tests := map[string]struct {
		spec string
		want ldapConfig
	}{
		"tls":    {"ldaps:localhost:cn=default:password:ou=application", ldapConfig{address: "localhost:636", tls: true, bindDN: "cn=default", bindPassword: "password", subtree: "ou=application", filterKey: "cn"}},
		"port":   {"ldap:localhost:1234:cn=default:password:ou=application", ldapConfig{address: "localhost:1234", bindDN: "cn=default", bindPassword: "password", subtree: "ou=application", filterKey: "cn"}},
		"filter": {"ldap:localhost:1234:cn=default:password:ou=application?search_filter_key=cn", ldapConfig{address: "localhost:1234", bindDN: "cn=default", bindPassword: "password", subtree: "ou=application", filterKey: "cn"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseLDAPSpec(tt.spec)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, *got, gocmp.AllowUnexported(ldapConfig{})); diff != "" {
				t.Fatal(diff)
			}
			if got.searchFilter("*") != `(cn=\2a)` {
				t.Fatal("LDAP wildcard not escaped")
			}
			if valid, err := got.check(t.Context(), "", ""); valid || err != nil {
				t.Fatalf("empty credentials = %v, %v", valid, err)
			}
		})
	}
}
