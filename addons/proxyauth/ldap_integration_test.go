// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build integration

package proxyauth

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon"
)

func TestLDAPIntegration(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	address := openLDAPAddress(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	config := ldapConfig{address: address, bindDN: "cn=admin,dc=example,dc=org", bindPassword: "integration-password"}
	var admin *ldap.Conn
	var closeAdmin func()
	var lastErr error
	for {
		admin, closeAdmin, lastErr = config.dial(ctx)
		if lastErr == nil {
			lastErr = admin.Bind(config.bindDN, config.bindPassword)
			if lastErr == nil {
				break
			}
			closeAdmin()
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			stack := make([]byte, 1<<20)
			n := runtime.Stack(stack, true)
			t.Fatalf("OpenLDAP did not become ready: %v\n%s", lastErr, stack[:n])
		}
	}
	defer closeAdmin()
	user := "user-" + strings.ReplaceAll(t.Name(), "/", "-")
	dn := "cn=" + user + ",dc=example,dc=org"
	entry := ldap.NewAddRequest(dn, nil)
	entry.Attribute("objectClass", []string{"inetOrgPerson"})
	entry.Attribute("cn", []string{user})
	entry.Attribute("sn", []string{"test"})
	entry.Attribute("userPassword", []string{"user-password"})
	if err := admin.Add(entry); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := admin.Del(ldap.NewDelRequest(dn, nil)); err != nil {
			t.Error(err)
		}
	}()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	spec := fmt.Sprintf("ldap:%s:%s:cn=admin,dc=example,dc=org:integration-password:dc=example,dc=org", host, port)
	_, manager, _ := newAuth(t, &spec)
	tests := map[string]struct {
		user, password string
		accepted       bool
	}{
		"correct bind":     {user, "user-password", true},
		"wrong password":   {user, "wrong", false},
		"missing user":     {"missing", "user-password", false},
		"escaped wildcard": {"*", "user-password", false},
		"empty user":       {"", "user-password", false},
		"empty password":   {user, "", false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := requestWithAuth(tt.user, tt.password)
			if err := manager.Hook(t.Context(), addon.RequestHeadersHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if tt.accepted {
				if f.Response != nil {
					t.Fatalf("valid bind rejected: %#v", f.Response)
				}
				got, _ := f.Metadata.Get("proxyauth")
				if diff := gocmp.Diff([]any{tt.user, tt.password}, got); diff != "" {
					t.Fatal(diff)
				}
				if f.Request.Headers.Has("Proxy-Authorization") {
					t.Fatal("successful header retained")
				}
			} else if f.Response == nil || f.Response.StatusCode != 407 {
				t.Fatal("invalid bind accepted")
			}
		})
	}
}

func openLDAPAddress(t *testing.T) string {
	t.Helper()
	if address := os.Getenv("MITMPROXY_TEST_LDAP_ADDRESS"); address != "" {
		return address
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("OpenLDAP integration requires Docker or MITMPROXY_TEST_LDAP_ADDRESS")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, docker, "info").CombinedOutput(); err != nil {
		t.Skipf("Docker is unavailable: %v: %s", err, out)
	}
	out, err := exec.CommandContext(ctx, docker, "run", "--detach", "--rm", "--publish", "127.0.0.1::389", "--env", "LDAP_DOMAIN=example.org", "--env", "LDAP_ADMIN_PASSWORD=integration-password", "--env", "LDAP_TLS=false", "osixia/openldap:1.5.0").Output()
	if err != nil {
		t.Fatalf("start OpenLDAP: %v", err)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
		defer stop()
		if out, err := exec.CommandContext(cleanupCtx, docker, "rm", "--force", id).CombinedOutput(); err != nil {
			t.Errorf("remove OpenLDAP: %v: %s", err, out)
		}
	})
	out, err = exec.CommandContext(ctx, docker, "port", id, "389/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}
