// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package webauth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/internal/tools/web/webauth"
	"github.com/zchee/mitmproxy-go/options"
)

const (
	argon2idVector = "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$ieVgG5ysTJFx4k/KvmC9aQ"
	argon2iVector  = "$argon2i$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$+mVW+bJM8rrFo4whr0C9Kg"
)

func authRegistry(t *testing.T) (*webauth.WebAuth, *addon.Manager, *options.Manager) {
	t.Helper()
	opts := options.New()
	if err := opts.Add(t.Context(), "web_host", options.TypeStr, "127.0.0.1", "test host"); err != nil {
		t.Fatal(err)
	}
	if err := opts.Add(t.Context(), "web_port", options.TypeInt, 8081, "test port"); err != nil {
		t.Fatal(err)
	}
	auth := webauth.New(opts)
	manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	if err := manager.Add(t.Context(), auth); err != nil {
		t.Fatal(err)
	}
	return auth, manager, opts
}

func update(t *testing.T, manager *addon.Manager, opts *options.Manager, values map[string]any) error {
	t.Helper()
	return manager.Do(t.Context(), func(ctx context.Context) error { return opts.Update(ctx, values) })
}

func configured(t *testing.T, manager *addon.Manager, opts *options.Manager, values map[string]any) {
	t.Helper()
	if err := update(t, manager, opts, values); err != nil {
		t.Fatal(err)
	}
}

func TestWebAuthConfiguration(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]struct {
			password        string
			invalid, random bool
		}{
			"test_token_auth":     {random: true},
			"test_plaintext_auth": {password: "test"},
			"test_argon2_auth":    {password: argon2idVector},
			"test_invalid_hash":   {password: "$argon2id$", invalid: true},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				var logs bytes.Buffer
				previous := slog.Default()
				slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
				t.Cleanup(func() { slog.SetDefault(previous) })
				auth, manager, opts := authRegistry(t)
				err := update(t, manager, opts, map[string]any{"web_password": tt.password})
				if tt.invalid {
					oe, ok := errors.AsType[*options.OptionsError](err)
					if !ok {
						t.Fatalf("invalid PHC error=%v", err)
					}
					if diff := gocmp.Diff("`web_password` starts with `$`, but it's not a valid argon2 hash.", oe.Error()); diff != "" {
						t.Fatal(diff)
					}
					if valid, err := auth.IsValidPassword(t.Context(), "test"); err != nil || valid {
						t.Fatalf("failed config activated password: %v,%v", valid, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				password := "test"
				if tt.random {
					address, err := url.Parse(auth.WebURL())
					if err != nil {
						t.Fatal(err)
					}
					password = address.Query().Get("token")
					if len(password) != 32 || strings.Trim(password, "0123456789abcdef") != "" {
						t.Fatalf("random token format invalid")
					}
					configured(t, manager, opts, map[string]any{"web_password": ""})
					if strings.Contains(auth.WebURL(), password) {
						t.Fatal("random token was not regenerated")
					}
					if valid, err := auth.IsValidPassword(t.Context(), password); err != nil || valid {
						t.Fatal("previous token remains active", err)
					}
					address, _ = url.Parse(auth.WebURL())
					password = address.Query().Get("token")
				} else if strings.Contains(auth.WebURL(), "token") {
					t.Fatal("configured password exposed in URL")
				}
				for _, input := range []string{"", "invalid", password} {
					valid, err := auth.IsValidPassword(t.Context(), input)
					if err != nil || valid != (input == password) {
						t.Fatalf("password match=%v want=%v err=%v", valid, input == password, err)
					}
				}
				if name == "test_plaintext_auth" {
					if !strings.Contains(logs.String(), "Consider using an argon2 hash") || strings.Contains(logs.String(), "\"test\"") {
						t.Fatalf("plaintext warning missing or includes password")
					}
				}
			})
		}
		t.Run("test_web_url", func(t *testing.T) {
			tests := map[string]struct {
				host string
				port int
				want string
			}{
				"hostname_8080": {"example.com", 8080, "http://example.com:8080/"},
				"ipv4_8080":     {"127.0.0.1", 8080, "http://127.0.0.1:8080/"},
				"ipv6_8080":     {"::1", 8080, "http://[::1]:8080/"},
				"hostname_80":   {"example.com", 80, "http://example.com:80/?"},
				"ipv4_80":       {"127.0.0.1", 80, "http://127.0.0.1:80/?"},
				"ipv6_80":       {"::1", 80, "http://[::1]:80/?"},
			}
			for name, tt := range tests {
				t.Run(name, func(t *testing.T) {
					auth, manager, opts := authRegistry(t)
					configured(t, manager, opts, map[string]any{"web_host": tt.host, "web_port": tt.port})
					if !strings.HasPrefix(auth.WebURL(), tt.want) {
						t.Fatalf("URL=%s want prefix=%s", auth.WebURL(), tt.want)
					}
				})
			}
		})
	})
	t.Run("limits", func(t *testing.T) {
		t.Run("accepted_boundaries", func(t *testing.T) {
			tests := map[string]struct{ hash string }{
				"minimum argon2id":        {argon2idVector},
				"minimum argon2i":         {argon2iVector},
				"maximum parameters":      {"$argon2id$v=19$m=262144,t=10,p=16$" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64)) + "$" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 64))},
				"parallel minimum memory": {strings.Replace(argon2idVector, "m=8,t=1,p=1", "m=128,t=1,p=16", 1)},
				"parameter order":         {strings.Replace(argon2idVector, "m=8,t=1,p=1", "p=1,m=8,t=1", 1)},
			}
			for name, tt := range tests {
				auth, manager, opts := authRegistry(t)
				if err := update(t, manager, opts, map[string]any{"web_password": tt.hash}); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if name == "minimum argon2id" || name == "minimum argon2i" {
					valid, err := auth.IsValidPassword(t.Context(), "test")
					if err != nil || !valid {
						t.Fatalf("%s: vector failed: %v,%v", name, valid, err)
					}
				}
			}
		})
		t.Run("rejected_boundaries", func(t *testing.T) {
			tests := map[string]struct{ old, replacement string }{
				"memory zero": {"m=8", "m=0"}, "memory below minimum": {"m=8", "m=7"},
				"memory over maximum": {"m=8", "m=262145"}, "parallel memory floor": {"p=1", "p=2"},
				"time zero": {"t=1", "t=0"}, "time eleven": {"t=1", "t=11"},
				"parallel zero": {"p=1", "p=0"}, "parallel seventeen": {"p=1", "p=17"},
				"uint32 overflow": {"m=8", "m=4294967296"}, "uint64 overflow": {"m=8", "m=18446744073709551616"},
				"negative": {"m=8", "m=-8"}, "signed positive": {"m=8", "m=+8"},
				"duplicate": {"m=8", "m=8,m=8"}, "unknown": {"m=8", "q=8"},
				"duplicate time": {"t=1", "t=1,t=1"}, "duplicate parallelism": {"p=1", "p=1,p=1"},
				"empty parameter": {"m=8", "m="}, "empty field": {"m=8", "m=8,"},
				"extra separator": {"v=19", "v=19$"}, "trailing field": {"ieVgG5ysTJFx4k/KvmC9aQ", "ieVgG5ysTJFx4k/KvmC9aQ$"},
				"whitespace number": {"m=8", "m= 8"}, "unicode number": {"m=8", "m=８"},
				"missing parameter": {"m=8,", ""}, "missing version": {"v=19$", ""},
				"old version": {"v=19", "v=16"}, "argon2d": {"argon2id", "argon2d"},
				"salt short": {"c2FsdHNhbHQ", "c2FsdA"}, "salt long": {"c2FsdHNhbHQ", base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 65))},
				"digest short": {"ieVgG5ysTJFx4k/KvmC9aQ", "YWJjZGVmZ2hpamtsbW5v"},
				"digest long":  {"ieVgG5ysTJFx4k/KvmC9aQ", base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 65))},
				"salt padding": {"c2FsdHNhbHQ", "c2FsdHNhbHQ="}, "newline": {"c2FsdHNhbHQ", "c2FsdHNhbHQ\n"},
				"noncanonical bits": {"c2FsdHNhbHQ", "c2FsdHNhbHR"}, "url alphabet": {"c2FsdHNhbHQ", "___________"},
				"encoded over limit": {"c2FsdHNhbHQ", strings.Repeat("A", 1025)},
			}
			_, manager, opts := authRegistry(t)
			for name, tt := range tests {
				hash := strings.Replace(argon2idVector, tt.old, tt.replacement, 1)
				if err := update(t, manager, opts, map[string]any{"web_password": hash}); err == nil {
					t.Errorf("%s accepted", name)
				}
			}
		})
		t.Run("config_rollback", func(t *testing.T) {
			auth, manager, opts := authRegistry(t)
			configured(t, manager, opts, map[string]any{"web_password": argon2idVector})
			before := auth.WebURL()
			if err := update(t, manager, opts, map[string]any{"web_password": "$argon2id$", "web_port": 9999}); err == nil {
				t.Fatal("malformed config accepted")
			}
			if diff := gocmp.Diff(before, auth.WebURL()); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff(argon2idVector, opts.Str("web_password")); diff != "" {
				t.Fatal(diff)
			}
			valid, err := auth.IsValidPassword(t.Context(), "test")
			if err != nil || !valid {
				t.Fatal("rollback invalidated active password", err)
			}
		})
	})
}
