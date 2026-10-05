// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package core_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/options"
)

func updateOptions(t *testing.T, h harness, values map[string]any) error {
	t.Helper()
	return h.manager.Do(t.Context(), func(ctx context.Context) error { return h.manager.Options().Update(ctx, values) })
}

func TestValidationSimple(t *testing.T) {
	h := setup(t)
	err := updateOptions(t, h, map[string]any{"add_upstream_certs_to_client_chain": true, "upstream_cert": false})
	if _, ok := errors.AsType[*options.OptionsError](err); !ok || !strings.Contains(err.Error(), "requires the upstream_cert option to be enabled") {
		t.Fatalf("invalid certificate options: %v", err)
	}
	if h.manager.Options().Bool("add_upstream_certs_to_client_chain") || !h.manager.Options().Bool("upstream_cert") {
		t.Fatal("rejected configuration was not rolled back")
	}
	if err := updateOptions(t, h, map[string]any{"add_upstream_certs_to_client_chain": true}); err != nil {
		t.Fatal(err)
	}
	if err := updateOptions(t, h, map[string]any{"upstream_cert": false}); err == nil {
		t.Fatal("invalid option combination accepted")
	}
}

func TestClientCerts(t *testing.T) {
	dir, err := filepath.Abs("../../testdata/mitmproxy/clientcert")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		value   any
		wantErr bool
	}{
		"directory": {dir, false},
		"file":      {filepath.Join(dir, "client.pem"), false},
		"absent":    {filepath.Join(t.TempDir(), "missing"), true},
		"empty":     {"", false},
		"none":      {nil, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			err := updateOptions(t, h, map[string]any{"client_certs": tt.value})
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if _, ok := errors.AsType[*options.OptionsError](err); !ok || !strings.Contains(err.Error(), "Client certificate path does not exist: "+tt.value.(string)) {
					t.Fatalf("invalid path error = %v", err)
				}
				if h.manager.Options().OptStr("client_certs") != nil {
					t.Fatal("rejected certificate path was not rolled back")
				}
			}
		})
	}
}

func TestClientCertsHomeAndUpdateSelection(t *testing.T) {
	h := setup(t)
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
	cert := filepath.Join(home, "client.pem")
	if err := os.WriteFile(cert, []byte("exists, validation does not parse certificates"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateOptions(t, h, map[string]any{"client_certs": "~/client.pem"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cert); err != nil {
		t.Fatal(err)
	}
	if err := updateOptions(t, h, map[string]any{"listen_host": "elsewhere"}); err != nil {
		t.Fatalf("unrelated update rechecked client_certs: %v", err)
	}
	if err := h.manager.Trigger(t.Context(), addon.ConfigureHook{Updated: map[string]struct{}{"client_certs": {}}}); err == nil {
		t.Fatal("client_certs update did not recheck deleted path")
	}
}

func TestClientCertsNamedUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	} // Windows expanduser uses USERPROFILE, not the account database.
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	h := setup(t)
	if err := updateOptions(t, h, map[string]any{"client_certs": "~" + u.Username}); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeLimitOption(t *testing.T) {
	h := setup(t)
	o, ok := h.manager.Options().Lookup("content_decode_limit")
	if !ok {
		t.Fatal("missing content_decode_limit")
	}
	const help = "Maximum size of a decoded HTTP body. Bodies exceeding this limit are treated as undecodable."
	if o.Type() != options.TypeStr || o.Default() != "256m" || o.Help() != help {
		t.Fatalf("decode limit metadata: %s %v %q", o.Type(), o.Default(), o.Help())
	}
	data, err := os.ReadFile("../../testdata/options-go-only.txt")
	if err != nil {
		t.Fatal(err)
	}
	row := fmt.Sprintf("content_decode_limit\tstr\t\"256m\"\t%s\n", help)
	if !strings.Contains(string(data), row) {
		t.Fatalf("Go-only option table lacks %q", row)
	}
	tests := map[string]struct {
		value   string
		wantErr bool
	}{
		"one MiB":         {"1m", false},
		"zero":            {"0", false},
		"unicode integer": {"١_٠k", false},
		"negative":        {"-1", true},
		"fraction":        {"1.5m", true},
		"unknown unit":    {"1x", true},
		"empty":           {"", true},
		"overflow":        {"9223372036854775808", true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			err := updateOptions(t, h, map[string]any{"content_decode_limit": tt.value})
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, tt.wantErr)
			}
			want := tt.value
			if tt.wantErr {
				want = "256m"
				if _, ok := errors.AsType[*options.OptionsError](err); !ok || !strings.Contains(err.Error(), "content_decode_limit") {
					t.Fatalf("decode limit error = %v", err)
				}
			}
			if diff := gocmp.Diff(want, h.manager.Options().Str("content_decode_limit")); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
