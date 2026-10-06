// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	dtls "github.com/pion/dtls/v3"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
)

func TestTLSStartClientTransport(t *testing.T) {
	t.Parallel()
	testTLSStartTransport(t, "client", (*TLSConfig).TLSStartClient)
}

func TestTLSStartServerTransport(t *testing.T) {
	t.Parallel()
	testTLSStartTransport(t, "server", (*TLSConfig).TLSStartServer)
}

func testTLSStartTransport(t *testing.T, side string, start func(*TLSConfig, context.Context, *hookdata.TLS) error) {
	t.Helper()
	tests := map[string]struct {
		isDTLS     bool
		minVersion string
		preset     bool
		wantErr    string
	}{
		"success: DTLS builds only a DTLS configuration": {isDTLS: true},
		"success: TLS builds only a TLS configuration":   {},
		"error: DTLS rejects a TLS 1.3 minimum":          {isDTLS: true, minVersion: "TLS1_3", wantErr: "exclude it"},
		"success: TLS retains its TLS 1.3 minimum":       {minVersion: "TLS1_3"},
		"success: DTLS preserves an addon override":      {isDTLS: true, preset: true},
		"success: TLS preserves an addon override":       {preset: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc, m, opts := newTLSConfig(t)
			values := map[string]any{"ssl_insecure": true}
			if tt.minVersion != "" {
				values["tls_version_"+side+"_min"] = tt.minVersion
			}
			if err := configure(t, m, opts, values); err != nil {
				t.Fatal(err)
			}
			connCtx := testContext(opts)
			connCtx.Server.Address = &connection.Address{Host: "origin.example", Port: 443}
			d := &hookdata.TLS{Conn: &connCtx.Client.Connection, Context: connCtx, IsDTLS: tt.isDTLS}
			if side == "server" {
				d.Conn = &connCtx.Server.Connection
			}
			if tt.preset {
				if tt.isDTLS {
					d.DTLSConfig = &dtls.Config{} //nolint:staticcheck // The frozen hook contract supports mutable addon overrides.
				} else {
					d.Config = &tls.Config{}
				}
			}
			tlsBefore, dtlsBefore := d.Config, d.DTLSConfig
			err := m.Do(t.Context(), func(ctx context.Context) error { return start(tc, ctx, d) })
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("start %s DTLS error = %v, want %q", side, err, tt.wantErr)
				}
				if d.Config != nil || d.DTLSConfig != nil {
					t.Fatal("rejected configuration was published")
				}
				return
			}
			if err != nil {
				t.Fatalf("start %s transport: %v", side, err)
			}
			if diff := gocmp.Diff(tt.isDTLS, d.DTLSConfig != nil); diff != "" {
				t.Fatalf("DTLS configuration present (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(!tt.isDTLS, d.Config != nil); diff != "" {
				t.Fatalf("TLS configuration present (-want +got):\n%s", diff)
			}
			if tt.preset && (d.Config != tlsBefore || d.DTLSConfig != dtlsBefore) {
				t.Fatal("existing addon configuration was replaced")
			}
			if !tt.isDTLS && tt.minVersion == "TLS1_3" {
				if diff := gocmp.Diff(uint16(tls.VersionTLS13), d.Config.MinVersion); diff != "" {
					t.Errorf("TLS minimum version (-want +got):\n%s", diff)
				}
			}
		})
	}
}
