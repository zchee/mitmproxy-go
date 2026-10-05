// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/options"
)

func TestTLSVersionBounds(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		name    string
		wantMin uint16
		wantMax uint16
	}{
		"success: UNBOUNDED spans every version": {name: "UNBOUNDED", wantMin: tls.VersionTLS10, wantMax: tls.VersionTLS13},
		"success: SSL3 clamps to TLS 1.0":        {name: "SSL3", wantMin: tls.VersionTLS10, wantMax: tls.VersionTLS10},
		"success: TLS1":                          {name: "TLS1", wantMin: tls.VersionTLS10, wantMax: tls.VersionTLS10},
		"success: TLS1_1":                        {name: "TLS1_1", wantMin: tls.VersionTLS11, wantMax: tls.VersionTLS11},
		"success: TLS1_2":                        {name: "TLS1_2", wantMin: tls.VersionTLS12, wantMax: tls.VersionTLS12},
		"success: TLS1_3":                        {name: "TLS1_3", wantMin: tls.VersionTLS13, wantMax: tls.VersionTLS13},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := minTLSVersion(tt.name); got != tt.wantMin {
				t.Errorf("minTLSVersion(%s) = %#x, want %#x", tt.name, got, tt.wantMin)
			}
			if got := maxTLSVersion(tt.name); got != tt.wantMax {
				t.Errorf("maxTLSVersion(%s) = %#x, want %#x", tt.name, got, tt.wantMax)
			}
		})
	}
}

func TestCurvePreferences(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		name *string
		want []tls.CurveID
	}{
		"success: unset keeps the defaults": {},
		"success: secp256r1":                {name: new("secp256r1"), want: []tls.CurveID{tls.CurveP256}},
		"success: secp384r1":                {name: new("secp384r1"), want: []tls.CurveID{tls.CurveP384}},
		"success: secp521r1":                {name: new("secp521r1"), want: []tls.CurveID{tls.CurveP521}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if diff := gocmp.Diff(tt.want, curvePreferences(tt.name)); diff != "" {
				t.Errorf("curvePreferences mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// The ciphers_client and ciphers_server options accept only colon-separated
// exact OpenSSL suite names; everything else of OpenSSL's cipher-string
// language is rejected (docs/compat.md).
func TestParseCipherOption(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		value   string
		want    []uint16
		wantErr string
	}{
		"success: two exact names": {
			value: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384",
			want:  []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		},
		"success: TLS 1.3 name": {
			value: "TLS_AES_256_GCM_SHA384",
			want:  []uint16{tls.TLS_AES_256_GCM_SHA384},
		},
		"error: alias":            {value: "ALL", wantErr: `"ALL"`},
		"error: cipher string":    {value: "HIGH:!aNULL", wantErr: `"HIGH"`},
		"error: seclevel keyword": {value: "@SECLEVEL=0:ALL", wantErr: `"@SECLEVEL=0"`},
		"error: sort keyword":     {value: "ECDHE-RSA-AES128-GCM-SHA256:@STRENGTH", wantErr: `"@STRENGTH"`},
		"error: exclusion":        {value: "-SHA", wantErr: `"-SHA"`},
		"error: addition":         {value: "+SHA", wantErr: `"+SHA"`},
		"error: unknown name":     {value: "NOT-A-SUITE", wantErr: `"NOT-A-SUITE"`},
		"error: empty value":      {value: "", wantErr: `""`},
		"error: unsupported openssl suite": {
			// A real OpenSSL suite that crypto/tls does not implement.
			value: "DHE-RSA-AES128-GCM-SHA256", wantErr: `"DHE-RSA-AES128-GCM-SHA256"`,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := parseCipherOption("ciphers_client", tt.value)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseCipherOption(%q) accepted, want error naming %s", tt.value, tt.wantErr)
				}
				if _, ok := errors.AsType[*options.OptionsError](err); !ok {
					t.Errorf("parseCipherOption(%q) error is %T, want *options.OptionsError", tt.value, err)
				}
				if !strings.Contains(err.Error(), tt.wantErr) || !strings.Contains(err.Error(), "ciphers_client") {
					t.Errorf("parseCipherOption(%q) error %q does not name ciphers_client and the entry %s", tt.value, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("parseCipherOption mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
