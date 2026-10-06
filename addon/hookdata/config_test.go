// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package hookdata

import (
	"crypto/tls"
	"errors"
	"testing"

	dtls "github.com/pion/dtls/v3"
)

//nolint:staticcheck // Tests exercise mutable DTLS configurations required for hook overrides.
func TestTLSValidateConfig(t *testing.T) {
	tests := map[string]struct {
		data *TLS
		want error
	}{
		"TLS config":             {data: &TLS{Config: &tls.Config{}}},
		"DTLS config":            {data: &TLS{IsDTLS: true, DTLSConfig: &dtls.Config{}}},
		"nil hook data":          {want: ErrTLSConfig},
		"TLS missing config":     {data: &TLS{}, want: ErrTLSConfig},
		"DTLS missing config":    {data: &TLS{IsDTLS: true}, want: ErrTLSConfig},
		"TLS with DTLS config":   {data: &TLS{DTLSConfig: &dtls.Config{}}, want: ErrTLSConfig},
		"DTLS with TLS config":   {data: &TLS{IsDTLS: true, Config: &tls.Config{}}, want: ErrTLSConfig},
		"TLS with both configs":  {data: &TLS{Config: &tls.Config{}, DTLSConfig: &dtls.Config{}}, want: ErrTLSConfig},
		"DTLS with both configs": {data: &TLS{IsDTLS: true, Config: &tls.Config{}, DTLSConfig: &dtls.Config{}}, want: ErrTLSConfig},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if err := tt.data.ValidateConfig(); !errors.Is(err, tt.want) {
				t.Fatalf("ValidateConfig() = %v, want %v", err, tt.want)
			}
		})
	}
}
