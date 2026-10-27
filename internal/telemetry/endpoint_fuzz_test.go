// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzOTLPEndpoint(f *testing.F) {
	f.Add("")
	f.Add("http://127.0.0.1:4318/base")
	f.Add("https://collector.example/base")
	f.Add("ftp://user:pass@127.0.0.1/base?query=1")
	f.Fuzz(func(t *testing.T, value string) {
		e, err := parseEndpoint(value)
		if err != nil || value == "" {
			return
		}
		if len(value) > 4096 {
			t.Fatal("parser accepted an overlong endpoint")
		}
		for _, signal := range []string{"traces", "metrics"} {
			derived, err := url.Parse(e.signalURL(signal))
			if err != nil {
				t.Fatal(err)
			}
			if derived.Scheme != e.base.Scheme || derived.Host != e.base.Host || derived.User != nil || derived.RawQuery != "" || derived.Fragment != "" || !strings.HasSuffix(derived.Path, "/v1/"+signal) {
				t.Fatal("signal derivation changed the validated endpoint boundary")
			}
		}
	})
}
