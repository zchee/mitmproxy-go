// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modes

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

func TestHTTP3ReverseScheme(t *testing.T) {
	tests := map[string]struct{ want reverseScheme }{
		"HTTP3 packet transport and consumer": {want: reverseScheme{transport: modespec.UDP, setSNI: true, application: hookdata.LayerHTTP3}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(test.want, reverseSchemes["http3"], gocmp.AllowUnexported(reverseScheme{})); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
