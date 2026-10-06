// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package stickycookie

import (
	json "encoding/json/v2"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestDomainMatchPython(t *testing.T) {
	tests := map[string]struct{ host, domain string }{"subdomain": {"www.google.com", ".google.com"}, "apex": {"google.com", ".google.com"}, "bare parent": {"www.google.com", "google.com"}, "trimmed dots": {"google.com", "...google.com..."}, "digit suffix": {"foo.123", ".123"}, "Unicode digits": {"foo.١٢٣", ".١٢٣"}, "IP": {"127.0.0.1", ".0.0.1"}, "interior substring": {"www.google.com.example", ".google.com"}, "lowercase expansion": {"İ.example", "i̇.example"}, "empty": {"", ""}, "newline numeric suffix": {"foo.123\n", ".123\n"}, "Greek lowercase context": {"ΟΣ.example", "ος.example"}}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			input, err := json.Marshal([]string{test.host, test.domain})
			if err != nil {
				t.Fatal(err)
			}
			out := difftest.Python(t, `import json, sys
from mitmproxy.addons.stickycookie import domain_match
print(json.dumps(domain_match(*json.load(sys.stdin))))
`, input)
			var want bool
			if err := json.Unmarshal(out, &want); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(want, domainMatch(test.host, test.domain)); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
