// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package updatealtsvc

import (
	json "encoding/json/v2"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestUpdateHeaderPython(t *testing.T) {
	tests := map[string]struct {
		Header string
		Port   int
	}{
		"simple":                 {`h3="example.com:443"; ma=3600, h2=":443"; ma=3600`, 1234},
		"IPv6 substring":         {`h3="[::1]:443"`, 1234},
		"Unicode host":           {`h3="例.example:443"`, 1234},
		"Unicode decimal digits": {`h3="a:٤٤٣"`, 1234},
		"long port":              {`h3="a:123456"`, 1234},
		"unrelated colon text":   {`foo=clock:123; h3="a:443"`, 1234},
		"underscored host":       {`h3="a_b:443"`, 1234},
		"negative port":          {`h3=":443"`, -1},
		"empty":                  {"", 1234},
	}
	input, err := json.Marshal(tests)
	if err != nil {
		t.Fatal(err)
	}
	out := difftest.Python(t, `import json, sys
from mitmproxy.addons.update_alt_svc import update_alt_svc_header
cases = json.load(sys.stdin)
print(json.dumps({name: update_alt_svc_header(case["Header"], case["Port"]) for name, case in cases.items()}))
`, input)
	var expected map[string]string
	if err := json.Unmarshal(out, &expected); err != nil {
		t.Fatal(err)
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := updateHeader(test.Header, test.Port)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(expected[name], got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
