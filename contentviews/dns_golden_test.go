// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"encoding/hex"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	yaml "go.yaml.in/yaml/v4"
)

func TestDNSHTTPSGolden(t *testing.T) {
	// test__view_dns.py::test_simple uses the same bytes. Pinned go-yaml leaves
	// the ECH scalar on one line; ruamel folds before the final long word at
	// 80 columns, preserving a trailing space. Both documents parse identically.
	data, err := hex.DecodeString("00008180000100010000000107746c732d656368036465760000410001c00c004100010000003c00520001000005004b0049fe0d00452b00200020015881d41a3e2ef8f2208185dc479245d20624ddd0918a8056f2e26af47e26280008000100010001000340127075626c69632e746c732d6563682e646576000000002904d0000000000000")
	if err != nil {
		t.Fatal(err)
	}
	want := `id: 0
query: false
op_code: QUERY
authoritative_answer: false
truncation: false
recursion_desired: true
recursion_available: true
response_code: NOERROR
questions:
- name: tls-ech.dev
  type: HTTPS
  class: IN
answers:
- name: tls-ech.dev
  type: HTTPS
  class: IN
  ttl: 60
  data:
    target_name: ''
    priority: 1
    ech: \x00I\xfe\r\x00E+\x00 \x00 \x01X\x81\xd4\x1a>.\xf8\xf2 \x81\x85\xdcG\x92E\xd2\x06$\xdd\xd0\x91\x8a\x80V\xf2\xe2j\xf4~&(\x00\x08\x00\x01\x00\x01\x00\x01\x00\x03@\x12public.tls-ech.dev\x00\x00
authorities: []
additionals:
- name: ''
  type: OPT
  class: CLASS(1232)
  ttl: 0
  data: 0x
size: 82
`
	got, err := (DNS{}).Prettify(data, Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Fatalf("pinned Go YAML golden (-want +got):\n%s", diff)
	}
	ruamel := strings.Replace(want, `\xf2 \x81\x85`, `\xf2 `+"\n      "+`\x81\x85`, 1)
	var goValue, upstreamValue any
	if err := yaml.Load([]byte(got), &goValue); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Load([]byte(ruamel), &upstreamValue); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(upstreamValue, goValue); diff != "" {
		t.Fatalf("whitespace changed parsed DNS value:\n%s", diff)
	}
}
