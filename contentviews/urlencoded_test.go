// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestURLEncoded includes the cases from test__view_urlencoded.py.
func TestURLEncoded(t *testing.T) {
	tests := map[string]struct {
		data string
		want string
	}{
		"test_view_urlencoded pairs":   {"one=two&three=four", "one: two\nthree: four\n"},
		"test_view_urlencoded blank":   {"adsfa=", "adsfa: ''\n"},
		"test_view_urlencoded bytes":   {"\xff\x00", "\\xff\\x00: ''\n"},
		"empty":                        {"", ""},
		"separators only":              {"&&", ""},
		"missing equals and semicolon": {"&;=&foo&", ";: ''\nfoo: ''\n"},
		"plus":                         {"a+b=c+d", "a b: c d\n"},
		"invalid escapes":              {"a=%zz&b=%&c=%2", "a: '%zz'\nb: '%'\nc: '%2'\n"},
		"escaped bytes":                {"a=%ff&b=%e6%97%a5", "a: \\xff\nb: \\xe6\\x97\\xa5\n"},
		"duplicates":                   {"a=one&a=two", "a:\n- one\n- two\n"},
		"initial empty replaced":       {"a=&a=two&a=three", "a:\n- two\n- three\n"},
		"later empty retained":         {"a=one&a=&a=three", "a:\n- one\n- ''\n- three\n"},
		"empty duplicates":             {"a=&a=", "a: ''\n"},
		"empty key":                    {"=v&=w", "'':\n- v\n- w\n"},
		"order":                        {"b=1&a=yes&b=true", "b:\n- '1'\n- 'true'\na: yes\n"},
		"quote":                        {"a='", "a: \"'\"\n"},
		"implicit YAML values":         {"a=1e999&b=2026-99-99&c=%3D", "a: '1e999'\nb: '2026-99-99'\nc: '='\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := (URLEncoded{}).Prettify([]byte(tt.data), Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestURLEncodedRenderPriority(t *testing.T) {
	tests := map[string]struct {
		data        string
		contentType string
		want        float64
	}{
		"matching": {"data", "application/x-www-form-urlencoded", 1},
		"other":    {"data", "text/plain", 0},
		"empty":    {"", "application/x-www-form-urlencoded", 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := (URLEncoded{}).RenderPriority([]byte(tt.data), Metadata{ContentType: tt.contentType})
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
