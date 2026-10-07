// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import "testing"

func TestHeaderValidation(t *testing.T) {
	tests := map[string]struct {
		fields   []HeaderField
		trailers bool
		valid    bool
	}{
		"ordered duplicate fields":  {fields: []HeaderField{{Name: ":status", Value: "200"}, {Name: "x-value", Value: "one"}, {Name: "x-value", Value: "two"}}, valid: true},
		"uppercase field":           {fields: []HeaderField{{Name: "X-Value", Value: "one"}}},
		"late pseudo-header":        {fields: []HeaderField{{Name: "x-value", Value: "one"}, {Name: ":status", Value: "200"}}},
		"duplicate pseudo-header":   {fields: []HeaderField{{Name: ":status", Value: "200"}, {Name: ":status", Value: "200"}}},
		"unknown pseudo-header":     {fields: []HeaderField{{Name: ":unknown", Value: "value"}}},
		"connection-specific field": {fields: []HeaderField{{Name: "connection", Value: "close"}}},
		"transfer encoding":         {fields: []HeaderField{{Name: "transfer-encoding", Value: "chunked"}}},
		"te trailers":               {fields: []HeaderField{{Name: "te", Value: "trailers"}}, valid: true},
		"te gzip":                   {fields: []HeaderField{{Name: "te", Value: "gzip"}}},
		"trailer pseudo-header":     {fields: []HeaderField{{Name: ":status", Value: "200"}}, trailers: true},
		"ordered trailers":          {fields: []HeaderField{{Name: "x-value", Value: "one"}, {Name: "x-value", Value: "two"}}, trailers: true, valid: true},
		"newline value":             {fields: []HeaderField{{Name: "x-value", Value: "one\ntwo"}}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateFields(test.fields, test.trailers)
			if (err == nil) != test.valid {
				t.Fatalf("validateFields(%+v, trailers=%v) = %v; valid=%v", test.fields, test.trailers, err, test.valid)
			}
		})
	}
}

func TestHeaderContentLength(t *testing.T) {
	tests := map[string]struct {
		values []string
		want   int64
		valid  bool
	}{
		"absent":                 {want: -1, valid: true},
		"zero":                   {values: []string{"0"}, valid: true},
		"positive":               {values: []string{"10"}, want: 10, valid: true},
		"identical duplicates":   {values: []string{"10", "10"}, want: 10, valid: true},
		"conflicting duplicates": {values: []string{"10", "11"}},
		"negative":               {values: []string{"-1"}},
		"leading plus":           {values: []string{"+1"}},
		"empty":                  {values: []string{""}},
		"overflow":               {values: []string{"9223372036854775808"}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var fields []HeaderField
			for _, value := range test.values {
				fields = append(fields, HeaderField{Name: "content-length", Value: value})
			}
			got, err := headerLength(fields)
			if (err == nil) != test.valid || test.valid && got != test.want {
				t.Fatalf("headerLength(%+v) = %d, %v; want %d, valid=%v", fields, got, err, test.want, test.valid)
			}
		})
	}
}
