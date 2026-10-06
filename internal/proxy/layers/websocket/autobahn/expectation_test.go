// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	json "encoding/json/v2"
	"fmt"
	"slices"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestExpectationEncoding(t *testing.T) {
	catalogue, err := loadJSON[manifest]("cases.json")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		value     string
		want      []string
		wantError bool
	}{
		"string":                  {`"OK"`, []string{"OK"}, false},
		"one-element array":       {`["OK"]`, []string{"OK"}, false},
		"two allowed outcomes":    {`["OK","NON-STRICT"]`, []string{"OK", "NON-STRICT"}, false},
		"reverse outcome order":   {`["NON-STRICT","OK"]`, []string{"NON-STRICT", "OK"}, false},
		"failed string":           {`"FAILED"`, nil, true},
		"failed array member":     {`["OK","FAILED"]`, nil, true},
		"unclean array member":    {`["OK","UNCLEAN"]`, nil, true},
		"unknown array member":    {`["OK","UNKNOWN"]`, nil, true},
		"empty string":            {`""`, nil, true},
		"empty array":             {`[]`, nil, true},
		"null":                    {`null`, nil, true},
		"duplicate array member":  {`["OK","OK"]`, nil, true},
		"non-string array member": {`["OK",1]`, nil, true},
		"null array member":       {`["OK",null]`, nil, true},
		"nested array":            {`[["OK"]]`, nil, true},
		"number":                  {`1`, nil, true},
		"boolean":                 {`true`, nil, true},
		"object":                  {`{"status":"OK"}`, nil, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var expected expectedCase
			err := json.Unmarshal(fmt.Appendf(nil, `{"id":"1.1.1","expected":%s}`, tt.value), &expected)
			if err == nil {
				m := manifest{Image: catalogue.Image, Cases: slices.Clone(catalogue.Cases)}
				m.Cases[0] = expected
				err = validateManifest(m)
			}
			if (err != nil) != tt.wantError {
				t.Fatalf("expectation=%s error=%v, want error=%v", tt.value, err, tt.wantError)
			}
			if err != nil {
				return
			}
			data, err := json.Marshal(expected.Expected)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("normalized expectation=%s: %v", data, err)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
