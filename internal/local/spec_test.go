// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestEncodeInterceptSpec(t *testing.T) {
	// Normalization follows src/intercept_conf.rs:68-88,92-106; errors use
	// src/intercept_conf.rs:43-53, which retains the original input verbatim.
	tests := map[string]struct {
		spec     string
		ownPID   uint32
		expected []string
		wantErr  string
	}{
		"success: disabled":                                         {ownPID: 42},
		"success: whitespace disables":                              {spec: " \t\n", ownPID: 42},
		"success: PID list":                                         {spec: "1,2,3", ownPID: 42, expected: []string{"1", "2", "3", "!42"}},
		"success: process substring":                                {spec: "mitm", ownPID: 42, expected: []string{"mitm", "!42"}},
		"success: exclusion first":                                  {spec: "!1234", ownPID: 42, expected: []string{"!1234", "!42"}},
		"success: trim around exclusions":                           {spec: " curl , ! 0007 ", ownPID: 42, expected: []string{"curl", "!7", "!42"}},
		"success: positive sign and leading zeros":                  {spec: "+0001,0002", ownPID: 42, expected: []string{"1", "2", "!42"}},
		"success: uint32 boundary":                                  {spec: "4294967295,4294967296", ownPID: 0, expected: []string{"4294967295", "4294967296", "!0"}},
		"success: negative integer is process substring":            {spec: "-1", ownPID: 42, expected: []string{"-1", "!42"}},
		"success: only one exclusion prefix":                        {spec: "!!curl", ownPID: 42, expected: []string{"!!curl", "!42"}},
		"success: self exclusion overrides explicit self inclusion": {spec: "42", ownPID: 42, expected: []string{"42", "!42"}},
		"success: Unicode whitespace":                               {spec: " curl ", ownPID: 42, expected: []string{"curl", "!42"}},
		"error: empty comma patterns":                               {spec: ",,", ownPID: 42, wantErr: "invalid intercept spec: ,,"},
		"error: trailing comma":                                     {spec: "curl,", ownPID: 42, wantErr: "invalid intercept spec: curl,"},
		"error: empty exclusion":                                    {spec: "! ", ownPID: 42, wantErr: "invalid intercept spec: ! "},
		"error: original whitespace preserved":                      {spec: " curl, \t", ownPID: 42, wantErr: "invalid intercept spec:  curl, \t"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			configuration, err := EncodeInterceptSpec(test.spec, test.ownPID)
			if test.wantErr != "" {
				if err == nil || err.Error() != test.wantErr || configuration != nil {
					t.Fatalf("EncodeInterceptSpec(%q) = %v, %v; want nil, %q", test.spec, configuration, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.expected, configuration.Actions); diff != "" {
				t.Fatalf("actions (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDescribeSpec(t *testing.T) {
	// Descriptions come from src/intercept_conf.rs:143-161; invalid-spec
	// error strings come from src/intercept_conf.rs:43-53.
	tests := map[string]struct {
		spec     string
		expected string
		wantErr  string
	}{
		"success: disabled":                   {expected: "Intercept nothing."},
		"success: PID list":                   {spec: "1,2,3", expected: "Include PID 1. Include PID 2. Include PID 3."},
		"success: process substring":          {spec: "mitm", expected: "Include processes matching \"mitm\"."},
		"success: PID exclusion":              {spec: "!1234", expected: "Exclude PID 1234."},
		"success: mixed rules":                {spec: " curl , ! 0007 , ! wget", expected: "Include processes matching \"curl\". Exclude PID 7. Exclude processes matching \"wget\"."},
		"success: positive signed PID":        {spec: "+0001", expected: "Include PID 1."},
		"success: oversized PID is a process": {spec: "4294967296", expected: "Include processes matching \"4294967296\"."},
		"success: quotes are not escaped":     {spec: "\"curl\"", expected: "Include processes matching \"\"curl\"\"."},
		"error: empty comma patterns":         {spec: ",,", wantErr: "invalid intercept spec: ,,"},
		"error: empty exclusion":              {spec: "!", wantErr: "invalid intercept spec: !"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := DescribeSpec(test.spec)
			if test.wantErr != "" {
				if err == nil || err.Error() != test.wantErr || got != "" {
					t.Fatalf("DescribeSpec(%q) = %q, %v; want empty, %q", test.spec, got, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.expected, got); diff != "" {
				t.Fatalf("description (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnavailableReason(t *testing.T) {
	// Exact messages follow mitmproxy-rs/src/server/local_redirector.rs:72-83
	// in the pinned Rust checkout.
	tests := map[string]struct {
		goos     string
		euid     int
		expected string
	}{
		"success: macOS user":     {goos: "darwin", euid: 501},
		"success: Windows user":   {goos: "windows", euid: -1},
		"success: Linux root":     {goos: "linux"},
		"error: Linux user":       {goos: "linux", euid: 1000, expected: "mitmproxy is not running as root."},
		"error: FreeBSD root":     {goos: "freebsd", expected: "Local redirect mode is not supported on freebsd"},
		"error: unsupported user": {goos: "openbsd", euid: 1000, expected: "Local redirect mode is not supported on openbsd"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(test.expected, UnavailableReason(test.goos, test.euid)); diff != "" {
				t.Fatalf("availability (-want +got):\n%s", diff)
			}
		})
	}
}
