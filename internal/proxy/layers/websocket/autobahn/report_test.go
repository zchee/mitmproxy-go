// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	json "encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestValidateReport(t *testing.T) {
	catalogue, err := loadJSON[manifest]("cases.json")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		mutate    func(*manifest, map[string]map[string]caseResult)
		wantError bool
	}{
		"complete": {func(*manifest, map[string]map[string]caseResult) {}, false},
		"missing":  {func(m *manifest, r map[string]map[string]caseResult) { delete(r[suiteAgent], m.Cases[0].ID) }, true},
		"unexpected ID with same count": {func(m *manifest, r map[string]map[string]caseResult) {
			delete(r[suiteAgent], m.Cases[0].ID)
			r[suiteAgent]["unexpected"] = caseResult{"OK", "OK"}
		}, true},
		"extra agent": {func(_ *manifest, r map[string]map[string]caseResult) { r["another agent"] = map[string]caseResult{} }, true},
		"failure": {func(m *manifest, r map[string]map[string]caseResult) {
			r[suiteAgent][m.Cases[0].ID] = caseResult{"FAILED", "OK"}
		}, true},
		"unclean close": {func(m *manifest, r map[string]map[string]caseResult) {
			r[suiteAgent][m.Cases[0].ID] = caseResult{"OK", "UNCLEAN"}
		}, true},
		"accepted but wrong status": {func(m *manifest, r map[string]map[string]caseResult) {
			r[suiteAgent][m.Cases[0].ID] = caseResult{"NON-STRICT", "OK"}
		}, true},
		"forbidden expectation": {func(m *manifest, _ map[string]map[string]caseResult) { m.Cases[0].Expected = "FAILED" }, true},
		"duplicate expectation": {func(m *manifest, _ map[string]map[string]caseResult) { m.Cases[1] = m.Cases[0] }, true},
		"wrong image":           {func(m *manifest, _ map[string]map[string]caseResult) { m.Image = "unpinned" }, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := manifest{Image: catalogue.Image, Cases: slices.Clone(catalogue.Cases)}
			report := map[string]map[string]caseResult{suiteAgent: {}}
			for _, c := range m.Cases {
				report[suiteAgent][c.ID] = caseResult{c.Expected, "OK"}
			}
			tt.mutate(&m, report)
			got, err := validateReport(m, report)
			if (err != nil) != tt.wantError {
				t.Fatalf("validate=%+v error=%v, want error=%v", got, err, tt.wantError)
			}
			if err == nil {
				want := summary{Image: suiteImage, Total: suiteCases, Verified: suiteCases, Report: "clients/index.json"}
				if diff := gocmp.Diff(want, got); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

func TestProxyProtocolFaultExpectations(t *testing.T) {
	catalogue, err := loadJSON[manifest]("cases.json")
	if err != nil {
		t.Fatal(err)
	}
	const reason = "proxy fails the offending hop immediately; the origin echo of the preceding valid message may still be in flight"
	tests := map[string]struct{ Reason string }{
		"3.2":   {reason},
		"3.3":   {reason},
		"4.1.3": {reason},
		"4.1.4": {reason},
		"4.2.3": {reason},
		"4.2.4": {reason},
		"5.15":  {reason},
	}
	got := make(map[string]struct{ Reason string })
	counts := make(map[string]int)
	for _, expected := range catalogue.Cases {
		counts[expected.Expected]++
		if expected.Expected == "NON-STRICT" {
			got[expected.ID] = struct{ Reason string }{expected.Reason}
		} else if expected.Reason != "" {
			t.Fatalf("unexpected proxy override reason for %s", expected.ID)
		}
	}
	if diff := gocmp.Diff(tests, got); diff != "" {
		t.Fatal(diff)
	}
	if diff := gocmp.Diff(map[string]int{"OK": 471, "NON-STRICT": 7, "INFORMATIONAL": 3, "UNIMPLEMENTED": 36}, counts); diff != "" {
		t.Fatal(diff)
	}
}

func TestJSONFiles(t *testing.T) {
	tests := map[string]struct {
		data      []byte
		wantError bool
	}{
		"valid":            {[]byte(`{"image":"pinned"}`), false},
		"duplicate member": {[]byte(`{"image":"one","image":"two"}`), true},
		"oversized":        {make([]byte, (4<<20)+1), true},
		"malformed":        {[]byte(`{`), true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(path, tt.data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadJSON[manifest](path)
			if (err != nil) != tt.wantError {
				t.Fatalf("read error=%v, want error=%v", err, tt.wantError)
			}
		})
	}
}

func TestWriteJSONDoesNotReplaceEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.json")
	want := summary{Image: suiteImage, Total: suiteCases, Verified: suiteCases}
	if err := writeJSON(path, want); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(path, summary{Failed: 1}); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing evidence replaced: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got summary
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}
}
