// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	json "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
		"forbidden expectation": {func(m *manifest, _ map[string]map[string]caseResult) { m.Cases[0].Expected = allowedStatuses{"FAILED"} }, true},
		"array first outcome": {func(m *manifest, r map[string]map[string]caseResult) {
			m.Cases[0].Expected = allowedStatuses{"OK", "NON-STRICT"}
			r[suiteAgent][m.Cases[0].ID] = caseResult{"OK", "OK"}
		}, false},
		"array second outcome": {func(m *manifest, r map[string]map[string]caseResult) {
			m.Cases[0].Expected = allowedStatuses{"OK", "NON-STRICT"}
			r[suiteAgent][m.Cases[0].ID] = caseResult{"NON-STRICT", "OK"}
		}, false},
		"array absent outcome": {func(m *manifest, r map[string]map[string]caseResult) {
			m.Cases[0].Expected = allowedStatuses{"OK", "NON-STRICT"}
			r[suiteAgent][m.Cases[0].ID] = caseResult{"INFORMATIONAL", "OK"}
		}, true},
		"array failed outcome": {func(m *manifest, r map[string]map[string]caseResult) {
			m.Cases[0].Expected = allowedStatuses{"OK", "NON-STRICT"}
			r[suiteAgent][m.Cases[0].ID] = caseResult{"FAILED", "OK"}
		}, true},
		"array unclean close": {func(m *manifest, r map[string]map[string]caseResult) {
			m.Cases[0].Expected = allowedStatuses{"OK", "NON-STRICT"}
			r[suiteAgent][m.Cases[0].ID] = caseResult{"NON-STRICT", "UNCLEAN"}
		}, true},
		"duplicate expectation": {func(m *manifest, _ map[string]map[string]caseResult) { m.Cases[1] = m.Cases[0] }, true},
		"wrong image":           {func(m *manifest, _ map[string]map[string]caseResult) { m.Image = "unpinned" }, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := manifest{Image: catalogue.Image, Cases: slices.Clone(catalogue.Cases)}
			report := map[string]map[string]caseResult{suiteAgent: {}}
			for _, c := range m.Cases {
				report[suiteAgent][c.ID] = caseResult{c.Expected[0], "OK"}
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

func TestVerifyShardedReports(t *testing.T) {
	catalogue, err := loadJSON[manifest]("cases.json")
	if err != nil {
		t.Fatal(err)
	}
	replaceJSON := func(t *testing.T, path string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tests := map[string]struct {
		mutation  string
		wantError string
	}{
		"complete":             {},
		"missing shard":        {"missing shard", "517 cases"},
		"repeated shard":       {"repeated shard", "duplicate case"},
		"overlapping reports":  {"overlap", "duplicate case"},
		"missing case":         {"missing case", "configured cases"},
		"unexpected case":      {"unexpected case", "present=false"},
		"failed case":          {"failed case", "FAILED"},
		"extra agent":          {"extra agent", "exactly agent"},
		"wrong image":          {"wrong image", "configuration"},
		"running container":    {"running", "container state"},
		"oom container":        {"oom", "container state"},
		"nonzero exit":         {"nonzero", "container state"},
		"absent exit evidence": {"absent exit", "container state"},
		"unbounded memory":     {"unbounded", "memory limit"},
		"swap enabled":         {"swap enabled", "memory limit"},
		"zero peak":            {"zero peak", "memory peak"},
		"negative duration":    {"negative duration", "duration"},
		"duplicate JSON case":  {"duplicate JSON", "duplicate"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dirs := []string{filepath.Join(root, "shards", "first"), filepath.Join(root, "shards", "second")}
			const memoryLimit = uint64(8 << 30)
			for i, dir := range dirs {
				if err := os.MkdirAll(filepath.Join(dir, "clients"), 0o700); err != nil {
					t.Fatal(err)
				}
				config := suiteConfig{Image: suiteImage, Servers: []suiteServer{{Agent: suiteAgent}}}
				report := map[string]map[string]caseResult{suiteAgent: {}}
				for j, c := range catalogue.Cases {
					if (j < suiteCases/2) != (i == 0) {
						continue
					}
					config.Cases = append(config.Cases, c.ID)
					report[suiteAgent][c.ID] = caseResult{c.Expected[0], "OK"}
				}
				evidence := map[string]any{
					"state":                   map[string]any{"Status": "exited", "OOMKilled": false, "ExitCode": 0},
					"memory_limit_bytes":      memoryLimit,
					"memory_swap_limit_bytes": memoryLimit,
				}
				files := map[string]any{
					"fuzzingclient.json":     config,
					"clients/index.json":     report,
					"container-state.json":   evidence,
					"cgroup-memory.peak.txt": uint64((i + 1) << 20),
					"duration-seconds.txt":   int64(i + 1),
				}
				for path, value := range files {
					if err := writeJSON(filepath.Join(dir, path), value); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := writeJSON(filepath.Join(root, "duration-seconds.txt"), int64(3)); err != nil {
				t.Fatal(err)
			}
			indexPath := filepath.Join(dirs[0], "clients", "index.json")
			index, err := loadJSON[map[string]map[string]caseResult](indexPath)
			if err != nil {
				t.Fatal(err)
			}
			firstID := catalogue.Cases[0].ID
			switch tt.mutation {
			case "missing shard":
				dirs = dirs[:1]
			case "repeated shard":
				dirs = append(dirs, dirs[0])
			case "overlap":
				otherPath := filepath.Join(dirs[1], "clients", "index.json")
				other, err := loadJSON[map[string]map[string]caseResult](otherPath)
				if err != nil {
					t.Fatal(err)
				}
				other[suiteAgent][firstID] = index[suiteAgent][firstID]
				replaceJSON(t, otherPath, other)
			case "missing case":
				delete(index[suiteAgent], firstID)
				replaceJSON(t, indexPath, index)
			case "unexpected case":
				index[suiteAgent]["unexpected"] = index[suiteAgent][firstID]
				delete(index[suiteAgent], firstID)
				replaceJSON(t, indexPath, index)
				configPath := filepath.Join(dirs[0], "fuzzingclient.json")
				config, err := loadJSON[suiteConfig](configPath)
				if err != nil {
					t.Fatal(err)
				}
				config.Cases[0] = "unexpected"
				replaceJSON(t, configPath, config)
			case "failed case":
				index[suiteAgent][firstID] = caseResult{"FAILED", "OK"}
				replaceJSON(t, indexPath, index)
			case "extra agent":
				index["unexpected"] = map[string]caseResult{}
				replaceJSON(t, indexPath, index)
			case "wrong image":
				configPath := filepath.Join(dirs[0], "fuzzingclient.json")
				config, err := loadJSON[suiteConfig](configPath)
				if err != nil {
					t.Fatal(err)
				}
				config.Image = "unreviewed"
				replaceJSON(t, configPath, config)
			case "running", "oom", "nonzero", "absent exit", "unbounded", "swap enabled":
				path := filepath.Join(dirs[0], "container-state.json")
				state := map[string]any{"Status": "exited", "OOMKilled": false, "ExitCode": 0}
				limit, swap := memoryLimit, memoryLimit
				switch tt.mutation {
				case "running":
					state["Status"] = "running"
				case "oom":
					state["OOMKilled"] = true
				case "nonzero":
					state["ExitCode"] = 137
				case "absent exit":
					delete(state, "ExitCode")
				case "unbounded":
					limit, swap = 0, 0
				case "swap enabled":
					swap *= 2
				}
				replaceJSON(t, path, map[string]any{"state": state, "memory_limit_bytes": limit, "memory_swap_limit_bytes": swap})
			case "zero peak":
				replaceJSON(t, filepath.Join(dirs[0], "cgroup-memory.peak.txt"), uint64(0))
			case "negative duration":
				replaceJSON(t, filepath.Join(dirs[0], "duration-seconds.txt"), int64(-1))
			case "duplicate JSON":
				data := fmt.Sprintf(`{"%s":{"%s":{},"%s":{}}}`, suiteAgent, firstID, firstID)
				if err := os.WriteFile(indexPath, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := verifyFiles("cases.json", root, dirs...)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("verify error=%v, want %q", err, tt.wantError)
				}
				if _, err := os.Stat(filepath.Join(root, "clients", "index.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("invalid run published a merged index: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := summary{Image: suiteImage, Total: suiteCases, Verified: suiteCases, Report: "clients/index.json", DurationSeconds: 3}
			for i, dir := range dirs {
				count := suiteCases / 2
				if i == 1 {
					count = suiteCases - count
				}
				want.Shards = append(want.Shards, shardSummary{Name: filepath.Base(dir), Cases: count, Verified: count, PeakBytes: uint64((i + 1) << 20), DurationSeconds: int64(i + 1), MemoryLimitBytes: memoryLimit, Status: "exited", Report: "shards/" + filepath.Base(dir) + "/clients/index.json"})
			}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Fatal(diff)
			}
			merged, err := loadJSON[map[string]map[string]caseResult](filepath.Join(root, "clients", "index.json"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validateReport(catalogue, merged); err != nil {
				t.Fatalf("merged index: %v", err)
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
		"3.4":   {reason},
		"4.1.3": {reason},
		"4.1.4": {reason},
		"4.1.5": {reason},
		"4.2.3": {reason},
		"4.2.4": {reason},
		"4.2.5": {reason},
		"5.15":  {reason},
	}
	got := make(map[string]struct{ Reason string })
	counts := make(map[string]int)
	for _, expected := range catalogue.Cases {
		if len(expected.Expected) > 1 {
			if diff := gocmp.Diff(allowedStatuses{"OK", "NON-STRICT"}, expected.Expected); diff != "" {
				t.Fatalf("proxy expectation %s: %s", expected.ID, diff)
			}
			counts["OK or NON-STRICT"]++
			got[expected.ID] = struct{ Reason string }{expected.Reason}
		} else {
			counts[expected.Expected[0]]++
			if expected.Reason != "" {
				t.Fatalf("unexpected proxy override reason for %s", expected.ID)
			}
		}
	}
	if diff := gocmp.Diff(tests, got); diff != "" {
		t.Fatal(diff)
	}
	if diff := gocmp.Diff(map[string]int{"OK": 468, "OK or NON-STRICT": 10, "INFORMATIONAL": 3, "UNIMPLEMENTED": 36}, counts); diff != "" {
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
