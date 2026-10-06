// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Command autobahn runs a real echo origin and validates the frozen testsuite catalogue.
package main

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
)

const (
	suiteImage = "crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
	suiteAgent = "mitmproxy-go"
	suiteCases = 517
)

type manifest struct {
	Image string         `json:"image"`
	Cases []expectedCase `json:"cases"`
}

type expectedCase struct {
	ID       string          `json:"id"`
	Expected allowedStatuses `json:"expected"`
	Reason   string          `json:"reason,omitzero"`
}

type allowedStatuses []string

// UnmarshalJSONFrom accepts one status or an array of allowed statuses.
func (s *allowedStatuses) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if dec.PeekKind() != '"' {
		return json.UnmarshalDecode(dec, (*[]string)(s))
	}
	var status string
	if err := json.UnmarshalDecode(dec, &status); err != nil {
		return err
	}
	*s = allowedStatuses{status}
	return nil
}

type caseResult struct {
	Behavior      string `json:"behavior"`
	BehaviorClose string `json:"behaviorClose"`
}

type summary struct {
	Image           string         `json:"image"`
	Total           int            `json:"total"`
	Verified        int            `json:"verified"`
	Failed          int            `json:"failed"`
	Report          string         `json:"report"`
	DurationSeconds int64          `json:"duration_seconds,omitzero"`
	Shards          []shardSummary `json:"shards,omitzero"`
}

type shardSummary struct {
	Name             string `json:"name"`
	Cases            int    `json:"cases"`
	Verified         int    `json:"verified"`
	PeakBytes        uint64 `json:"peak_bytes"`
	DurationSeconds  int64  `json:"duration_seconds"`
	MemoryLimitBytes uint64 `json:"memory_limit_bytes"`
	Status           string `json:"status"`
	OOMKilled        bool   `json:"oom_killed"`
	ExitCode         int    `json:"exit_code"`
	Report           string `json:"report"`
}

type containerEvidence struct {
	State struct {
		Status    string `json:"Status"`
		OOMKilled *bool  `json:"OOMKilled"`
		ExitCode  *int   `json:"ExitCode"`
		Error     string `json:"Error"`
	} `json:"state"`
	MemoryLimitBytes     uint64 `json:"memory_limit_bytes"`
	MemorySwapLimitBytes uint64 `json:"memory_swap_limit_bytes"`
}

type suiteConfig struct {
	Image             string              `json:"image"`
	Outdir            string              `json:"outdir"`
	Servers           []suiteServer       `json:"servers"`
	Cases             []string            `json:"cases"`
	ExcludeCases      []string            `json:"exclude-cases"`
	ExcludeAgentCases map[string][]string `json:"exclude-agent-cases"`
}

type suiteServer struct {
	Agent string `json:"agent"`
	URL   string `json:"url"`
}

func acceptable(status string) bool {
	switch status {
	case "OK", "NON-STRICT", "INFORMATIONAL", "UNIMPLEMENTED":
		return true
	default:
		return false
	}
}

func validateManifest(m manifest) error {
	if m.Image != suiteImage || len(m.Cases) != suiteCases {
		return fmt.Errorf("manifest must pin the reviewed image and %d cases", suiteCases)
	}
	seen := make(map[string]bool, len(m.Cases))
	for _, expected := range m.Cases {
		if expected.ID == "" || seen[expected.ID] || len(expected.Expected) == 0 {
			return fmt.Errorf("invalid or duplicate expectation %+v", expected)
		}
		for i, status := range expected.Expected {
			if !acceptable(status) || slices.Contains(expected.Expected[:i], status) {
				return fmt.Errorf("invalid or duplicate status for case %s: %q", expected.ID, status)
			}
		}
		seen[expected.ID] = true
	}
	return nil
}

func validateReport(m manifest, report map[string]map[string]caseResult) (summary, error) {
	if err := validateManifest(m); err != nil {
		return summary{}, err
	}
	cases, ok := report[suiteAgent]
	if !ok || len(report) != 1 || len(cases) != len(m.Cases) {
		return summary{}, fmt.Errorf("report must contain exactly agent %q and %d cases", suiteAgent, len(m.Cases))
	}
	var mismatches []error
	for _, expected := range m.Cases {
		result, present := cases[expected.ID]
		if !present || !slices.Contains(expected.Expected, result.Behavior) || !acceptable(result.BehaviorClose) {
			mismatches = append(mismatches, fmt.Errorf("case %s: present=%v behavior=%q (want %q) close=%q", expected.ID, present, result.Behavior, expected.Expected, result.BehaviorClose))
		}
	}
	if len(mismatches) > 0 {
		return summary{}, errors.Join(mismatches...)
	}
	return summary{Image: m.Image, Total: len(m.Cases), Verified: len(m.Cases), Report: "clients/index.json"}, nil
}

func loadJSON[T any](path string) (value T, err error) {
	f, err := os.OpenInRoot(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return value, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	const maxBytes = 4 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return value, err
	}
	if len(data) > maxBytes {
		return value, fmt.Errorf("JSON file %s exceeds %d bytes", path, maxBytes)
	}
	err = json.Unmarshal(data, &value)
	return value, err
}

func writeJSON(path string, value any) (err error) {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	f, err := root.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(data, '\n'))
	return errors.Join(writeErr, f.Close())
}

func verifyFiles(manifestPath, reportDir string, shardDirs ...string) (summary, error) {
	m, err := loadJSON[manifest](manifestPath)
	if err != nil {
		return summary{}, fmt.Errorf("manifest: %w", err)
	}
	if len(shardDirs) == 0 {
		report, err := loadJSON[map[string]map[string]caseResult](filepath.Join(reportDir, "clients", "index.json"))
		if err != nil {
			return summary{}, fmt.Errorf("report: %w", err)
		}
		return validateReport(m, report)
	}
	if err := validateManifest(m); err != nil {
		return summary{}, err
	}
	merged := map[string]map[string]caseResult{suiteAgent: {}}
	shards := make([]shardSummary, 0, len(shardDirs))
	for _, dir := range shardDirs {
		indexPath := filepath.Join(dir, "clients", "index.json")
		report, err := loadJSON[map[string]map[string]caseResult](indexPath)
		if err != nil {
			return summary{}, fmt.Errorf("shard %s report: %w", dir, err)
		}
		cases, ok := report[suiteAgent]
		if !ok || len(report) != 1 {
			return summary{}, fmt.Errorf("shard %s must contain exactly agent %q", dir, suiteAgent)
		}
		for id, result := range cases {
			if _, present := merged[suiteAgent][id]; present {
				return summary{}, fmt.Errorf("duplicate case %s in shard %s", id, dir)
			}
			merged[suiteAgent][id] = result
		}
		config, err := loadJSON[suiteConfig](filepath.Join(dir, "fuzzingclient.json"))
		if err != nil {
			return summary{}, fmt.Errorf("shard %s configuration: %w", dir, err)
		}
		if config.Image != m.Image || len(config.Servers) != 1 || config.Servers[0].Agent != suiteAgent || len(config.ExcludeCases) != 0 || len(config.ExcludeAgentCases) != 0 {
			return summary{}, fmt.Errorf("shard %s configuration differs from the reviewed suite", dir)
		}
		if len(config.Cases) == 0 || len(config.Cases) != len(cases) {
			return summary{}, fmt.Errorf("shard %s report differs from configured cases", dir)
		}
		seen := make(map[string]bool, len(config.Cases))
		for _, id := range config.Cases {
			if _, present := cases[id]; !present || seen[id] {
				return summary{}, fmt.Errorf("shard %s report differs from configured cases at %s", dir, id)
			}
			seen[id] = true
		}
		evidence, err := loadJSON[containerEvidence](filepath.Join(dir, "container-state.json"))
		if err != nil {
			return summary{}, fmt.Errorf("shard %s container state: %w", dir, err)
		}
		state := evidence.State
		if state.Status != "exited" || state.OOMKilled == nil || *state.OOMKilled || state.ExitCode == nil || *state.ExitCode != 0 || state.Error != "" {
			return summary{}, fmt.Errorf("shard %s container state is not a clean zero exit", dir)
		}
		if evidence.MemoryLimitBytes == 0 || evidence.MemorySwapLimitBytes != evidence.MemoryLimitBytes {
			return summary{}, fmt.Errorf("shard %s requires a memory limit with no additional swap", dir)
		}
		peak, err := loadJSON[uint64](filepath.Join(dir, "cgroup-memory.peak.txt"))
		if err != nil || peak == 0 {
			return summary{}, fmt.Errorf("shard %s memory peak=%d error=%v", dir, peak, err)
		}
		duration, err := loadJSON[int64](filepath.Join(dir, "duration-seconds.txt"))
		if err != nil || duration < 0 {
			return summary{}, fmt.Errorf("shard %s duration=%d error=%v", dir, duration, err)
		}
		relative, err := filepath.Rel(reportDir, indexPath)
		if err != nil {
			return summary{}, err
		}
		shards = append(shards, shardSummary{Name: filepath.Base(dir), Cases: len(config.Cases), Verified: len(cases), PeakBytes: peak, DurationSeconds: duration, MemoryLimitBytes: evidence.MemoryLimitBytes, Status: state.Status, Report: filepath.ToSlash(relative)})
	}
	result, err := validateReport(m, merged)
	if err != nil {
		return summary{}, err
	}
	duration, err := loadJSON[int64](filepath.Join(reportDir, "duration-seconds.txt"))
	if err != nil || duration < 0 {
		return summary{}, fmt.Errorf("suite duration=%d error=%v", duration, err)
	}
	if err := os.Mkdir(filepath.Join(reportDir, "clients"), 0o700); err != nil {
		return summary{}, err
	}
	// Detailed wire evidence remains in each shard; this index records all outcomes.
	if err := writeJSON(filepath.Join(reportDir, "clients", "index.json"), merged); err != nil {
		return summary{}, err
	}
	result.Shards, result.DurationSeconds = shards, duration
	return result, nil
}
