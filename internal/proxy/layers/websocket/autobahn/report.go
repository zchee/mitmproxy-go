// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Command autobahn runs a real echo origin and validates the frozen testsuite catalogue.
package main

import (
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	ID       string `json:"id"`
	Expected string `json:"expected"`
	Reason   string `json:"reason,omitzero"`
}

type caseResult struct {
	Behavior      string `json:"behavior"`
	BehaviorClose string `json:"behaviorClose"`
}

type summary struct {
	Image    string `json:"image"`
	Total    int    `json:"total"`
	Verified int    `json:"verified"`
	Failed   int    `json:"failed"`
	Report   string `json:"report"`
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
		if expected.ID == "" || seen[expected.ID] || !acceptable(expected.Expected) {
			return fmt.Errorf("invalid or duplicate expectation %+v", expected)
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
		if !present || result.Behavior != expected.Expected || !acceptable(result.BehaviorClose) {
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

func verifyFiles(manifestPath, reportDir string) (summary, error) {
	m, err := loadJSON[manifest](manifestPath)
	if err != nil {
		return summary{}, fmt.Errorf("manifest: %w", err)
	}
	report, err := loadJSON[map[string]map[string]caseResult](filepath.Join(reportDir, "clients", "index.json"))
	if err != nil {
		return summary{}, fmt.Errorf("report: %w", err)
	}
	return validateReport(m, report)
}
