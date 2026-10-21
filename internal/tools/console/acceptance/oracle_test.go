// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package acceptance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	json "encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

type oracleFrame struct {
	Frame           string `json:"frame"`
	Width           int    `json:"width"`
	Height          int    `json:"height"`
	UpstreamCommit  string `json:"upstream_commit"`
	ReferenceSHA256 string `json:"reference_sha256"`
	AdapterSHA256   string `json:"adapter_sha256"`
	Python          string `json:"python"`
	Urwid           string `json:"urwid"`
	Mitmproxy       string `json:"mitmproxy"`
	FlowCount       int    `json:"flow_count"`
}

func TestConsoleOracle(t *testing.T) {
	t.Run("oracle", func(t *testing.T) {
		tests := map[string]struct{}{"flowlist": {}, "flowview": {}, "commander": {}}
		for state := range tests {
			t.Run(state, func(t *testing.T) {
				t.Run("80x24", func(t *testing.T) {
					uv, err := exec.LookPath("uv")
					requireNoError(t, err)
					inputs := loadFrameInputs(t)
					root := os.Getenv("MITMPROXY_TEST_CONSOLE_ARTIFACTS")
					if root == "" {
						root = t.TempDir()
					}
					requireNoError(t, os.MkdirAll(root, 0o700))
					out, err := os.MkdirTemp(root, "oracle-"+state+"-")
					requireNoError(t, err)
					adapter, err := filepath.Abs("testdata/oracle.py")
					requireNoError(t, err)
					flows, err := filepath.Abs("testdata/console.mitm")
					requireNoError(t, err)
					reference, err := filepath.Abs("../../../../testdata/mitmproxy/tools/console/conftest.py")
					requireNoError(t, err)
					args := []string{
						"run", "--quiet", "--no-project", "--python", difftest.PythonVersion, "--with", difftest.Requirement, "--script", adapter,
						"--flows", flows, "--reference", reference, "--work-dir", out, "--keys", inputs.States[state],
					}
					for _, value := range inputs.Options {
						args = append(args, "--set", value)
					}
					ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, uv, args...) //nolint:gosec // Only test-owned paths, fixed options and the pinned requirement are passed.
					cmd.Env = append(os.Environ(), "TZ=UTC", "PYTHONDONTWRITEBYTECODE=1")
					var stderr bytes.Buffer
					cmd.Stderr = &stderr
					data, runErr := cmd.Output()
					requireNoError(t, os.WriteFile(filepath.Join(out, "python.stdout.json"), data, 0o600))
					requireNoError(t, os.WriteFile(filepath.Join(out, "python.stderr"), stderr.Bytes(), 0o600))
					requireNoError(t, os.WriteFile(filepath.Join(out, "command.txt"), []byte(cmd.String()+"\n"), 0o600))
					if runErr != nil {
						t.Fatalf("pinned Python oracle failed: %v\nstderr:\n%s\nartifacts: %s", runErr, stderr.Bytes(), out)
					}
					var expected oracleFrame
					requireNoError(t, json.Unmarshal(data, &expected, json.RejectUnknownMembers(true)))
					adapterBytes, err := os.ReadFile(adapter)
					requireNoError(t, err)
					referenceBytes, err := os.ReadFile(reference)
					requireNoError(t, err)
					if expected.UpstreamCommit != difftest.PinnedCommit || expected.AdapterSHA256 != fmt.Sprintf("%x", sha256.Sum256(adapterBytes)) || expected.ReferenceSHA256 != fmt.Sprintf("%x", sha256.Sum256(referenceBytes)) || !strings.HasPrefix(expected.Python, difftest.PythonVersion+".") || expected.Urwid == "" || expected.FlowCount != len(inputs.IDs) || expected.Width != 80 || expected.Height != 24 {
						t.Fatalf("oracle pin/runtime/dimension/input preflight failed: %+v; artifacts: %s", expected, out)
					}
					view, transcript := captureFrame(t, state, 80, 24)
					actual := frameCells(t, view, 80, 24)
					want := strings.ReplaceAll(expected.Frame, "\r\n", "\n")
					for name, content := range map[string][]byte{
						"python.frame.txt": []byte(want), "go.frame.txt": []byte(actual),
						"go.frame.ansi.txt": []byte(view.Content), "go.transcript.ansi": transcript,
					} {
						requireNoError(t, os.WriteFile(filepath.Join(out, name), content, 0o600))
					}
					t.Logf("live oracle %s: pin=%s Python=%s urwid=%s artifacts=%s", state, expected.UpstreamCommit, strings.Fields(expected.Python)[0], expected.Urwid, out)
					if diff := gocmp.Diff(want, actual); diff != "" {
						requireNoError(t, os.WriteFile(filepath.Join(out, "cells.diff"), []byte(diff), 0o600))
						t.Fatalf("exact decoded cells differ (-Python +Go); no content normalization permitted:\n%s\nartifacts: %s", diff, out)
					}
				})
			})
		}
	})
}
