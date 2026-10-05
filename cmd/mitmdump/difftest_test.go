// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package main

import (
	json "encoding/json/v2"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// expectedOracleFailures lists the fixture and detail pairs where the
// pinned Python mitmdump itself crashes: the syntax-highlight step of its
// raw-view fallback cannot encode a surrogate that the corrupted body
// produces. These pairs have no oracle text; the Go binary must still
// exit 0.
var expectedOracleFailures = map[string]string{
	"corrupted_gzip_body.mitm/3": "UnicodeEncodeError",
	"corrupted_gzip_body.mitm/4": "UnicodeEncodeError",
}

// processResult is one mitmdump run of the pinned Python.
type processResult struct {
	Returncode int    `json:"returncode"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
}

// oracle runs the pinned Python mitmdump through the oracle script.
func oracle(t *testing.T, args ...string) []byte {
	t.Helper()
	return difftest.Script(t, filepath.Join("testdata", "mitmdump_oracle.py"), args...)
}

// TestDifferentialReadDump reads every recorded flow fixture at every
// detail level through the Go binary and through the pinned Python
// mitmdump, both with piped output, and requires identical text and exit
// status 0 on both sides. The pairs where the pinned dumper itself
// crashes are asserted to fail with the recorded exception while the Go
// binary still exits 0.
func TestDifferentialReadDump(t *testing.T) {
	flowsDir := testutil.FixturePath(t, "mitmproxy/flows")
	var results map[string]processResult
	if err := json.Unmarshal(oracle(t, "render", flowsDir), &results); err != nil {
		t.Fatalf("decode oracle output: %v", err)
	}
	var rendered map[string]struct {
		Text  string `json:"text"`
		Error string `json:"error"`
	}
	bare := difftest.Script(t, filepath.Join("..", "..", "addons", "dumper", "testdata", "dumper_oracle.py"), flowsDir)
	if err := json.Unmarshal(bare, &rendered); err != nil {
		t.Fatalf("decode dumper oracle output: %v", err)
	}
	paths, err := filepath.Glob(filepath.Join(flowsDir, "*.mitm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no flow fixtures under %s", flowsDir)
	}
	slices.Sort(paths)
	for _, path := range paths {
		for detail := range 5 {
			key := fmt.Sprintf("%s/%d", filepath.Base(path), detail)
			t.Run(key, func(t *testing.T) {
				entry, ok := results[key]
				if !ok {
					t.Fatalf("the oracle ran no entry for %s", key)
				}
				goOut, goErr, goCode := goRun(t, "-n", "-r", path, "--flow-detail", strconv.Itoa(detail))
				if goCode != 0 {
					t.Fatalf("Go mitmdump exited %d, stderr %q", goCode, goErr)
				}
				if want, expected := expectedOracleFailures[key]; expected {
					if !strings.HasPrefix(rendered[key].Error, want+":") {
						t.Fatalf("bare dumper error %q, want %s", rendered[key].Error, want)
					}
					if entry.Returncode != 1 || !strings.Contains(entry.Stdout, want+":") || entry.Stderr != "Error logged during startup, exiting...\n" {
						t.Fatalf("pinned mitmdump result %+v, want a %s startup failure", entry, want)
					}
					return
				}
				if entry.Returncode != 0 {
					t.Fatalf("pinned mitmdump exited %d: %s", entry.Returncode, entry.Stderr)
				}
				if rendered[key].Error != "" || rendered[key].Text != entry.Stdout {
					t.Fatalf("binary output differs from bare dumper: error %q, diff:\n%s", rendered[key].Error, gocmp.Diff(rendered[key].Text, entry.Stdout))
				}
				if diff := gocmp.Diff(entry.Stdout, goOut); diff != "" {
					t.Fatalf("output differs from the pinned mitmdump (-python +go):\n%s", diff)
				}
			})
		}
	}
}

// TestDifferentialWriteInterop round-trips stream files in both
// directions: a file written by the Go binary reads back through the
// pinned Python with the text of the original fixture, and a file
// written by the pinned Python reads back through the Go binary the same
// way.
func TestDifferentialWriteInterop(t *testing.T) {
	for _, fixture := range []string{"successful_log.mitm", "websocket.mitm"} {
		src := testutil.FixturePath(t, "mitmproxy/flows/"+fixture)
		t.Run(fixture+"/go writes, python reads", func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "go.mitm")
			if _, stderr, code := goRun(t, "-n", "-r", src, "-w", out); code != 0 {
				t.Fatalf("Go mitmdump exited %d, stderr %q", code, stderr)
			}
			var written, original processResult
			if err := json.Unmarshal(oracle(t, "read", out), &written); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(oracle(t, "read", src), &original); err != nil {
				t.Fatal(err)
			}
			if written.Returncode != 0 {
				t.Fatalf("pinned mitmdump exited %d reading the Go file: %s", written.Returncode, written.Stderr)
			}
			if original.Returncode != 0 {
				t.Fatalf("pinned mitmdump exited %d reading the fixture: %s", original.Returncode, original.Stderr)
			}
			if diff := gocmp.Diff(original.Stdout, written.Stdout); diff != "" {
				t.Fatalf("the Go-written file reads differently (-fixture +written):\n%s", diff)
			}
		})
		t.Run(fixture+"/python writes, go reads", func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "py.mitm")
			var write processResult
			if err := json.Unmarshal(oracle(t, "write", src, out), &write); err != nil {
				t.Fatal(err)
			}
			if write.Returncode != 0 {
				t.Fatalf("pinned mitmdump exited %d writing: %s", write.Returncode, write.Stderr)
			}
			written, stderr, code := goRun(t, "-n", "-r", out)
			if code != 0 {
				t.Fatalf("Go mitmdump exited %d, stderr %q", code, stderr)
			}
			original, stderr, code := goRun(t, "-n", "-r", src)
			if code != 0 {
				t.Fatalf("Go mitmdump exited %d, stderr %q", code, stderr)
			}
			if diff := gocmp.Diff(original, written); diff != "" {
				t.Fatalf("the Python-written file reads differently (-fixture +written):\n%s", diff)
			}
		})
	}
}
