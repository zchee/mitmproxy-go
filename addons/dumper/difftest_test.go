// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package dumper

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/eventsequence"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/options"
)

// expectedOracleFailures lists the fixture and detail pairs where the
// pinned Python dumper itself crashes, keyed to the exception it raises.
// The syntax-highlight step of its raw-view fallback cannot encode a
// surrogate that the corrupted body produces, so these pairs have no
// oracle text to compare against; the Go rendering is only checked by the
// unit tests.
var expectedOracleFailures = map[string]string{
	"corrupted_gzip_body.mitm/3": "UnicodeEncodeError",
	"corrupted_gzip_body.mitm/4": "UnicodeEncodeError",
}

// oracleEntry is one fixture and detail rendering of the pinned dumper.
type oracleEntry struct {
	Text  *string  `json:"text"`
	Error *string  `json:"error"`
	Views []string `json:"views"`
}

// unportedViews returns the view names the oracle used that the Go
// registry does not serve yet, compared case-insensitively.
func unportedViews(views []string) []string {
	available := make(map[string]bool)
	for _, name := range contentviews.DefaultRegistry.AvailableViews() {
		available[name] = true
	}
	var missing []string
	for _, name := range views {
		if !available[strings.ToLower(name)] {
			missing = append(missing, name)
		}
	}
	return missing
}

// renderGo replays every flow of the file through the Go dumper at the
// given detail level, dispatching the same hook sequence upstream's
// eventsequence produces, and returns the output.
func renderGo(t *testing.T, path string, detail int) string {
	t.Helper()
	opts := options.New()
	var out bytes.Buffer
	d := New(opts, &out)
	m := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(m.Close)
	if err := m.Add(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	err := m.Do(t.Context(), func(ctx context.Context) error {
		return m.Options().Update(ctx, map[string]any{"flow_detail": detail})
	})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	for f, err := range flowio.NewReader(file).All() {
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for hook := range eventsequence.Iterate(f) {
			if err := m.Hook(t.Context(), hook); err != nil {
				t.Fatalf("%s hook: %v", hook.Name(), err)
			}
		}
	}
	return out.String()
}

// TestDifferentialPinnedDumper renders every recorded flow fixture at
// every detail level through the Go dumper and through the pinned Python
// dumper, and requires byte-identical text. Pairs whose automatic content
// views are not ported yet are skipped by view name; pairs where the
// pinned dumper itself crashes are asserted to fail with the recorded
// exception.
func TestDifferentialPinnedDumper(t *testing.T) {
	flowsDir := testutil.FixturePath(t, "mitmproxy/flows")
	raw := difftest.Script(t, filepath.Join("testdata", "dumper_oracle.py"), flowsDir)
	var oracle map[string]oracleEntry
	if err := json.Unmarshal(raw, &oracle); err != nil {
		t.Fatalf("decode oracle output: %v", err)
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
				entry, ok := oracle[key]
				if !ok {
					t.Fatalf("the oracle rendered no entry for %s", key)
				}
				if want, expected := expectedOracleFailures[key]; expected {
					if entry.Error == nil || !strings.HasPrefix(*entry.Error, want) {
						t.Fatalf("pinned dumper error = %v, want a %s", entry.Error, want)
					}
					return
				}
				if entry.Error != nil {
					t.Fatalf("pinned dumper failed: %s", *entry.Error)
				}
				if detail >= 3 {
					if missing := unportedViews(entry.Views); len(missing) > 0 {
						t.Skipf("content views not ported yet: %s", strings.Join(missing, ", "))
					}
				}
				got := renderGo(t, path, detail)
				if diff := gocmp.Diff(*entry.Text, got); diff != "" {
					t.Fatalf("output differs from the pinned dumper (-python +go):\n%s", diff)
				}
			})
		}
	}
}
