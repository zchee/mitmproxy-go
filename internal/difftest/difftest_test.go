// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package difftest_test

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

// recorder is a testing.TB whose Skip and Fatal methods record the message
// and stop the calling goroutine instead of ending the test, so that tests can
// observe how a helper skips or fails.
type recorder struct {
	testing.TB

	skipped string
	failed  string
}

func (r *recorder) Helper() {}

func (r *recorder) Skip(args ...any) {
	r.skipped = fmt.Sprint(args...)
	runtime.Goexit()
}

func (r *recorder) Skipf(format string, args ...any) {
	r.skipped = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.failed = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

// run calls f on a new goroutine and waits for it to return or to stop in
// one of the recording methods.
func (r *recorder) run(f func()) {
	var wg sync.WaitGroup
	wg.Go(f)
	wg.Wait()
}

func TestUVSkipsWithoutBuildTag(t *testing.T) {
	if difftest.Enabled {
		t.Skip("built with -tags difftest; the skip path is not reachable")
	}

	rec := &recorder{TB: t}
	rec.run(func() { difftest.UV(rec) })
	if !strings.Contains(rec.skipped, "-tags difftest") {
		t.Errorf("UV without the difftest tag: skip message = %q, want it to mention -tags difftest", rec.skipped)
	}
}

// TestPinnedCommit checks that Python really runs the pinned upstream commit:
// uv records the resolved git commit of a VCS requirement in direct_url.json.
func TestPinnedCommit(t *testing.T) {
	const script = `
import importlib.metadata, json
info = json.loads(importlib.metadata.distribution("mitmproxy").read_text("direct_url.json"))
print(info["vcs_info"]["commit_id"])
`
	got := strings.TrimSpace(string(difftest.Python(t, script, nil)))
	if diff := gocmp.Diff(difftest.PinnedCommit, got); diff != "" {
		t.Errorf("installed mitmproxy commit mismatch (-want +got):\n%s", diff)
	}
}

func TestPython(t *testing.T) {
	tests := map[string]struct {
		script  string
		stdin   string
		want    string
		wantErr string
	}{
		"success: stdin is passed to the script": {
			script: "import sys; sys.stdout.write(sys.stdin.read().upper())",
			stdin:  "flow\n",
			want:   "FLOW\n",
		},
		"success: upstream modules are importable": {
			script: "from mitmproxy.io import tnetstring; import sys; sys.stdout.buffer.write(tnetstring.dumps([1, b'a', 'b']))",
			want:   "12:1:1#1:a,1:b;]",
		},
		"error: a failing script shows its standard error": {
			script:  "import sys; sys.exit('upstream raised')",
			wantErr: "upstream raised",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{TB: t}
			var got []byte
			rec.run(func() { got = difftest.Python(rec, tt.script, []byte(tt.stdin)) })
			if rec.skipped != "" {
				t.Skip(rec.skipped)
			}

			if tt.wantErr != "" {
				if !strings.Contains(rec.failed, tt.wantErr) {
					t.Fatalf("Python failure = %q, want it to contain %q", rec.failed, tt.wantErr)
				}
				return
			}
			if rec.failed != "" {
				t.Fatalf("Python failed: %s", rec.failed)
			}
			if diff := gocmp.Diff(tt.want, string(got)); diff != "" {
				t.Errorf("Python output mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestScript(t *testing.T) {
	got := string(difftest.Script(t, filepath.Join("testdata", "version_args.py"), "a b", "c"))
	if diff := gocmp.Diff("13.0.0.dev\na b\nc\n", got); diff != "" {
		t.Errorf("Script output mismatch (-want +got):\n%s", diff)
	}
}
