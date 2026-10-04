// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package testutil_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// manifestFile lists every imported upstream file with its SHA-256 digest, in
// the format of shasum -a 256, relative to the testdata directory.
const manifestFile = "SHA256SUMS"

// importedRoots are the testdata entries that hold only byte-exact upstream
// copies; every file under them must be listed in the manifest.
var importedRoots = []string{"UPSTREAM_LICENSE", "mitmproxy", "mitmproxy-rs", "wg-test-client"}

// parseManifest parses shasum -a 256 output into a map from path to
// hex-encoded digest.
func parseManifest(t *testing.T, data []byte) map[string]string {
	t.Helper()

	sums := make(map[string]string)
	for n, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		digest, path, ok := strings.Cut(line, "  ")
		if !ok || len(digest) != sha256.Size*2 || !fs.ValidPath(path) {
			t.Fatalf("%s:%d: malformed line %q, want \"<sha256>  <path>\"", manifestFile, n+1, line)
		}
		if _, dup := sums[path]; dup {
			t.Errorf("%s:%d: %s is listed more than once", manifestFile, n+1, path)
		}
		sums[path] = digest
	}
	return sums
}

// TestFixtureManifest checks that the files under the imported testdata roots
// are exactly the files in the manifest, with the listed digests.
func TestFixtureManifest(t *testing.T) {
	want := parseManifest(t, testutil.Fixture(t, manifestFile))
	t.Logf("%s lists %d files", manifestFile, len(want))

	fsys := os.DirFS(testutil.FixturePath(t, "."))
	got := make(map[string]string, len(want))
	for _, root := range importedRoots {
		err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := fs.ReadFile(fsys, path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			got[path] = hex.EncodeToString(sum[:])
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	// A path only in want is missing on disk, a path only in got is not in
	// the manifest, and a path in both with different values was modified.
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Errorf("imported fixtures differ from %s (-manifest +disk):\n%s", manifestFile, diff)
	}
}

// tableRowPath matches a Markdown table row whose first cell is a code span
// and captures that code span.
var tableRowPath = regexp.MustCompile("(?m)^\\| `([^`]+)` \\|")

// TestREADMEPathsExist checks that every path named in the first column of a
// table in testdata/README.md exists, and is a directory when it ends in "/".
func TestREADMEPathsExist(t *testing.T) {
	matches := tableRowPath.FindAllStringSubmatch(string(testutil.Fixture(t, "README.md")), -1)
	if len(matches) == 0 {
		t.Fatal("README.md has no table rows that start with a code span")
	}

	for _, m := range matches {
		rel := m[1]
		t.Run(rel, func(t *testing.T) {
			info, err := os.Stat(testutil.FixturePath(t, strings.TrimSuffix(rel, "/")))
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(rel, "/") && !info.IsDir() {
				t.Errorf("README.md lists %q as a directory, but it is a file", rel)
			}
		})
	}
}

func TestFixturePath(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	testdata := filepath.Join(filepath.Dir(self), "..", "..", "testdata")

	tests := map[string]struct {
		rel     string
		want    string
		wantErr string
	}{
		"success: file": {
			rel:  "mitmproxy/flows/websocket.mitm",
			want: filepath.Join(testdata, "mitmproxy", "flows", "websocket.mitm"),
		},
		"success: directory": {
			rel:  "mitmproxy/flows",
			want: filepath.Join(testdata, "mitmproxy", "flows"),
		},
		"success: testdata root": {
			rel:  ".",
			want: testdata,
		},
		"error: missing file": {
			rel:     "mitmproxy/flows/no-such-file.mitm",
			wantErr: "no-such-file.mitm",
		},
		"error: parent directory": {
			rel:     "../go.mod",
			wantErr: "not a clean slash-separated relative path",
		},
		"error: absolute path": {
			rel:     "/etc/hosts",
			wantErr: "not a clean slash-separated relative path",
		},
		"error: trailing slash": {
			rel:     "mitmproxy/",
			wantErr: "not a clean slash-separated relative path",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &fatalRecorder{TB: t}
			var got string
			rec.run(func() { got = testutil.FixturePath(rec, tt.rel) })

			if tt.wantErr != "" {
				if !strings.Contains(rec.msg, tt.wantErr) {
					t.Fatalf("FixturePath(%q) failure = %q, want it to contain %q", tt.rel, rec.msg, tt.wantErr)
				}
				return
			}
			if rec.msg != "" {
				t.Fatalf("FixturePath(%q) failed: %s", tt.rel, rec.msg)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("FixturePath(%q) mismatch (-want +got):\n%s", tt.rel, diff)
			}
		})
	}
}

func TestFixture(t *testing.T) {
	got := testutil.Fixture(t, "mitmproxy/replace")
	if diff := gocmp.Diff("replacecontents", strings.TrimSpace(string(got))); diff != "" {
		t.Errorf("Fixture(%q) mismatch (-want +got):\n%s", "mitmproxy/replace", diff)
	}
}

// fatalRecorder is a testing.TB whose Fatalf records the message and stops
// the calling goroutine instead of failing the test, so tests can observe how
// a helper fails.
type fatalRecorder struct {
	testing.TB

	msg string
}

func (r *fatalRecorder) Helper() {}

func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

// run calls f on a new goroutine and waits for it to return or to stop in
// Fatalf.
func (r *fatalRecorder) run(f func()) {
	var wg sync.WaitGroup
	wg.Go(f)
	wg.Wait()
}

func TestFlowFormatVersions(t *testing.T) {
	tests := map[string]struct {
		path string
		want int
	}{
		"corrupted_gzip_body is format 21": {path: "mitmproxy/flows/corrupted_gzip_body.mitm", want: 21},
		"event_stream is format 20":        {path: "mitmproxy/flows/event_stream.mitm", want: 20},
		"websocket is format 20":           {path: "mitmproxy/flows/websocket.mitm", want: 20},
		"diff_data is format 18":           {path: "mitmproxy/flows/diff_data.mitm", want: 18},
		"error_log is format 18":           {path: "mitmproxy/flows/error_log.mitm", want: 18},
		"incomplete_log is format 18":      {path: "mitmproxy/flows/incomplete_log.mitm", want: 18},
		"successful_log is format 18":      {path: "mitmproxy/flows/successful_log.mitm", want: 18},
		"dumpfile-19 is format 20":         {path: "mitmproxy/dumpfile-19.mitm", want: 20},
		"dumpfile-7 is format 11":          {path: "mitmproxy/dumpfile-7.mitm", want: 11},
		"dumpfile-10 is format 10":         {path: "mitmproxy/dumpfile-10.mitm", want: 10},
		"dumpfile-7-websocket is format 7": {path: "mitmproxy/dumpfile-7-websocket.mitm", want: 7},
		"dumpfile-019 is format 7":         {path: "mitmproxy/dumpfile-019.mitm", want: 7},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := flowVersions(testutil.Fixture(t, tt.path))
			if err != nil {
				t.Fatalf("scan %s: %v", tt.path, err)
			}
			if len(got) == 0 {
				t.Fatalf("%s: no %q fragment found", tt.path, versionKey)
			}
			for i, v := range got {
				if v != tt.want {
					t.Errorf("%s: flow %d has version %d, want %d (all versions: %v)", tt.path, i, v, tt.want, got)
				}
			}
		})
	}
}

func TestFlowVersions(t *testing.T) {
	tests := map[string]struct {
		in      string
		want    []int
		wantErr bool
	}{
		"success: no version key": {
			in: "4:spam;4:eggs;}",
		},
		"success: one flow": {
			in:   "1:a;1:b;7:version;2:21#}",
			want: []int{21},
		},
		"success: two flows": {
			in:   "7:version;2:18#}7:version;1:7#}",
			want: []int{18, 7},
		},
		"success: other keys containing version are not matched": {
			in:   "11:tls_version;7:TLSv1.3;12:http_version;8:HTTP/1.1;7:version;2:20#}",
			want: []int{20},
		},
		"success: match inside a longer length prefix is skipped": {
			in:   "17:version;abcdefghij;7:version;2:19#}",
			want: []int{19},
		},
		"error: tuple version": {
			in:      "7:version;13:1:0#2:18#1:2#]}",
			wantErr: true,
		},
		"error: truncated value": {
			in:      "7:version;5:21#",
			wantErr: true,
		},
		"error: missing length": {
			in:      "7:version;",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := flowVersions([]byte(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("flowVersions(%q) error = %v, wantErr %t", tt.in, err, tt.wantErr)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("flowVersions(%q) mismatch (-want +got):\n%s", tt.in, diff)
			}
		})
	}
}

// versionKey is the tnetstring encoding of the text key "version".
const versionKey = "7:version;"

// flowVersions returns, in file order, the integer that follows every
// occurrence of the tnetstring key "version" in data. Each value must be a
// tnetstring integer ("<len>:<digits>#"); any other value is an error. This is
// a byte scan, not a tnetstring decoder: it finds the key wherever it occurs.
func flowVersions(data []byte) ([]int, error) {
	var versions []int
	for {
		i := bytes.Index(data, []byte(versionKey))
		if i < 0 {
			return versions, nil
		}
		// A match preceded by a digit is the tail of a longer length prefix such
		// as "17:version;...", not the key "version"; skip it.
		precededByDigit := i > 0 && '0' <= data[i-1] && data[i-1] <= '9'
		data = data[i+len(versionKey):]
		if precededByDigit {
			continue
		}

		lenField, rest, ok := bytes.Cut(data, []byte(":"))
		if !ok {
			return nil, fmt.Errorf("version value at offset %d has no length prefix", i)
		}
		n, err := strconv.Atoi(string(lenField))
		if err != nil || n < 0 || n >= len(rest) {
			return nil, fmt.Errorf("version value has an invalid length %q", lenField)
		}
		payload, tag := rest[:n], rest[n]
		if tag != '#' {
			return nil, fmt.Errorf("version value %q has tnetstring tag %q, want '#'", payload, tag)
		}
		v, err := strconv.Atoi(string(payload))
		if err != nil {
			return nil, fmt.Errorf("version value %q: %w", payload, err)
		}
		versions = append(versions, v)
		data = rest[n+1:]
	}
}
