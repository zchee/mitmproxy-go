// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package onboardingapp

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/options"
)

// TestRoutes ports TestApp.test_basic, test_cert and test_head from upstream
// test/mitmproxy/addons/test_onboarding.py, including every certificate format.
func TestRoutes(t *testing.T) {
	t.Parallel()
	opts := options.New()
	if err := opts.Update(t.Context(), map[string]any{"confdir": testutil.FixturePath(t, "mitmproxy/confdir")}); err != nil {
		t.Fatal(err)
	}
	handler := New(opts)
	tests := map[string]struct{ path, file, mime string }{
		"index":  {"/", "", "text/html; charset=utf-8"},
		"pem":    {"/cert/pem", "mitmproxy-ca-cert.pem", "application/x-x509-ca-cert"},
		"p12":    {"/cert/p12", "mitmproxy-ca-cert.p12", "application/x-pkcs12"},
		"cer":    {"/cert/cer", "mitmproxy-ca-cert.cer", "application/x-x509-ca-cert"},
		"magisk": {"/cert/magisk", "mitmproxy-magisk-module.zip", "application/zip"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), method, tt.path, nil))
				if w.Code != http.StatusOK {
					t.Fatalf("%s %s = %d: %s", method, tt.path, w.Code, w.Body)
				}
				if diff := gocmp.Diff(tt.mime, w.Header().Get("Content-Type")); diff != "" {
					t.Error(diff)
				}
				if w.Header().Get("Content-Length") == "" {
					t.Error("missing Content-Length")
				}
				if tt.file != "" {
					if diff := gocmp.Diff("attachment; filename="+tt.file, w.Header().Get("Content-Disposition")); diff != "" {
						t.Error(diff)
					}
				}
				if method == http.MethodHead {
					if w.Body.Len() != 0 {
						t.Error("HEAD returned a body")
					}
				} else if tt.file != "" {
					if diff := gocmp.Diff(testutil.Fixture(t, "mitmproxy/confdir/"+tt.file), w.Body.Bytes()); diff != "" {
						t.Error(diff)
					}
				} else {
					for _, text := range []string{"Install mitmproxy's Certificate Authority", "Windows", "Linux", "macOS", "iOS", "Android", "Firefox", "/cert/magisk", "Other Platforms"} {
						if !strings.Contains(w.Body.String(), text) {
							t.Errorf("page lacks %q", text)
						}
					}
				}
			}
		})
	}
}

func TestStaticChecksums(t *testing.T) {
	t.Parallel()
	manifest, err := os.ReadFile("static.sha256")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for line := range strings.Lines(string(manifest)) {
		digest, name, ok := strings.Cut(strings.TrimSpace(line), "  ")
		if !ok {
			t.Fatalf("invalid manifest line %q", line)
		}
		data, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if diff := gocmp.Diff(digest, fmt.Sprintf("%x", sha256.Sum256(data))); diff != "" {
			t.Errorf("%s: %s", name, diff)
		}
		w := httptest.NewRecorder()
		New(options.New()).ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), "GET", "/"+name, nil))
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data) {
			t.Errorf("%s was not served byte-exact", name)
		}
		count++
	}
	files := 0
	if err := fs.WalkDir(assets, "static", func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			files++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != files {
		t.Fatalf("manifest has %d entries for %d assets", count, files)
	}
}

// TestGeneratedMagisk also covers test_get_ca and test_magisk_write from
// upstream test/mitmproxy/utils/test_magisk.py through the HTTP endpoint.
func TestGeneratedMagisk(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, file := range []string{"mitmproxy-ca.pem", "mitmproxy-dhparam.pem"} {
		if err := os.WriteFile(filepath.Join(dir, file), testutil.Fixture(t, "mitmproxy/confdir/"+file), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	opts := options.New()
	if err := opts.Update(t.Context(), map[string]any{"confdir": dir}); err != nil {
		t.Fatal(err)
	}
	handler := New(opts)
	want := zipContents(t, testutil.Fixture(t, "mitmproxy/confdir/mitmproxy-magisk-module.zip"))
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), "GET", "/cert/magisk", nil))
			if w.Code != 200 {
				t.Errorf("status %d: %s", w.Code, w.Body)
				return
			}
			if diff := gocmp.Diff(want, zipContents(t, w.Body.Bytes())); diff != "" {
				t.Error(diff)
			}
		})
	}
	group.Wait()
	data, err := os.ReadFile(filepath.Join(dir, "mitmproxy-magisk-module.zip"))
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(want, zipContents(t, data)); diff != "" {
		t.Error(diff)
	}
}

func zipContents(t *testing.T, data []byte) map[string]string {
	t.Helper()
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]string)
	for _, file := range archive.File {
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		result[file.Name] = string(content)
	}
	return result
}

func TestOversizedDownload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file, err := os.Create(filepath.Join(dir, "mitmproxy-ca-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxDownloadBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	opts := options.New()
	if err := opts.Update(t.Context(), map[string]any{"confdir": dir}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	New(opts).ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), "GET", "/cert/pem", nil))
	if diff := gocmp.Diff(http.StatusInternalServerError, w.Code); diff != "" {
		t.Error(diff)
	}
}

func TestHomeDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	if err := os.WriteFile(filepath.Join(dir, "mitmproxy-ca-cert.pem"), []byte("public certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := options.New()
	if err := opts.Update(t.Context(), map[string]any{"confdir": "~/"}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	New(opts).ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), "GET", "/cert/pem", nil))
	if diff := gocmp.Diff("public certificate", w.Body.String()); diff != "" {
		t.Error(diff)
	}
}

func TestFailures(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		path, method string
		status       int
	}{
		"unknown certificate":  {"/cert/key", "GET", 404},
		"missing certificate":  {"/cert/pem", "GET", 500},
		"unknown route":        {"/other", "GET", 404},
		"unknown asset":        {"/static/missing", "GET", 404},
		"no directory listing": {"/static/", "GET", 404},
		"unsupported method":   {"/cert/pem", "POST", 405},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := options.New()
			if err := opts.Update(t.Context(), map[string]any{"confdir": t.TempDir()}); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			New(opts).ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), tt.method, tt.path, nil))
			if diff := gocmp.Diff(tt.status, w.Code); diff != "" {
				t.Error(diff)
			}
		})
	}
}
