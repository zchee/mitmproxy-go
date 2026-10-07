// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func syntheticArtifactWheel(t *testing.T, name string, mode fs.FileMode, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(mode)
	entry, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestAcquireArtifactOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator-redirector")
	if err := os.WriteFile(path, []byte("operator-selected executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(t.TempDir(), "Synthetic Redirector.app")
	if err := os.Mkdir(app, 0o700); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		path    string
		goos    string
		wantErr bool
	}{
		"success: validated override avoids acquisition": {path: path, goos: "unsupported"},
		"success: macOS app directory":                   {path: app, goos: "darwin"},
		"error: missing override":                        {path: path + ".missing", goos: "unsupported", wantErr: true},
		"error: directory override":                      {path: filepath.Dir(path), goos: "unsupported", wantErr: true},
		"error: non-app macOS directory":                 {path: filepath.Dir(path), goos: "darwin", wantErr: true},
		"error: app directory on Windows":                {path: app, goos: "windows", wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Unsupported selectors prove override handling precedes network selection.
			got, err := AcquireArtifact(t.Context(), "", test.path, test.goos, "unsupported")
			if (err != nil) != test.wantErr {
				t.Fatalf("AcquireArtifact() error = %v, want error %v", err, test.wantErr)
			}
			if !test.wantErr && got != test.path {
				t.Fatalf("override path = %q, want %q", got, test.path)
			}
		})
	}
}

func TestAcquireArtifactSymlinkOverride(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlink fixtures requires Windows developer mode or administrator privileges")
	}
	tests := map[string]struct{ directory bool }{
		"error: symlink to executable": {},
		"error: symlink to app":        {directory: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "target")
			if test.directory {
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(target, []byte("synthetic override"), 0o700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(t.TempDir(), "Synthetic Redirector.app")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			if _, err := AcquireArtifact(t.Context(), "", link, "darwin", "arm64"); err == nil {
				t.Fatal("symlink override accepted")
			}
		})
	}
}

func TestAcquireArtifactIntegrity(t *testing.T) {
	payload := []byte("synthetic redirector fixture, not a captured native artifact")
	goodWheel := syntheticArtifactWheel(t, "package/redirector", 0o700, payload)
	goodDigest := sha256.Sum256(goodWheel)
	tests := map[string]struct {
		wheel   []byte
		digest  string
		status  int
		wantErr bool
	}{
		"success: verified bounded extraction":   {wheel: goodWheel, status: http.StatusOK},
		"error: digest mismatch leaves no files": {wheel: goodWheel, digest: strings.Repeat("0", 64), status: http.StatusOK, wantErr: true},
		"error: invalid wheel leaves no files":   {wheel: []byte("not a ZIP"), status: http.StatusOK, wantErr: true},
		"error: absolute entry":                  {wheel: syntheticArtifactWheel(t, "/outside", 0o600, payload), status: http.StatusOK, wantErr: true},
		"error: traversal entry":                 {wheel: syntheticArtifactWheel(t, "package/../redirector", 0o700, payload), status: http.StatusOK, wantErr: true},
		"error: backslash traversal entry":       {wheel: syntheticArtifactWheel(t, `..\outside`, 0o600, payload), status: http.StatusOK, wantErr: true},
		"error: symlink entry":                   {wheel: syntheticArtifactWheel(t, "package/redirector", fs.ModeSymlink|0o777, []byte("outside")), status: http.StatusOK, wantErr: true},
		"error: empty target":                    {wheel: syntheticArtifactWheel(t, "package/redirector", 0o700, nil), status: http.StatusOK, wantErr: true},
		"error: missing target":                  {wheel: syntheticArtifactWheel(t, "package/other", 0o600, payload), status: http.StatusOK, wantErr: true},
		"error: HTTP failure":                    {wheel: goodWheel, status: http.StatusBadGateway, wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			digest := sha256.Sum256(test.wheel)
			if test.digest == "" {
				test.digest = hex.EncodeToString(digest[:])
			}
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(test.status)
				_, _ = w.Write(test.wheel)
			}))
			defer server.Close()
			cache := filepath.Join(t.TempDir(), "cache", "platform")
			artifact := artifactSpec{filename: "fixture.whl", url: server.URL, sha256: test.digest, entry: "package/redirector"}
			got, err := acquireArtifact(t.Context(), cache, artifact, server.Client())
			if (err != nil) != test.wantErr {
				t.Fatalf("acquireArtifact() = %q, %v; want error %v", got, err, test.wantErr)
			}
			if test.wantErr {
				if err := filepath.WalkDir(filepath.Dir(cache), func(path string, entry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if !entry.IsDir() {
						t.Errorf("failed acquisition left file %s", path)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				return
			}
			content, err := os.ReadFile(got)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(payload, content); diff != "" {
				t.Fatalf("payload (-want +got):\n%s", diff)
			}
			cached, err := acquireArtifact(t.Context(), cache, artifact, server.Client())
			if err != nil || cached != got || requests.Load() != 1 {
				t.Fatalf("cache reuse = %q, %v, requests %d", cached, err, requests.Load())
			}
			cachedWheel, err := os.ReadFile(filepath.Join(cache, artifact.filename))
			if err != nil || sha256.Sum256(cachedWheel) != goodDigest {
				t.Fatalf("cached wheel digest changed: %v", err)
			}
			if err := os.WriteFile(got, []byte("tampered"), 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := acquireArtifact(t.Context(), cache, artifact, server.Client()); err == nil {
				t.Fatal("tampered cached payload accepted")
			}
			if requests.Load() != 1 {
				t.Fatal("invalid cache was silently overwritten by a new download")
			}
		})
	}
}

func TestAcquireArtifactConcurrent(t *testing.T) {
	tests := map[string]struct{ callers int }{
		"success: eight concurrent callers":   {callers: 8},
		"success: sixteen concurrent callers": {callers: 16},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			wheel := syntheticArtifactWheel(t, "package/redirector", 0o700, []byte("synthetic payload"))
			digest := sha256.Sum256(wheel)
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				_, _ = w.Write(wheel)
			}))
			defer server.Close()
			artifact := artifactSpec{filename: "fixture.whl", url: server.URL, sha256: hex.EncodeToString(digest[:]), entry: "package/redirector"}
			cache := filepath.Join(t.TempDir(), "cache", "platform")
			var group sync.WaitGroup
			for range test.callers {
				group.Go(func() {
					if _, err := acquireArtifact(t.Context(), cache, artifact, server.Client()); err != nil {
						t.Error(err)
					}
				})
			}
			group.Wait()
			if requests.Load() != 1 {
				t.Fatalf("concurrent acquisition downloaded %d times, want 1", requests.Load())
			}
		})
	}
}

func TestAcquireArtifactCancellation(t *testing.T) {
	tests := map[string]struct{ waiting bool }{
		"error: canceled before acquisition":         {},
		"error: canceled while acquisition occupied": {waiting: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.waiting {
				artifactAcquisition <- struct{}{}
				defer func() { <-artifactAcquisition }()
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			artifact := artifactSpec{}
			if _, err := acquireArtifact(ctx, filepath.Join(t.TempDir(), "cache"), artifact, http.DefaultClient); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled acquisition error = %v", err)
			}
			if _, err := AcquireArtifact(ctx, t.TempDir(), "", "darwin", "arm64"); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled public acquisition error = %v", err)
			}
		})
	}
}

func TestArtifactEntryBounds(t *testing.T) {
	tests := map[string]struct {
		entries int
		size    uint64
		wantErr bool
	}{
		"success: entry count limit":     {entries: maxArtifactEntries, size: 1},
		"error: too many entries":        {entries: maxArtifactEntries + 1, size: 1, wantErr: true},
		"success: size limit":            {entries: 1, size: maxArtifactBytes},
		"error: oversized entry":         {entries: 1, size: maxArtifactBytes + 1, wantErr: true},
		"error: combined size limit":     {entries: 2, size: maxArtifactBytes/2 + 1, wantErr: true},
		"error: uint64 overflow avoided": {entries: 1, size: ^uint64(0), wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			reader := new(zip.Reader)
			for i := range test.entries {
				header := zip.FileHeader{Name: "package/" + strings.Repeat("x", i), UncompressedSize64: test.size}
				if i == 0 {
					header.Name = "package/redirector"
				}
				header.SetMode(0o600)
				reader.File = append(reader.File, &zip.File{FileHeader: header})
			}
			artifact := artifactSpec{entry: "package/redirector"}
			if err := artifactEntries(reader, artifact); (err != nil) != test.wantErr {
				t.Fatalf("artifactEntries() error = %v, want error %v", err, test.wantErr)
			}
		})
	}
}

func TestAcquirePinnedArtifacts(t *testing.T) {
	if os.Getenv("MITMPROXY_TEST_REDIRECTOR_DOWNLOAD") != "1" {
		t.Skip("real-network artifact verification requires MITMPROXY_TEST_REDIRECTOR_DOWNLOAD=1")
	}
	tests := map[string]struct{ goos, goarch string }{
		"success: macOS":       {"darwin", "arm64"},
		"success: Windows":     {"windows", "amd64"},
		"success: Linux amd64": {"linux", "amd64"},
		"success: Linux arm64": {"linux", "arm64"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path, err := AcquireArtifact(t.Context(), t.TempDir(), "", test.goos, test.goarch)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Size() == 0 {
				t.Fatalf("downloaded target = %v, %v", info, err)
			}
		})
	}
}
