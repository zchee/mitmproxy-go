// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package webauth

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"

	gocmp "github.com/google/go-cmp/cmp"
)

func testWebBodySnapshot(t *testing.T) {
	tests := map[string]struct {
		input string
		limit int64
		disk  bool
		fail  bool
	}{
		"empty":                 {},
		"memory boundary":       {input: strings.Repeat("m", 64), limit: 64},
		"spill boundary":        {input: strings.Repeat("f", 65), limit: 64, disk: true},
		"memory reader failure": {input: "short", limit: 64, fail: true},
		"disk reader failure":   {input: strings.Repeat("f", 128), limit: 64, fail: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("TMPDIR", dir)
			var input io.Reader = strings.NewReader(tt.input)
			readErr := errors.New("body reader failed")
			if tt.fail {
				input = io.MultiReader(input, iotest.ErrReader(readErr))
			}
			snapshot, err := captureBody(input, tt.limit)
			if tt.fail {
				if !errors.Is(err, readErr) || snapshot != nil {
					t.Fatalf("capture failure = %v, %v", snapshot, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = snapshot.close() }()
				if diff := gocmp.Diff(tt.disk, snapshot.file != nil); diff != "" {
					t.Fatal(diff)
				}
				if snapshot.file != nil {
					info, err := snapshot.file.Stat()
					if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
						t.Fatalf("temporary file permissions: %v, %v", info, err)
					}
				}
				for range 2 {
					reader := snapshot.reader()
					got, err := io.ReadAll(reader)
					if err != nil {
						t.Fatal(err)
					}
					if err := reader.Close(); err != nil {
						t.Fatal(err)
					}
					if diff := gocmp.Diff(tt.input, string(got)); diff != "" {
						t.Fatal(diff)
					}
				}
				if err := snapshot.close(); err != nil {
					t.Fatal(err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("temporary files retained: %v, %v", entries, err)
			}
		})
	}
}

func testWebUploadFileLifetime(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("upload", "large.bin")
	if err != nil {
		t.Fatal(err)
	}
	const size = formMemoryLimit + 1
	if _, err := io.WriteString(part, strings.Repeat("f", size)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	rawSize := int64(body.Len())
	r := httptest.NewRequest(http.MethodPost, "/api", &body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("Authorization", "Bearer test")
	r.Header.Set("X-XSRFToken", "upload-xsrf")
	r.AddCookie(&http.Cookie{Name: xsrfCookieName, Value: "upload-xsrf"})
	auth, _, _ := newAuth(t, "test")
	var uploaded *multipart.FileHeader
	var replayPath string
	wrapped := auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var found bool
		uploaded, found = FirstUploadedFile(r)
		if !found {
			t.Fatal("spilled upload is missing")
		}
		parsed := r.Context().Value(parsedArgumentsKey{}).(*parsedArguments)
		if parsed.body.file == nil {
			t.Fatal("raw body above the memory bound did not spill")
		}
		replayPath = parsed.body.file.Name()
		file, err := uploaded.Open()
		if err != nil {
			t.Fatal(err)
		}
		n, err := io.Copy(io.Discard, file)
		if err != nil || n != size {
			t.Fatalf("spilled file bytes = %d, %v", n, err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		n, err = io.Copy(io.Discard, r.Body)
		if err != nil || n != rawSize {
			t.Fatalf("replayed body bytes = %d, %v", n, err)
		}
		w.WriteHeader(http.StatusOK)
	}), nil)
	response := httptest.NewRecorder()
	wrapped.ServeHTTP(response, r)
	if response.Code != http.StatusOK || uploaded == nil {
		t.Fatalf("spill handler status = %d", response.Code)
	}
	if _, err := os.Stat(replayPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replay temporary file retained: %v", err)
	}
	if file, err := uploaded.Open(); err == nil {
		_ = file.Close()
		t.Fatal("multipart temporary file retained after handler return")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("request temporary files retained: %v, %v", entries, err)
	}
}

func testWebUploads(t *testing.T) {
	tests := map[string]struct {
		fields    []string
		values    bool
		form      bool
		plain     bool
		oversized bool
	}{
		"first field alpha":       {fields: []string{"alpha", "beta"}},
		"first field beta":        {fields: []string{"beta", "alpha"}},
		"value before first file": {fields: []string{"beta", "alpha"}, values: true},
		"multipart without files": {values: true},
		"form exact raw bytes":    {form: true},
		"non multipart body":      {plain: true},
		"oversized part":          {fields: []string{"alpha"}, oversized: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			if err := writer.SetBoundary("upload-boundary"); err != nil {
				t.Fatal(err)
			}
			if tt.values {
				if err := writer.WriteField("before", "value + %2f"); err != nil {
					t.Fatal(err)
				}
			}
			for _, field := range tt.fields {
				part, err := writer.CreateFormFile(field, field+".bin")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(part, field+"\x00\r\ncontent"); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			contentType := writer.FormDataContentType()
			raw := body.String()
			if tt.form {
				contentType, raw = "application/x-www-form-urlencoded", "value=one+two&value=%2f%2F&empty=&token=wrong"
			}
			if tt.plain {
				contentType, raw = "application/octet-stream", "raw\x00bytes\r\n"
			}
			auth, _, _ := newAuth(t, "test")
			wrapped := auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.oversized {
					t.Error("oversized request reached the wrapped handler")
				}
				file, found := FirstUploadedFile(r)
				if diff := gocmp.Diff(len(tt.fields) != 0, found); diff != "" {
					t.Error(diff)
				}
				if found {
					if diff := gocmp.Diff(tt.fields[0]+".bin", file.Filename); diff != "" {
						t.Error(diff)
					}
					opened, err := file.Open()
					if err != nil {
						t.Error(err)
						return
					}
					data, err := io.ReadAll(opened)
					if err != nil {
						t.Error(err)
					}
					if err := opened.Close(); err != nil {
						t.Error(err)
					}
					if diff := gocmp.Diff(tt.fields[0]+"\x00\r\ncontent", string(data)); diff != "" {
						t.Error(diff)
					}
					for _, field := range tt.fields {
						if len(r.MultipartForm.File[field]) != 1 {
							t.Errorf("multipart field %s changed", field)
						}
					}
				}
				if _, err := io.Copy(w, r.Body); err != nil {
					t.Error(err)
				}
			}), nil)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.oversized {
					r.Body = http.MaxBytesReader(w, r.Body, 64)
				}
				wrapped.ServeHTTP(w, r)
			}))
			t.Cleanup(server.Close)
			status, echoed, _ := request(t, server.Client(), http.MethodPost, server.URL, raw, map[string]string{
				"Content-Type": contentType, "Authorization": "Bearer test", "X-XSRFToken": "upload-xsrf",
			}, &http.Cookie{Name: xsrfCookieName, Value: "upload-xsrf"})
			if tt.oversized {
				if status != http.StatusBadRequest {
					t.Fatalf("oversized request status = %d", status)
				}
				return
			}
			if status != http.StatusOK {
				t.Fatalf("upload status = %d", status)
			}
			if diff := gocmp.Diff(raw, echoed); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
