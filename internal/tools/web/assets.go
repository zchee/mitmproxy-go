// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package web serves the embedded mitmweb frontend.
package web

import (
	"bytes"
	"crypto/sha512"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed index.html static templates UPSTREAM_LICENSE assets.tsv
var assets embed.FS

// The pinned commit time makes validators reproducible despite embed's zero mtimes.
var assetModified = time.Unix(1791038697, 0).UTC()

var loginPage = template.Must(template.ParseFS(assets, "templates/login.html"))

var staticETags = sync.OnceValue(func() map[string]string {
	entries, err := assets.ReadDir("static")
	if err != nil {
		panic(err)
	}
	etags := make(map[string]string, len(entries))
	for _, entry := range entries {
		body, err := assets.ReadFile("static/" + entry.Name())
		if err != nil {
			panic(err)
		}
		etags[entry.Name()] = fmt.Sprintf(`"%x"`, sha512.Sum512(body))
	}
	return etags
})

// StaticHandler serves only the embedded static subtree at /static/.
// It does not require authentication, matching upstream's static handler.
func StaticHandler() http.Handler {
	files := http.FileServerFS(staticAssetFS{})
	etags := staticETags()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		name, ok := strings.CutPrefix(r.URL.Path, "/static/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		// URL.Path has already been decoded once. Never unescape it again.
		name = path.Clean(name)
		if name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		etag, ok := etags[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Etag", etag)
		if strings.HasSuffix(name, ".js") {
			// ES modules must not depend on the host's MIME registry.
			w.Header().Set("Content-Type", "text/javascript")
		}
		if r.URL.Query().Has("v") {
			const maxAge = 315360000
			w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(maxAge))
			w.Header().Set("Expires", time.Now().UTC().Add(maxAge*time.Second).Format(http.TimeFormat))
		}
		request := r.Clone(r.Context())
		request.URL = r.URL.Clone()
		request.URL.Path = "/" + name
		request.URL.RawPath = ""
		files.ServeHTTP(w, request)
	})
}

// IndexHandler serves the byte-exact embedded index at /.
// The caller must apply authentication before exposing this handler.
func IndexHandler() http.Handler {
	body, err := assets.ReadFile("index.html")
	if err != nil {
		panic(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	})
}

// RenderLogin writes the upstream login form with status 403 and an escaped XSRF token.
// It returns template-rendering or response-writing errors to the caller.
func RenderLogin(w http.ResponseWriter, r *http.Request, invalidPassword bool, xsrfToken string) error {
	data := struct {
		InvalidPassword bool
		XSRFToken       string
	}{invalidPassword, xsrfToken}
	var body bytes.Buffer
	if err := loginPage.ExecuteTemplate(&body, "login.html", data); err != nil {
		return fmt.Errorf("render web login: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	w.WriteHeader(http.StatusForbidden)
	if r.Method == http.MethodHead {
		return nil
	}
	if _, err := w.Write(body.Bytes()); err != nil {
		return fmt.Errorf("write web login: %w", err)
	}
	return nil
}

type staticAssetFS struct{}

func (staticAssetFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	file, err := assets.Open("static/" + name)
	if err != nil {
		return nil, err
	}
	return staticAssetFile{file}, nil
}

type staticAssetFile struct{ fs.File }

func (f staticAssetFile) Stat() (fs.FileInfo, error) {
	info, err := f.File.Stat()
	if err != nil {
		return nil, err
	}
	return staticAssetInfo{info}, nil
}

func (f staticAssetFile) Seek(offset int64, whence int) (int64, error) {
	return f.File.(io.Seeker).Seek(offset, whence)
}

type staticAssetInfo struct{ fs.FileInfo }

func (staticAssetInfo) ModTime() time.Time { return assetModified }
