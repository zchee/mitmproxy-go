// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package onboardingapp serves the certificate installation page and downloads.
package onboardingapp

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/internal/magisk"
	"github.com/zchee/mitmproxy-go/options"
)

//go:embed static templates
var assets embed.FS

var page = template.Must(template.ParseFS(assets, "templates/*.html", "templates/icons/*.svg"))

const maxDownloadBytes = 8 << 20

type app struct {
	opts *options.Manager
	mu   sync.Mutex
}

// New returns a concurrent-safe handler using opts for the configuration
// directory and CA settings. The static files are embedded from upstream;
// certificates are read from confdir. A missing Magisk archive is generated
// from the CA and cached in that directory.
func New(opts *options.Manager) http.Handler {
	a := &app{opts: opts}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.index)
	mux.HandleFunc("GET /static/{path...}", a.static)
	mux.HandleFunc("GET /cert/{format}", a.certificate)
	return mux
}

func (a *app) index(w http.ResponseWriter, r *http.Request) {
	var body bytes.Buffer
	if err := page.ExecuteTemplate(&body, "layout.html", nil); err != nil {
		slog.ErrorContext(r.Context(), "Cannot render onboarding page", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body.Bytes())
	}
}

func (a *app) static(w http.ResponseWriter, r *http.Request) {
	name := "static/" + r.PathValue("path")
	body, err := assets.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if contentType := mime.TypeByExtension(filepath.Ext(name)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
}

func (a *app) certificate(w http.ResponseWriter, r *http.Request) {
	ext := r.PathValue("format")
	filename := options.ConfBasename + "-ca-cert." + ext
	contentType := "application/x-x509-ca-cert"
	switch ext {
	case "pem", "cer":
	case "p12":
		contentType = "application/x-pkcs12"
	case "magisk":
		filename = options.ConfBasename + "-magisk-module.zip"
		contentType = "application/zip"
	default:
		http.NotFound(w, r)
		return
	}
	body, err := a.download(filename, ext == "magisk")
	if err != nil {
		slog.ErrorContext(r.Context(), "Cannot serve onboarding download", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (a *app) download(filename string, buildModule bool) ([]byte, error) {
	// Both generation and reads share the lock, so simultaneous first
	// requests cannot observe a partly written cached archive.
	a.mu.Lock()
	defer a.mu.Unlock()
	dir := a.opts.Str("confdir")
	if rest, ok := strings.CutPrefix(dir, "~"); ok {
		name, suffix, _ := strings.Cut(filepath.ToSlash(rest), "/")
		var home string
		if name == "" {
			home, _ = os.UserHomeDir()
		} else if account, err := user.Lookup(name); err == nil {
			home = account.HomeDir
		}
		if home != "" {
			dir = filepath.Join(home, filepath.FromSlash(suffix))
		}
	}
	path := filepath.Join(dir, filename)
	file, err := os.Open(path) //nolint:gosec // The directory is configured by the user; the filename is one of four fixed downloads.
	if errors.Is(err, os.ErrNotExist) && buildModule {
		var passphrase []byte
		if value := a.opts.OptStr("cert_passphrase"); value != nil {
			passphrase = []byte(*value)
		}
		store, err := certs.FromStore(dir, options.ConfBasename, a.opts.Int("key_size"), passphrase)
		if err != nil {
			return nil, err
		}
		var archive bytes.Buffer
		if err := magisk.WriteModule(&archive, store.DefaultCA().X509()); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, archive.Bytes(), 0o666); err != nil { //nolint:gosec // The archive contains only the public CA certificate and installation scripts.
			return nil, err
		}
		return archive.Bytes(), nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, maxDownloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDownloadBytes {
		return nil, fmt.Errorf("onboarding download exceeds %d bytes", maxDownloadBytes)
	}
	return body, nil
}
