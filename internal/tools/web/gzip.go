// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/klauspost/compress/gzip"
)

func withGzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/updates" {
			next.ServeHTTP(w, r)
			return
		}
		writer := &gzipResponse{ResponseWriter: w, request: r}
		next.ServeHTTP(writer, r)
		_ = writer.finish()
	})
}

type gzipResponse struct {
	http.ResponseWriter
	request    *http.Request
	status     int
	started    bool
	pending    bytes.Buffer
	compressor *gzip.Writer
}

func (w *gzipResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *gzipResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *gzipResponse) compressible() bool {
	media, _, _ := strings.Cut(w.Header().Get("Content-Type"), ";")
	if strings.HasPrefix(media, "text/") {
		return true
	}
	switch media {
	case "application/octet-stream", "application/javascript", "application/x-javascript", "application/xml", "application/atom+xml", "application/json", "application/xhtml+xml", "image/svg+xml":
		return true
	default:
		return false
	}
}

func (w *gzipResponse) start(finishing bool) error {
	if w.started {
		return nil
	}
	w.started = true
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	}
	if vary := w.Header().Get("Vary"); vary != "" {
		w.Header().Set("Vary", vary+", Accept-Encoding")
	} else {
		w.Header().Set("Vary", "Accept-Encoding")
	}
	if strings.Contains(w.request.Header.Get("Accept-Encoding"), "gzip") && w.compressible() && w.Header().Values("Content-Encoding") == nil && (!finishing || w.pending.Len() >= 1024) && w.status != http.StatusNoContent && w.status != http.StatusNotModified {
		writer, err := gzip.NewWriterLevel(w.ResponseWriter, 6)
		if err != nil {
			return err
		}
		w.compressor = writer
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
	}
	w.ResponseWriter.WriteHeader(w.status)
	if w.request.Method == http.MethodHead {
		w.pending.Reset()
		return nil
	}
	if w.compressor != nil {
		_, err := w.compressor.Write(w.pending.Bytes())
		w.pending.Reset()
		return err
	}
	_, err := w.ResponseWriter.Write(w.pending.Bytes())
	w.pending.Reset()
	return err
}

func (w *gzipResponse) Write(body []byte) (int, error) {
	if !w.started {
		if w.pending.Len()+len(body) < 1024 {
			return w.pending.Write(body)
		}
		remaining := 1024 - w.pending.Len()
		_, _ = w.pending.Write(body[:remaining])
		if err := w.start(false); err != nil {
			return 0, err
		}
		if w.compressor != nil {
			_, err := w.compressor.Write(body[remaining:])
			return len(body), err
		}
		_, err := w.ResponseWriter.Write(body[remaining:])
		return len(body), err
	}
	if w.compressor != nil {
		return w.compressor.Write(body)
	}
	return w.ResponseWriter.Write(body)
}

func (w *gzipResponse) Flush() {
	if err := w.start(false); err != nil {
		return
	}
	if w.compressor != nil {
		_ = w.compressor.Flush()
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *gzipResponse) finish() error {
	if err := w.start(true); err != nil {
		return err
	}
	if w.compressor != nil {
		return w.compressor.Close()
	}
	return nil
}
