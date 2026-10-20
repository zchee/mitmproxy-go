// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package webauth

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
)

const formMemoryLimit = 32 << 20

const receiveLimit = 4 << 30

type parsedArgumentsKey struct{}

type parsedArguments struct {
	body  *bodySnapshot
	first *multipart.FileHeader
}

// FirstUploadedFile returns the first file part in wire order recorded by Wrap.
// It returns nil, false when no file was parsed. Open and consume the header
// during the wrapped handler: Wrap removes multipart and replay temporary files
// after that handler returns. This function never parses or consumes r.Body.
func FirstUploadedFile(r *http.Request) (*multipart.FileHeader, bool) {
	parsed, _ := r.Context().Value(parsedArgumentsKey{}).(*parsedArguments)
	if parsed == nil || parsed.first == nil {
		return nil, false
	}
	return parsed.first, true
}

func firstFileField(body io.Reader, boundary string) (string, error) {
	reader := multipart.NewReader(body, boundary)
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if name := part.FormName(); name != "" && part.FileName() != "" {
			// Do not close the part: Close would consume the file body. The
			// independent snapshot reader owns no underlying file descriptor.
			return name, nil
		}
	}
}

func cleanupArguments(r *http.Request) {
	var err error
	if parsed, _ := r.Context().Value(parsedArgumentsKey{}).(*parsedArguments); parsed != nil {
		err = parsed.body.close()
	}
	if r.MultipartForm != nil {
		err = errors.Join(err, r.MultipartForm.RemoveAll())
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "Could not clean up web request data.", "error", err)
	}
}

type bodySnapshot struct {
	data []byte
	file *os.File
	size int64
}

func captureBody(body io.Reader, memoryLimit int64) (*bodySnapshot, error) {
	var memory bytes.Buffer
	// Hide Buffer.ReadFrom so it cannot grow beyond the bounded prefix while
	// attempting one more read at EOF.
	if _, err := io.CopyBuffer(struct{ io.Writer }{&memory}, io.LimitReader(body, memoryLimit), make([]byte, 32<<10)); err != nil {
		return nil, err
	}
	var extra [1]byte
	n, err := io.ReadFull(body, extra[:])
	if errors.Is(err, io.EOF) {
		return &bodySnapshot{data: memory.Bytes(), size: int64(memory.Len())}, nil
	}
	if err != nil {
		return nil, err
	}
	file, err := os.CreateTemp("", "mitmweb-body-*")
	if err != nil {
		return nil, err
	}
	snapshot := &bodySnapshot{file: file}
	snapshot.size, err = io.Copy(file, io.MultiReader(bytes.NewReader(memory.Bytes()), bytes.NewReader(extra[:n]), body))
	if err != nil {
		return nil, errors.Join(err, snapshot.close())
	}
	return snapshot, nil
}

func (snapshot *bodySnapshot) reader() io.ReadCloser {
	if snapshot.file != nil {
		return io.NopCloser(io.NewSectionReader(snapshot.file, 0, snapshot.size))
	}
	return io.NopCloser(bytes.NewReader(snapshot.data))
}

func (snapshot *bodySnapshot) close() error {
	if snapshot.file == nil {
		return nil
	}
	file := snapshot.file
	snapshot.file = nil
	return errors.Join(file.Close(), os.Remove(file.Name()))
}
