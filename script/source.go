// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const sourceLimit = 1 << 20

type source struct {
	data  []byte
	mtime time.Time
}

func sourcePath(path string) (string, error) {
	path = strings.Trim(path, "'\" ")
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	return filepath.Abs(path)
}

// readSource follows operator-selected symlinks, but checks the opened object
// rather than trusting an earlier path stat. The extra byte distinguishes an
// exactly-at-limit file from an oversized one without truncating code.
func readSource(path string) (result source, err error) {
	st, err := os.Stat(path)
	if err != nil {
		return source{}, err
	}
	observed := source{mtime: st.ModTime()}
	if !st.Mode().IsRegular() {
		return observed, fmt.Errorf("No such script: %s", path) //nolint:staticcheck // Preserve the upstream operator-facing diagnostic.
	}
	f, err := openSource(path)
	if err != nil {
		return observed, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	st, err = f.Stat()
	if err != nil {
		return observed, err
	}
	observed.mtime = st.ModTime()
	if !st.Mode().IsRegular() {
		return observed, fmt.Errorf("No such script: %s", path) //nolint:staticcheck // Preserve the upstream operator-facing diagnostic.
	}
	if st.Size() > sourceLimit {
		return observed, fmt.Errorf("script source exceeds %d bytes", sourceLimit)
	}
	data, err := io.ReadAll(io.LimitReader(f, sourceLimit+1))
	if err != nil {
		return source{}, err
	}
	if len(data) > sourceLimit {
		return source{}, fmt.Errorf("script source exceeds %d bytes", sourceLimit)
	}
	return source{data: data, mtime: st.ModTime()}, nil
}
