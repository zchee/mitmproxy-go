// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package privfile opens private, operator-selected output files without following
// a final-component symlink. Unix opens verify regular-file type and effective-uid
// ownership before narrowing permissions to 0600 and changing any content. Windows
// validates the opened handle, requires the current user as owner, and narrows the
// DACL to a protected current-user-only entry before modifying content. New Windows
// files receive that descriptor atomically. Parent directories must be trusted on
// every platform.
package privfile

import "os"

// Create opens path for writing, creating it if absent or truncating it only after
// validating the descriptor and restricting access on Unix and Windows. It returns
// an error naming path if the destination is unsafe or cannot be opened.
// The caller owns the returned file and must close it.
func Create(path string) (*os.File, error) { return openPrivate(path, false) }

// Append opens path for append, creating it if absent and preserving existing
// content. Unix and Windows restrict access before the first write. It returns an error
// naming path if the destination is unsafe or cannot be opened.
// The caller owns the returned file and must close it.
func Append(path string) (*os.File, error) { return openPrivate(path, true) }
