// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package testutil holds helpers shared by the tests of this module.
package testutil

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// testdataDir is the location of the repository's testdata directory relative
// to the directory that holds this file.
const testdataDir = "../../testdata"

// FixturePath returns the absolute path of the fixture rel, a slash-separated
// path relative to the repository's testdata directory, such as
// "mitmproxy/flows/websocket.mitm". It fails the test if rel is not a clean
// relative path or if nothing exists at that path.
//
// The repository root is located from the source path of this file, so the
// result does not depend on the working directory of the test binary. That
// path is not a file system path when the binary is built with -trimpath.
func FixturePath(t testing.TB, rel string) string {
	t.Helper()

	if !fs.ValidPath(rel) {
		t.Fatalf("testutil.FixturePath(%q): not a clean slash-separated relative path", rel)
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("testutil.FixturePath(%q): cannot determine the source path of the testutil package", rel)
	}
	if !filepath.IsAbs(file) {
		t.Fatalf("testutil.FixturePath(%q): source path %q is not absolute; fixtures cannot be located in a binary built with -trimpath", rel, file)
	}

	path := filepath.Join(filepath.Dir(file), filepath.FromSlash(testdataDir), filepath.FromSlash(rel))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("testutil.FixturePath(%q): %v", rel, err)
	}
	return path
}

// Fixture returns the contents of the fixture file rel, a slash-separated path
// relative to the repository's testdata directory. It fails the test if the
// file cannot be read. The file is read through an [os.Root] opened on the
// testdata directory, so a symbolic link cannot lead the read outside it.
func Fixture(t testing.TB, rel string) []byte {
	t.Helper()

	FixturePath(t, rel) // fails the test if rel is malformed or missing
	root, err := os.OpenRoot(FixturePath(t, "."))
	if err != nil {
		t.Fatalf("testutil.Fixture(%q): %v", rel, err)
	}
	b, err := root.ReadFile(filepath.FromSlash(rel))
	if closeErr := root.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("testutil.Fixture(%q): %v", rel, err)
	}
	return b
}
