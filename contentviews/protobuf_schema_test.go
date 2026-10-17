// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestProtobufSchema(t *testing.T) {
	tests := map[string]struct {
		path     string
		response bool
		want     string
	}{
		"request":          {"/sample.Service/Call", false, "sample.Request"},
		"response":         {"/sample.Service/Call", true, "sample.Response"},
		"query_fallback":   {"/sample.Other/Other?x=1", false, "sample.Request"},
		"message_fallback": {"/sample.Unknown/Response", false, "sample.Response"},
		"unknown_fallback": {"/unknown", false, "sample.Request"},
	}
	root := t.TempDir()
	source := `syntax = "proto3"; package sample; message Request { string value = 1; } message Response { int32 code = 1; } service Service { rpc Call(Request) returns (Response); }`
	if err := os.WriteFile(filepath.Join(root, "service.proto"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			schema, err := loadProtobufSchema(t.Context(), []string{root}, schemaLimits{}, newViewBudget("test"))
			if err != nil {
				t.Fatal(err)
			}
			descriptor, err := schema.messageDescriptor(test.path, test.response)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.want, string(descriptor.FullName())); diff != "" {
				t.Fatalf("descriptor (-want +got):\n%s", diff)
			}
			first, err := schema.newMessage(test.path, test.response)
			if err != nil {
				t.Fatal(err)
			}
			second, err := schema.newMessage(test.path, test.response)
			if err != nil || first == second {
				t.Fatalf("messages must be caller owned: %v", err)
			}
		})
	}
}

func TestProtobufSchemaSources(t *testing.T) {
	tests := map[string]struct {
		files     map[string]string
		roots     []string
		wantError bool
	}{
		"imports":             {files: map[string]string{"a.proto": `syntax="proto3"; import "sub/b.proto"; message A { B b=1; }`, "sub/b.proto": `syntax="proto3"; message B { string value=1; }`}, roots: []string{"a.proto"}},
		"standard_import":     {files: map[string]string{"a.proto": `syntax="proto3"; import "google/protobuf/timestamp.proto"; message A { google.protobuf.Timestamp value=1; }`}},
		"recursive_directory": {files: map[string]string{"b.proto": `syntax="proto3"; message B {}`, "sub/a.proto": `syntax="proto3"; message A {}`}},
		"missing_import":      {files: map[string]string{"a.proto": `syntax="proto3"; import "missing.proto"; message A {}`}, wantError: true},
		"escaping_import":     {files: map[string]string{"a.proto": `syntax="proto3"; import "../outside.proto"; message A {}`}, wantError: true},
		"cycle":               {files: map[string]string{"a.proto": `syntax="proto3"; import "b.proto"; message A {}`, "b.proto": `syntax="proto3"; import "a.proto"; message B {}`}, wantError: true},
		"invalid_definition":  {files: map[string]string{"a.proto": `message A { broken`}, wantError: true},
		"empty_directory":     {files: map[string]string{}, wantError: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for path, content := range test.files {
				file := filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			roots := []string{root}
			if test.roots != nil {
				roots = nil
				for _, path := range test.roots {
					roots = append(roots, filepath.Join(root, path))
				}
			}
			schema, err := loadProtobufSchema(t.Context(), roots, schemaLimits{}, newViewBudget("test"))
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v want error=%v", err, test.wantError)
			}
			if test.wantError {
				if schema != nil {
					t.Fatal("partial schema returned")
				}
				return
			}
			if len(schema.files) == 0 {
				t.Fatal("no descriptors")
			}
			if name == "recursive_directory" {
				var paths []string
				for _, file := range schema.files {
					paths = append(paths, file.Path())
				}
				if diff := gocmp.Diff([]string{"b.proto", "sub/a.proto"}, paths); diff != "" {
					t.Fatalf("deterministic paths:\n%s", diff)
				}
			}
		})
	}
}

func TestProtobufSchemaLimits(t *testing.T) {
	tests := map[string]struct {
		files  map[string]string
		limits schemaLimits
	}{
		"file_bytes":      {map[string]string{"a.proto": `syntax="proto3"; message A {}`}, schemaLimits{Files: 10, FileBytes: 4, TotalBytes: 1000, Depth: 4}},
		"total_bytes":     {map[string]string{"a.proto": `syntax="proto3"; message A {}`}, schemaLimits{Files: 10, FileBytes: 1000, TotalBytes: 4, Depth: 4}},
		"file_count":      {map[string]string{"a.proto": `syntax="proto3"; message A {}`, "b.proto": `syntax="proto3"; message B {}`}, schemaLimits{Files: 1, FileBytes: 1000, TotalBytes: 1000, Depth: 4}},
		"directory_depth": {map[string]string{"a/b.proto": `syntax="proto3"; message B {}`}, schemaLimits{Files: 10, FileBytes: 1000, TotalBytes: 1000, Depth: 1}},
		"import_depth":    {map[string]string{"a.proto": `syntax="proto3"; import "b.proto"; message A {}`, "b.proto": `syntax="proto3"; message B {}`}, schemaLimits{Files: 10, FileBytes: 1000, TotalBytes: 1000, Depth: 1}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for path, content := range test.files {
				file := filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			schema, err := loadProtobufSchema(t.Context(), []string{root}, test.limits, newViewBudget("test"))
			var limit *LimitError
			if !errors.As(err, &limit) || schema != nil {
				t.Fatalf("expected typed refusal without schema: %v", err)
			}
		})
	}
}

func TestProtobufSchemaRefreshAndCancellation(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "a.proto")
	for _, name := range []string{"First", "Second"} {
		if err := os.WriteFile(file, []byte(`syntax="proto3"; message `+name+` {}`), 0o600); err != nil {
			t.Fatal(err)
		}
		schema, err := loadProtobufSchema(t.Context(), []string{file}, schemaLimits{}, newViewBudget("test"))
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := schema.messageDescriptor("", false)
		if err != nil || string(descriptor.Name()) != name {
			t.Fatalf("stale schema: %v %v", descriptor, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if schema, err := loadProtobufSchema(ctx, []string{file}, schemaLimits{}, newViewBudget("test")); !errors.Is(err, context.Canceled) || schema != nil {
		t.Fatalf("canceled load: %v %v", schema, err)
	}
}

func TestProtobufSchemaSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "outside.proto"), []byte(`syntax="proto3"; message Outside {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "outside.proto"), filepath.Join(root, "escape.proto")); err != nil {
		t.Fatal(err)
	}
	if schema, err := loadProtobufSchema(t.Context(), []string{root}, schemaLimits{}, newViewBudget("test")); err == nil || schema != nil {
		t.Fatalf("escaped root: %v %v", schema, err)
	}
	if err := os.Remove(filepath.Join(root, "escape.proto")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.proto"), []byte(`syntax="proto3"; message A { string value=1; }`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(root, "loop")); err != nil {
		t.Fatal(err)
	}
	schema, err := loadProtobufSchema(t.Context(), []string{root}, schemaLimits{}, newViewBudget("test"))
	if err != nil || schema == nil {
		t.Fatalf("contained directory cycle: %v", err)
	}
	if len(schema.files) != 1 || !strings.HasSuffix(schema.files[0].Path(), "a.proto") {
		t.Fatalf("duplicate cycle sources: %v", schema.files)
	}
}
