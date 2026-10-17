// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bufbuild/protocompile"
	"github.com/bufbuild/protocompile/parser"
	"github.com/bufbuild/protocompile/reporter"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

type schemaLimits struct {
	Files                 int
	FileBytes, TotalBytes uint64
	Depth                 int
}

type protobufSchema struct{ files []protoreflect.FileDescriptor }

type schemaSourceRoot struct {
	root *os.Root
	path string
}

func (r schemaSourceRoot) canonical(name string) (string, error) {
	resolved, err := filepath.EvalSymlinks(filepath.Join(r.path, filepath.FromSlash(name)))
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(r.path, resolved)
	if err != nil || !filepath.IsLocal(relative) {
		return "", fmt.Errorf("protobuf source escapes configured root")
	}
	return filepath.ToSlash(relative), nil
}

func loadProtobufSchema(ctx context.Context, roots []string, limits schemaLimits, budget *viewBudget) (schema *protobufSchema, err error) {
	const stage = "protobuf schema"
	if limits == (schemaLimits{}) {
		limits = schemaLimits{Files: 1024, FileBytes: 16 << 20, TotalBytes: 64 << 20, Depth: 64}
	}
	if limits.Files <= 0 || limits.Files > 1024 || limits.FileBytes == 0 || limits.FileBytes > 16<<20 || limits.TotalBytes == 0 || limits.TotalBytes > 64<<20 || limits.Depth <= 0 || limits.Depth > 64 {
		return nil, fmt.Errorf("invalid protobuf schema limits")
	}
	if len(roots) == 0 || len(roots) > limits.Files {
		return nil, fmt.Errorf("invalid protobuf schema root count")
	}
	var directories []schemaSourceRoot
	defer func() {
		for _, directory := range directories {
			if closeErr := directory.root.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close protobuf source root: %w", closeErr))
				schema = nil
			}
		}
	}()
	var inputs []string
	seenInputs, seenDirectories := map[string]bool{}, map[string]bool{}
	var walk func(schemaSourceRoot, string, int) error
	walk = func(directory schemaSourceRoot, name string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > limits.Depth {
			return budget.refusal(stage, "directory depth", 0, uint64(depth), uint64(limits.Depth))
		}
		if err := budget.chargeNodes(stage, 1); err != nil {
			return err
		}
		name, err := directory.canonical(name)
		if err != nil {
			return err
		}
		resolved := filepath.Join(directory.path, filepath.FromSlash(name))
		if seenDirectories[resolved] {
			return nil
		}
		file, err := directory.root.Open(name)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("protobuf schema directory changed")
		}
		seenDirectories[resolved] = true
		var names []string
		for {
			entries, err := file.ReadDir(64)
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			for _, entry := range entries {
				if err := budget.chargeNodes(stage, 1); err != nil {
					return err
				}
				if err := budget.chargeMaterialization(stage, uint64(len(entry.Name())+16)); err != nil {
					return err
				}
				names = append(names, entry.Name())
			}
			if errors.Is(err, io.EOF) {
				break
			}
		}
		slices.Sort(names)
		for _, child := range names {
			relative, err := directory.canonical(path.Join(name, child))
			if err != nil {
				return err
			}
			info, err := directory.root.Stat(relative)
			if err != nil {
				return err
			}
			if info.IsDir() {
				if err := walk(directory, relative, depth+1); err != nil {
					return err
				}
			} else if strings.HasSuffix(child, ".proto") && !seenInputs[relative] {
				if len(inputs) == limits.Files {
					return budget.refusal(stage, "files", uint64(len(inputs)), 1, uint64(limits.Files))
				}
				seenInputs[relative] = true
				inputs = append(inputs, relative)
			}
		}
		return nil
	}
	for _, configured := range roots {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		absolute, err := filepath.Abs(configured)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return nil, err
		}
		base, name := absolute, "."
		if !info.IsDir() {
			base, name = filepath.Dir(absolute), filepath.Base(absolute)
		}
		base, err = filepath.EvalSymlinks(base)
		if err != nil {
			return nil, err
		}
		opened, err := os.OpenRoot(base)
		if err != nil {
			return nil, err
		}
		directory := schemaSourceRoot{root: opened, path: base}
		directories = append(directories, directory)
		if info.IsDir() {
			if err := walk(directory, ".", 1); err != nil {
				return nil, err
			}
		} else if !seenInputs[name] {
			seenInputs[name] = true
			inputs = append(inputs, name)
		}
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no protobuf definitions found")
	}
	sources := map[string]protocompile.SearchResult{}
	dependencies := map[string][]string{}
	states, heights := map[string]byte{}, map[string]int{}
	standard := protocompile.WithStandardImports(protocompile.ResolverFunc(func(string) (protocompile.SearchResult, error) {
		return protocompile.SearchResult{}, protoregistry.NotFound
	}))
	var total uint64
	var load func(string, int) (int, error)
	load = func(name string, depth int) (int, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if depth > limits.Depth {
			return 0, budget.refusal(stage, "import depth", 0, uint64(depth), uint64(limits.Depth))
		}
		if states[name] == 1 {
			return 0, fmt.Errorf("protobuf import cycle")
		}
		if states[name] == 2 {
			if depth+heights[name]-1 > limits.Depth {
				return 0, budget.refusal(stage, "import depth", 0, uint64(depth+heights[name]-1), uint64(limits.Depth))
			}
			return heights[name], nil
		}
		if !fs.ValidPath(name) || strings.ContainsRune(name, '\\') {
			return 0, fmt.Errorf("invalid protobuf import path")
		}
		var file *os.File
		for _, directory := range directories {
			canonical, err := directory.canonical(name)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return 0, err
			}
			candidate, err := directory.root.Open(canonical)
			if err == nil {
				file = candidate
				break
			}
			if !errors.Is(err, fs.ErrNotExist) {
				return 0, err
			}
		}
		if file == nil {
			result, err := standard.FindFileByPath(name)
			if err != nil {
				return 0, fmt.Errorf("protobuf import not found: %s", name)
			}
			sources[name] = result
			states[name], heights[name] = 2, 1
			return 1, nil
		}
		defer func() { _ = file.Close() }()
		if len(dependencies) >= limits.Files {
			return 0, budget.refusal(stage, "files", uint64(len(dependencies)), 1, uint64(limits.Files))
		}
		info, err := file.Stat()
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() {
			return 0, fmt.Errorf("protobuf source is not a regular file")
		}
		if info.Size() < 0 || uint64(info.Size()) > limits.FileBytes {
			return 0, budget.refusal(stage, "file bytes", 0, uint64(info.Size()), limits.FileBytes)
		}
		if total > limits.TotalBytes || uint64(info.Size()) > limits.TotalBytes-total {
			return 0, budget.refusal(stage, "total bytes", total, uint64(info.Size()), limits.TotalBytes)
		}
		// The extra byte detects a file that grows after Stat without reading it unboundedly.
		if err := budget.chargeMaterialization(stage, uint64(info.Size())+1); err != nil {
			return 0, err
		}
		data, err := io.ReadAll(io.LimitReader(file, info.Size()+1))
		if err != nil {
			return 0, err
		}
		if int64(len(data)) != info.Size() {
			return 0, fmt.Errorf("protobuf source changed while reading")
		}
		total += uint64(len(data))
		handler := reporter.NewHandler(nil)
		ast, err := parser.Parse(name, bytes.NewReader(data), handler)
		if err != nil {
			return 0, fmt.Errorf("parse protobuf definitions: %w", err)
		}
		result, err := parser.ResultFromAST(ast, true, handler)
		if err != nil {
			return 0, fmt.Errorf("parse protobuf definitions: %w", err)
		}
		sources[name] = protocompile.SearchResult{ParseResult: result}
		dependencies[name] = result.FileDescriptorProto().GetDependency()
		states[name] = 1
		height := 1
		for _, dependency := range dependencies[name] {
			if err := budget.chargeNodes(stage, 1); err != nil {
				return 0, err
			}
			child, err := load(dependency, depth+1)
			if err != nil {
				return 0, err
			}
			height = max(height, child+1)
		}
		states[name], heights[name] = 2, height
		return height, nil
	}
	for _, name := range inputs {
		if _, err := load(name, 1); err != nil {
			return nil, err
		}
	}
	compiler := protocompile.Compiler{MaxParallelism: 1, Resolver: protocompile.ResolverFunc(func(name string) (protocompile.SearchResult, error) {
		result, ok := sources[name]
		if !ok {
			return protocompile.SearchResult{}, protoregistry.NotFound
		}
		return result, nil
	})}
	compiled, err := compiler.Compile(ctx, inputs...)
	if err != nil {
		return nil, fmt.Errorf("compile protobuf definitions: %w", err)
	}
	files := make([]protoreflect.FileDescriptor, len(compiled))
	for i, file := range compiled {
		files[i] = file
	}
	return &protobufSchema{files: files}, nil
}

func (s *protobufSchema) messageDescriptor(requestPath string, isResponse bool) (protoreflect.MessageDescriptor, error) {
	if !strings.ContainsRune(requestPath, '?') {
		servicePath, methodName, found := strings.Cut(strings.TrimLeft(requestPath, "/"), "/")
		if found && !strings.ContainsRune(methodName, '/') {
			packageName, serviceName, qualified := strings.CutLast(servicePath, ".")
			if !qualified {
				packageName, serviceName = "", servicePath
			}
			for _, file := range s.files {
				if string(file.Package()) != packageName {
					continue
				}
				if service := file.Services().ByName(protoreflect.Name(serviceName)); service != nil {
					if method := service.Methods().ByName(protoreflect.Name(methodName)); method != nil {
						if isResponse {
							return method.Output(), nil
						}
						return method.Input(), nil
					}
				}
				if message := file.Messages().ByName(protoreflect.Name(methodName)); message != nil {
					return message, nil
				}
			}
		}
	}
	if len(s.files) != 0 {
		file := s.files[0]
		if file.Services().Len() != 0 && file.Services().Get(0).Methods().Len() != 0 {
			method := file.Services().Get(0).Methods().Get(0)
			if isResponse {
				return method.Output(), nil
			}
			return method.Input(), nil
		}
		if file.Messages().Len() != 0 {
			return file.Messages().Get(0), nil
		}
	}
	return nil, fmt.Errorf("no protobuf message definition")
}

func (s *protobufSchema) newMessage(requestPath string, isResponse bool) (*dynamicpb.Message, error) {
	descriptor, err := s.messageDescriptor(requestPath, isResponse)
	if err != nil {
		return nil, err
	}
	return dynamicpb.NewMessage(descriptor), nil
}
