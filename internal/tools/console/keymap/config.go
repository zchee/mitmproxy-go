// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package keymap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	yaml "go.yaml.in/yaml/v4"
	"go.yaml.in/yaml/v4/plugin/limit"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
)

// MaxInputBytes bounds key configuration before node graph allocation.
const (
	MaxInputBytes = 1 << 20
	maxNodes      = 65_536
	maxBindings   = 4_096
	maxDepth      = 32
)

// Config registers loading through the frontend's asynchronous effect admission.
// Submit must enqueue work without file I/O or waiting under dispatch.
type Config struct {
	Submit func(context.Context, string) error
}

// Load registers the separate keymap-load command with its source signature.
func (c *Config) Load(_ context.Context, loader *addon.Loader) error {
	if c.Submit == nil {
		return errors.New("keymap configuration requires an asynchronous submitter")
	}
	return loader.AddCommand("console.keymap.load", func(ctx context.Context, path command.Path) error { return c.Submit(ctx, string(path)) }, command.WithHelp("Load key bindings from a file."), command.WithParams("path"))
}

// DefaultPath resolves the startup keymap location under the configured directory.
func DefaultPath(confdir string) string { return filepath.Join(expandHome(confdir), "keys.yaml") }

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

// ReadPath reads and validates a keymap outside dispatch. Missing and nonregular
// paths return present=false without error; a bad present file leaves the map unchanged.
func ReadPath(path string) (bindings []Binding, present bool, err error) {
	path = expandHome(path)
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, nil
	}
	if info.Size() > MaxInputBytes {
		return nil, true, fmt.Errorf("key binding config exceeds %d bytes", MaxInputBytes)
	}
	f, err := os.Open(path) //nolint:gosec // The operator explicitly selects this keymap file.
	if err != nil {
		return nil, true, err
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxInputBytes+1))
	err = errors.Join(err, f.Close())
	if err != nil {
		return nil, true, err
	}
	bindings, err = Parse(data)
	if err == nil {
		for _, binding := range bindings {
			if failure := validate(binding.Contexts); failure != nil {
				err = failure
				break
			}
		}
	}
	if err != nil {
		return nil, true, fmt.Errorf("Error reading %s: %w", path, err) //nolint:staticcheck // Preserve upstream's load error prefix.
	}
	return bindings, true, nil
}

type weight struct {
	nodes, height int
	active        bool
}
type frame struct {
	weight
	anchor string
	kind   yaml.NativeEventKind
}

func preflight(data []byte) error {
	if len(data) > MaxInputBytes {
		return fmt.Errorf("key binding config exceeds %d bytes", MaxInputBytes)
	}
	if !utf8.Valid(data) {
		return errors.New("Encoding error - expected UTF8") //nolint:staticcheck // Preserve upstream's encoding error prefix.
	}
	anchors := make(map[string]weight)
	var stack []frame
	nodes, entries, documents := 0, 0, 0
	add := func(n, height int) error {
		if n > maxNodes-nodes {
			return fmt.Errorf("key binding config exceeds %d expanded nodes", maxNodes)
		}
		nodes += n
		if len(stack) > 0 {
			p := &stack[len(stack)-1]
			p.nodes += n
			p.height = max(p.height, height+1)
		}
		return nil
	}
	return yaml.ScanNativeEvents(bytes.NewReader(data), func(e yaml.NativeEvent) error {
		switch e.Kind {
		case yaml.NativeStreamStart, yaml.NativeStreamEnd, yaml.NativeTailComment:
			return nil
		case yaml.NativeDocumentStart:
			documents++
			if documents > 1 {
				return errors.New("expected one key binding document")
			}
			return nil
		case yaml.NativeDocumentEnd:
			return nil
		case yaml.NativeMappingEnd, yaml.NativeSequenceEnd:
			if len(stack) == 0 {
				return errors.New("unmatched YAML collection")
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if f.anchor != "" {
				anchors[f.anchor] = weight{nodes: f.nodes, height: f.height}
			}
			if len(stack) > 0 {
				p := &stack[len(stack)-1]
				p.nodes += f.nodes - 1
				p.height = max(p.height, f.height+1)
			}
			return nil
		case yaml.NativeAlias, yaml.NativeScalar, yaml.NativeMappingStart, yaml.NativeSequenceStart:
			if len(stack) == 1 && stack[0].kind == yaml.NativeSequenceStart {
				entries++
				if entries > maxBindings {
					return fmt.Errorf("key binding config exceeds %d entries", maxBindings)
				}
			}
		default:
			return errors.New("unsupported YAML event")
		}
		if e.Kind == yaml.NativeAlias {
			w, ok := anchors[string(e.Anchor)]
			if !ok || w.active {
				return errors.New("undefined or cyclic YAML alias")
			}
			if len(stack)+w.height > maxDepth {
				return errors.New("key binding nesting exceeds 32")
			}
			return add(w.nodes, w.height)
		}
		if err := add(1, 0); err != nil {
			return err
		}
		anchor := string(e.Anchor)
		if e.Kind == yaml.NativeScalar {
			if anchor != "" {
				anchors[anchor] = weight{nodes: 1}
			}
			return nil
		}
		if len(stack) >= maxDepth {
			return errors.New("key binding nesting exceeds 32")
		}
		if anchor != "" {
			anchors[anchor] = weight{active: true}
		}
		stack = append(stack, frame{nodes: 1, height: 1, anchor: anchor, kind: e.Kind})
		return nil
	}, yaml.WithPlugin(limit.New(limit.DepthValue(maxDepth))))
}

// Parse validates budgets using native events before decoding the node graph once.
func Parse(data []byte) ([]Binding, error) {
	if err := preflight(data); err != nil {
		return nil, err
	}
	loader, err := yaml.NewLoader(bytes.NewReader(data), yaml.WithPlugin(limit.New(limit.DepthValue(maxDepth), limit.AliasNone())))
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := loader.Load(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, nil
	}
	root := resolve(doc.Content[0])
	if root.Tag == "!!null" {
		return nil, nil
	}
	if root.Kind != yaml.SequenceNode {
		return nil, nodeError(root, "Invalid keybinding config - expected a list of keys")
	}
	bindings := make([]Binding, 0, len(root.Content))
	for _, n := range root.Content {
		n = resolve(n)
		if n.Kind != yaml.MappingNode {
			return nil, nodeError(n, "expected a key binding mapping")
		}
		b := Binding{Contexts: []string{"global"}}
		seen := make(map[string]bool)
		for i := 0; i < len(n.Content); i += 2 {
			key, value := resolve(n.Content[i]), resolve(n.Content[i+1])
			if key.Tag != "!!str" || seen[key.Value] {
				return nil, nodeError(key, "invalid or duplicate key attribute")
			}
			seen[key.Value] = true
			switch key.Value {
			case "key", "cmd", "help":
				if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
					return nil, nodeError(value, "Invalid type for "+key.Value)
				}
				switch key.Value {
				case "key":
					b.Key = value.Value
				case "cmd":
					b.Command = value.Value
				case "help":
					b.Help = value.Value
				}
			case "ctx":
				if value.Kind != yaml.SequenceNode {
					return nil, nodeError(value, "Invalid type for ctx")
				}
				b.Contexts = nil
				for _, v := range value.Content {
					v = resolve(v)
					if v.Kind != yaml.ScalarNode || v.Tag != "!!str" {
						return nil, nodeError(v, "expected a context string")
					}
					b.Contexts = append(b.Contexts, v.Value)
				}
			default:
				return nil, nodeError(key, "Unknown key attributes: "+key.Value)
			}
		}
		if !seen["key"] || !seen["cmd"] {
			return nil, nodeError(n, "Missing required key attributes: key, cmd")
		}
		bindings = append(bindings, b)
	}
	return bindings, nil
}

func resolve(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func nodeError(n *yaml.Node, message string) error {
	return fmt.Errorf("Key binding config error at line %d, column %d: %s", n.Line, n.Column, message) //nolint:staticcheck // Preserve upstream's parse error prefix.
}
