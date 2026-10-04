// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package options

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	yaml "go.yaml.in/yaml/v4"

	"github.com/zchee/mitmproxy-go/omap"
)

// parse is mitmproxy's optmanager.parse: it decodes a YAML configuration
// document into an insertion-ordered mapping. Empty and comment-only
// documents yield an empty mapping; a document that is not a mapping is an
// [*OptionsError].
func parse(text string) (*omap.Map[any], error) {
	data := omap.New[any]()
	if text == "" {
		return data, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, configError(text, err)
	}
	root := &doc
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return data, nil
		}
		root = root.Content[0]
	}
	switch {
	case root.Kind == 0:
		return data, nil
	case root.Kind == yaml.ScalarNode && root.ShortTag() == "!!null":
		return data, nil
	case root.Kind != yaml.MappingNode:
		return nil, Errorf("Config error - no keys found.")
	}

	// Decode the values through a Go map so that aliases and merge keys
	// resolve, and take the key order from the node tree.
	var values map[string]any
	if err := root.Decode(&values); err != nil {
		return nil, Errorf("Config error - %v", err)
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		k := root.Content[i].Value
		if v, ok := values[k]; ok && !data.Has(k) {
			data.Set(k, v)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(values)) {
		if !data.Has(k) {
			data.Set(k, values[k])
		}
	}
	return data, nil
}

// configError renders a YAML syntax error the way mitmproxy reports one:
// the line number, a snippet with a caret under the error column, and the
// problem description.
func configError(text string, err error) error {
	le, ok := errors.AsType[*yaml.LoadError](err)
	if !ok || le.Mark.Line <= 0 {
		return &OptionsError{Msg: "Could not parse options.", Err: err}
	}
	var snippet string
	if lines := strings.Split(text, "\n"); le.Mark.Line <= len(lines) {
		col := max(le.Mark.Column-1, 0)
		snippet = "    " + lines[le.Mark.Line-1] + "\n    " + strings.Repeat(" ", col) + "^"
	}
	return &OptionsError{
		Msg: fmt.Sprintf("Config error at line %d:\n%s\n%s", le.Mark.Line, snippet, le.Message),
		Err: err,
	}
}

// Load applies a YAML configuration document, overwriting values already
// set. Keys naming options that are not registered are deferred (see
// [Manager.ProcessDeferred]). Load returns an [*OptionsError] when the
// document is invalid.
func (m *Manager) Load(ctx context.Context, text string) error { return m.load(ctx, text, "") }

func (m *Manager) load(ctx context.Context, text, cwd string) error {
	data, err := parse(text)
	if err != nil {
		return err
	}
	if scripts, ok := data.Get("scripts"); ok && scripts != nil && cwd != "" {
		// Script paths in a configuration file are relative to that file,
		// not to the working directory.
		if list, ok := scripts.([]any); ok {
			resolved := make([]any, len(list))
			for i, p := range list {
				s, ok := p.(string)
				if !ok {
					return &TypeError{Name: "scripts", Type: TypeSeq, Value: scripts}
				}
				resolved[i] = relativePath(s, cwd)
			}
			data.Set("scripts", resolved)
		}
	}
	values := maps.Collect(data.All())
	return m.UpdateDeferred(ctx, values)
}

// LoadPaths loads configuration files in order, each taking precedence over
// the previous one. A leading "~" is expanded; paths that do not exist or
// are not regular files are skipped. A file that is not valid UTF-8 or not
// valid configuration yields an [*OptionsError] naming the file.
func (m *Manager) LoadPaths(ctx context.Context, paths ...string) error {
	for _, p := range paths {
		p = expandUser(p)
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		b, err := os.ReadFile(p) //nolint:gosec // Reading the configuration file the caller names is the point.
		if err != nil {
			return err
		}
		if err := checkUTF8(b); err != nil {
			return &OptionsError{Msg: fmt.Sprintf("Error reading %s: %v", p, err), Err: err}
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return err
		}
		if err := m.load(ctx, string(b), filepath.Dir(abs)); err != nil {
			if oe, ok := errors.AsType[*OptionsError](err); ok {
				return &OptionsError{Msg: fmt.Sprintf("Error reading %s: %v", p, oe), Err: err}
			}
			return err
		}
	}
	return nil
}

// checkUTF8 reports the first invalid byte the way Python's UnicodeDecodeError
// does.
func checkUTF8(b []byte) error {
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size <= 1 {
			return fmt.Errorf("'utf-8' codec can't decode byte 0x%02x in position %d: invalid start byte", b[i], i)
		}
		i += size
	}
	return nil
}

// Serialize renders the options as YAML. text is a previous serialization
// that is updated in place: its keys keep their order and, unless defaults
// is true, its values for options still at their default are kept. Options
// with non-default values (all options, when defaults is true) are written;
// keys that do not name a registered option are dropped. Serialize returns
// an [*OptionsError] when text is invalid.
func (m *Manager) Serialize(text string, defaults bool) (string, error) {
	data, err := parse(text)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	for k, o := range m.opts.All() {
		if defaults || !equalValues(o.current(), o.def) {
			data.Set(k, copyValue(o.current()))
		}
	}
	for _, k := range data.Keys() {
		if !m.opts.Has(k) {
			data.Delete(k)
		}
	}
	m.mu.Unlock()

	doc := &yaml.Node{Kind: yaml.MappingNode}
	for k, v := range data.All() {
		doc.Content = append(doc.Content, strNode(k), valueNode(v))
	}
	b, err := yaml.Dump(doc, yaml.WithV4Defaults())
	return string(b), err
}

// Save writes the options to path with [Manager.Serialize], updating the
// file in place when it exists. Unlike upstream, which creates the file with
// the default mode, a new file is readable by its owner only.
func (m *Manager) Save(path string, defaults bool) error {
	path = expandUser(path)
	var text string
	if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
		b, err := os.ReadFile(path) //nolint:gosec // Updating the configuration file the caller names is the point.
		if err != nil {
			return err
		}
		if err := checkUTF8(b); err != nil {
			return &OptionsError{Msg: fmt.Sprintf("Error trying to modify %s: %v", path, err), Err: err}
		}
		text = string(b)
	}
	out, err := m.Serialize(text, defaults)
	if err != nil {
		return err
	}
	// A new file is created readable by its owner only, since it may hold
	// cert_passphrase; an existing file keeps its permissions.
	return os.WriteFile(path, []byte(out), 0o600)
}

// Dump renders every option with its default value as an annotated YAML
// document, sorted by name, each option preceded by its help text, its
// valid values or its type as a comment (mitmproxy's dump_defaults, the
// output of "--options").
func (m *Manager) Dump() (string, error) {
	items := m.Items()
	slices.SortFunc(items, func(a, b Option) int { return strings.Compare(a.name, b.name) })
	var out strings.Builder
	for _, o := range items {
		txt := strings.TrimSpace(o.help)
		if len(o.choices) > 0 {
			reprs := make([]string, len(o.choices))
			for i, c := range o.choices {
				reprs[i] = pyRepr(c)
			}
			txt += fmt.Sprintf(" Valid values are %s.", strings.Join(reprs, ", "))
		} else {
			txt += fmt.Sprintf(" Type %s.", o.typ)
		}
		key := strNode(o.name)
		if lines := wrap(txt); len(lines) > 0 {
			key.HeadComment = "# " + strings.Join(lines, "\n# ")
		}
		doc := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{key, valueNode(o.def)}}
		b, err := yaml.Dump(doc, yaml.WithV4Defaults())
		if err != nil {
			return "", err
		}
		out.WriteByte('\n')
		out.Write(b)
	}
	return out.String(), nil
}

func strNode(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}

// valueNode builds the YAML node for an option value, or for a value decoded
// from a configuration file. Strings are left unstyled so that the emitter
// quotes them only where needed, and null is written as an empty value, as
// ruamel.yaml writes it.
func valueNode(v any) *yaml.Node {
	switch x := v.(type) {
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null"}
	case string:
		return strNode(x)
	case *string:
		if x == nil {
			return valueNode(nil)
		}
		return strNode(*x)
	case *int:
		if x == nil {
			return valueNode(nil)
		}
		return valueNode(*x)
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(x)}
	case int:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(x)}
	case []string:
		n := &yaml.Node{Kind: yaml.SequenceNode}
		for _, s := range x {
			n.Content = append(n.Content, strNode(s))
		}
		if len(x) == 0 {
			n.Style = yaml.FlowStyle
		}
		return n
	case []any:
		n := &yaml.Node{Kind: yaml.SequenceNode}
		for _, e := range x {
			n.Content = append(n.Content, valueNode(e))
		}
		if len(x) == 0 {
			n.Style = yaml.FlowStyle
		}
		return n
	case map[string]any:
		n := &yaml.Node{Kind: yaml.MappingNode}
		for _, k := range slices.Sorted(maps.Keys(x)) {
			n.Content = append(n.Content, strNode(k), valueNode(x[k]))
		}
		if len(x) == 0 {
			n.Style = yaml.FlowStyle
		}
		return n
	}
	n := &yaml.Node{}
	if err := n.Encode(v); err != nil {
		return strNode(fmt.Sprint(v))
	}
	return n
}

// expandUser is Python's os.path.expanduser: a leading "~" or "~user" is
// replaced by the home directory; the path is returned unchanged when the
// home directory cannot be determined.
func expandUser(p string) string {
	if !strings.HasPrefix(p, "~") {
		return p
	}
	i := strings.IndexFunc(p, isPathSeparator)
	if i < 0 {
		i = len(p)
	}
	var home string
	if i == 1 {
		h, err := os.UserHomeDir()
		if err != nil {
			return p
		}
		home = h
	} else {
		u, err := user.Lookup(p[1:i])
		if err != nil {
			return p
		}
		home = u.HomeDir
	}
	return strings.TrimRightFunc(home, isPathSeparator) + p[i:]
}

func isPathSeparator(r rune) bool { return r < 0x80 && os.IsPathSeparator(uint8(r)) }

// relativePath is mitmproxy's optmanager.relative_path: a script path found
// in a configuration file is made absolute relative to the directory of that
// file. Like Python's pathlib, it joins without resolving ".." components.
func relativePath(script, relativeTo string) string {
	if exp := expandUser(script); exp != script && !filepath.IsAbs(script) {
		script = pyAbsolute(exp)
	}
	return pyAbsolute(pyJoin(relativeTo, expandUser(script)))
}

// pyJoin joins b onto a the way pathlib's "/" operator does: an absolute b
// replaces a. On Windows, where a path can have a drive without a root
// ("C:x") or a root without a drive (`\x`), it follows ntpath.join: a b on
// another drive replaces a, a b on the same drive is joined onto a's
// directory, and a rooted b keeps only a's drive.
func pyJoin(a, b string) string {
	if filepath.IsAbs(b) {
		return pyNormalize(b)
	}
	volA, volB := filepath.VolumeName(a), filepath.VolumeName(b)
	switch {
	case volB != "" && !strings.EqualFold(volA, volB):
		return pyNormalize(b)
	case volB != "":
		return pyNormalize(volB + a[len(volA):] + string(filepath.Separator) + b[len(volB):])
	case isRooted(b):
		return pyNormalize(volA + b)
	}
	return pyNormalize(a + string(filepath.Separator) + b)
}

// pyAbsolute is pathlib's Path.absolute: it prefixes the working directory
// to a relative path without normalising "..". On Windows a rooted path
// without a drive gets the working directory's drive, and a path with a
// drive but no root is resolved against that drive's working directory.
func pyAbsolute(p string) string {
	if filepath.IsAbs(p) {
		return pyNormalize(p)
	}
	if vol := filepath.VolumeName(p); vol != "" {
		// filepath.Abs of a bare drive asks the system for the working
		// directory of that drive, as os.path.abspath does.
		base, err := filepath.Abs(vol)
		if err != nil {
			return pyNormalize(p)
		}
		return pyNormalize(base + string(filepath.Separator) + p[len(vol):])
	}
	wd, err := os.Getwd()
	if err != nil {
		return pyNormalize(p)
	}
	if isRooted(p) {
		return pyNormalize(filepath.VolumeName(wd) + p)
	}
	return pyNormalize(wd + string(filepath.Separator) + p)
}

// isRooted reports whether p starts with a path separator. Such a path is
// absolute on POSIX but not on Windows, where it has no drive.
func isRooted(p string) bool { return p != "" && os.IsPathSeparator(p[0]) }

// pyNormalize applies pathlib's lexical normalisation: repeated separators
// and "." components are removed, ".." components are kept.
func pyNormalize(p string) string {
	sep := string(filepath.Separator)
	p = filepath.FromSlash(p)
	vol := filepath.VolumeName(p)
	rest := p[len(vol):]
	rooted := strings.HasPrefix(rest, sep)
	var parts []string
	for part := range strings.SplitSeq(rest, sep) {
		if part != "" && part != "." {
			parts = append(parts, part)
		}
	}
	joined := strings.Join(parts, sep)
	switch {
	case rooted:
		return vol + sep + joined
	case joined == "" && vol == "":
		return "."
	default:
		return vol + joined
	}
}
