// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package maplocal serves matching HTTP requests from local files or directories.
package maplocal

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/filter/regex"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/internal/spec"
	"github.com/zchee/mitmproxy-go/internal/version"
	"github.com/zchee/mitmproxy-go/options"
)

const maxFileBytes = 64 << 20

type mapping struct {
	matches   filter.Expr
	pattern   *regex.Pattern
	localPath string
}

// MapLocal serves the first matching readable file and otherwise emits 404 when
// candidate paths exist. Files are reread per request, bounded to 64 MiB and
// confined with os.Root. Only regular files are served. Shared state belongs to
// addon dispatch; patterns inherit filter/regex's resource bounds.
type MapLocal struct {
	options      *options.Manager
	replacements []mapping
}

// New returns a local file mapper using opts.
func New(opts *options.Manager) *MapLocal { return &MapLocal{options: opts} }

// Name returns the upstream addon name.
func (*MapLocal) Name() string { return "maplocal" }

// Load registers the upstream map_local option.
func (*MapLocal) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "map_local", options.TypeSeq, []string{}, `Map remote resources to a local file using a pattern of the form "[/flow-filter]/url-regex/file-or-directory-path", where the separator can be any character.`)
}

// Configure validates expressions and resolves existing local paths.
func (m *MapLocal) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, changed := updated["map_local"]; !changed {
		return nil
	}
	m.replacements = nil
	for _, option := range m.options.Seq("map_local") {
		r, err := parse(option)
		if err != nil {
			return options.Errorf("Cannot parse map_local option %s: %v", option, err)
		}
		m.replacements = append(m.replacements, r)
	}
	return nil
}

func parse(option string) (mapping, error) {
	matches, subject, path, err := spec.Parse(option)
	if err != nil {
		return mapping{}, err
	}
	pattern, err := regex.CompilePattern(subject, regex.Unicode)
	if err != nil {
		return mapping{}, fmt.Errorf("Invalid regular expression %s (%v)", pyrepr.Str(subject), err) //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
	}
	original := path
	if strings.HasPrefix(path, "~") {
		owner, suffix, _ := strings.Cut(path[1:], "/")
		home := ""
		if owner == "" {
			home, err = os.UserHomeDir()
		} else {
			var account *user.User
			account, err = user.Lookup(owner)
			if err == nil {
				home = account.HomeDir
			}
		}
		if err != nil {
			return mapping{}, fmt.Errorf("Invalid file path: %s (%v)", original, err) //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
		}
		path = filepath.Join(home, suffix)
	}
	path, err = filepath.Abs(path)
	if err == nil {
		path, err = filepath.EvalSymlinks(path)
	}
	if err != nil {
		return mapping{}, fmt.Errorf("Invalid file path: %s (%v)", original, err) //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
	}
	return mapping{matches: matches, pattern: pattern, localPath: path}, nil
}

func fileCandidates(url string, s mapping) ([]string, error) {
	match, err := s.pattern.SearchString(url)
	if err != nil || match == nil {
		return nil, err
	}
	suffix := ""
	if len(match.Groups) > 1 {
		suffix = string(match.Groups[1])
	} else {
		suffix = url[match.Spans[0][1]:]
		suffix, _, _ = strings.Cut(suffix, "?")
		suffix = strings.Trim(suffix, "/")
	}
	if suffix == "" {
		return []string{filepath.Join(s.localPath, "index.html")}, nil
	}
	// Python unquote keeps malformed percent escapes and replaces invalid UTF-8.
	decoded := make([]byte, 0, len(suffix))
	var b [1]byte
	for i := 0; i < len(suffix); i++ {
		if suffix[i] == '%' && i+2 < len(suffix) {
			if _, err := hex.Decode(b[:], []byte(suffix[i+1:i+3])); err == nil {
				decoded = append(decoded, b[0])
				i += 2
				continue
			}
		}
		decoded = append(decoded, suffix[i])
	}
	decodedSuffix := strings.Map(func(r rune) rune { return r }, string(decoded))
	escaped := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || strings.ContainsRune("-_.=(),/", r) {
			return r
		}
		return '_'
	}, decodedSuffix)
	suffixes := []string{decodedSuffix, decodedSuffix + "/index.html"}
	if escaped != decodedSuffix {
		suffixes = append(suffixes, escaped, escaped+"/index.html")
	}
	candidates := make([]string, 0, len(suffixes))
	for _, suffix := range suffixes {
		path := filepath.FromSlash(suffix)
		if !filepath.IsLocal(path) || strings.IndexByte(path, 0) >= 0 {
			return nil, nil
		}
		for part := range strings.SplitSeq(path, string(filepath.Separator)) {
			if part == ".." {
				return nil, nil
			}
		}
		candidates = append(candidates, filepath.Join(s.localPath, path))
	}
	return candidates, nil
}

// Request serves the first matching rule's file unless already answered or failed.
// Unsafe paths produce no candidates and pass through; safe missing candidates
// produce an empty 404 response.
func (m *MapLocal) Request(ctx context.Context, f *flow.HTTPFlow) error {
	if f.Response != nil || f.Error != nil || !f.Live {
		return nil
	}
	url := f.Request.PrettyURL()
	var allCandidates []string
	for _, s := range m.replacements {
		if !filter.Match(s.matches, f) {
			continue
		}
		match, err := s.pattern.SearchString(url)
		if err != nil {
			return fmt.Errorf("maplocal: cannot match URL: %w", err)
		}
		if match == nil {
			continue
		}
		var candidates []string
		root := s.localPath
		if info, err := os.Stat(s.localPath); err == nil && info.Mode().IsRegular() {
			candidates = []string{s.localPath}
			root = filepath.Dir(s.localPath)
		} else {
			candidates, err = fileCandidates(url, s)
			if err != nil {
				return err
			}
		}
		allCandidates = append(allCandidates, candidates...)
		if len(candidates) == 0 {
			continue
		}
		contents, file, err := readCandidates(root, candidates)
		if err != nil {
			slog.WarnContext(ctx, fmt.Sprintf("Could not read file: %v", err))
			continue
		}
		if file == "" {
			continue
		}
		headers := httpmsg.Headers{{Name: []byte("Server"), Value: []byte(version.String())}}
		if typ := mime.TypeByExtension(filepath.Ext(file)); typ != "" {
			headers.Set("Content-Type", typ)
		}
		response, err := httpmsg.MakeResponse(200, contents, headers)
		if err != nil {
			return err
		}
		f.Response = response
		return nil
	}
	if len(allCandidates) > 0 {
		response, err := httpmsg.MakeResponse(404, []byte{}, httpmsg.Headers{})
		if err != nil {
			return err
		}
		f.Response = response
		slog.InfoContext(ctx, "None of the local file candidates exist: "+strings.Join(allCandidates, ", "))
	}
	return nil
}

func readCandidates(dir string, candidates []string) (contents []byte, file string, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if closeErr := root.Close(); err == nil {
			err = closeErr
		}
	}()
	for _, candidate := range candidates {
		name, err := filepath.Rel(dir, candidate)
		if err != nil {
			return nil, "", err
		}
		info, err := root.Stat(name)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if info.Size() > maxFileBytes {
			return nil, candidate, fmt.Errorf("local file exceeds %d bytes", maxFileBytes)
		}
		handle, err := root.Open(name)
		if err != nil {
			return nil, candidate, err
		}
		info, statErr := handle.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			closeErr := handle.Close()
			if statErr != nil {
				return nil, candidate, statErr
			}
			if closeErr != nil {
				return nil, candidate, closeErr
			}
			return nil, candidate, fmt.Errorf("local file is not regular")
		}
		data, readErr := io.ReadAll(io.LimitReader(handle, maxFileBytes+1))
		closeErr := handle.Close()
		if readErr != nil {
			return nil, candidate, readErr
		}
		if closeErr != nil {
			return nil, candidate, closeErr
		}
		if len(data) > maxFileBytes {
			return nil, candidate, fmt.Errorf("local file exceeds %d bytes", maxFileBytes)
		}
		return data, candidate, nil
	}
	return nil, "", nil
}

var (
	_ addon.LoadHandler      = (*MapLocal)(nil)
	_ addon.ConfigureHandler = (*MapLocal)(nil)
	_ addon.RequestHandler   = (*MapLocal)(nil)
)
