// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package releasetest builds owned executable and source fixtures for release tests.
package releasetest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	json "encoding/json/v2"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

const (
	// Tag is the validated version embedded in the fixture executables.
	Tag        = "v1.2.3"
	modulePath = "github.com/zchee/mitmproxy-go"
)

// Family contains immutable owned source, archive and executable fixture bytes.
// Callers must clone bytes before mutating them.
type Family struct {
	Root, Commit, Tree, GoVersion string
	Toolchain, ToolVersion        string
	// PlainGoVersion comes from the repository go directive, not host or artifact metadata.
	PlainGoVersion string
	Environment    []string
	Files          map[string][]byte
	Members        map[string][]byte
	License        []byte
}

type executable struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	BuildInfo string `json:"build_info"`
}

var cache = struct {
	sync.Mutex
	families map[bool]*Family
}{families: make(map[bool]*Family)}

// Load builds a real six-target family once per experiment profile and process.
// It fails the test if a fixture command cannot complete.
func Load(t *testing.T, experimental bool) *Family {
	t.Helper()
	cache.Lock()
	defer cache.Unlock()
	if family := cache.families[experimental]; family != nil {
		return family
	}
	family, err := build(t.Context(), experimental)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture driver=%s selected_version=%s expected_plain=%q env_overrides=%q (GOEXPERIMENT unset unless listed); no module dependencies", family.Toolchain, family.ToolVersion, family.PlainGoVersion, family.Environment)
	cache.families[experimental] = family
	return family
}

// Cleanup removes cached source checkouts after the package's tests finish.
func Cleanup() {
	for _, family := range cache.families {
		_ = os.RemoveAll(filepath.Dir(family.Root))
	}
}

func command(ctx context.Context, dir string, environment []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // Private test fixture callers pass only git or the test process's absolute Go toolchain, without a shell.
	cmd.Dir = dir
	cmd.Env = environment
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("fixture %s %q: %w\n%s\n%s", name, args, err, output, stderr.Bytes())
	}
	return bytes.TrimSpace(output), nil
}

func build(ctx context.Context, experimental bool) (_ *Family, err error) {
	work, err := os.MkdirTemp("", "releasecheck-fixture-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(work)
		}
	}()
	family := &Family{Root: filepath.Join(work, "source"), Files: make(map[string][]byte), Members: make(map[string][]byte), License: []byte("owned release fixture license\n")}
	if err := os.Mkdir(family.Root, 0o700); err != nil {
		return nil, err
	}
	family.Toolchain = filepath.Join(runtime.GOROOT(), "bin", "go") //nolint:staticcheck // The local test-process driver selects the repository's toolchain explicitly, never an arbitrary PATH binary.
	if runtime.GOOS == "windows" {
		family.Toolchain += ".exe"
	}
	inherited := slices.DeleteFunc(os.Environ(), func(value string) bool {
		key, _, _ := strings.Cut(value, "=")
		return slices.Contains([]string{"GOENV", "GOTOOLCHAIN", "GOFLAGS", "GOEXPERIMENT", "GOWORK", "GOOS", "GOARCH", "CGO_ENABLED"}, key)
	})
	bootstrap := append(slices.Clone(inherited), "GOENV=off", "GOTOOLCHAIN=local", "GOFLAGS=", "GOWORK=off")
	goModPath, err := command(ctx, "", bootstrap, family.Toolchain, "env", "GOMOD")
	if err != nil {
		return nil, err
	}
	goMod, err := os.ReadFile(string(goModPath))
	if err != nil {
		return nil, fmt.Errorf("read repository go.mod: %w", err)
	}
	for line := range strings.SplitSeq(string(goMod), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "go" {
			family.PlainGoVersion = "go" + fields[1]
			break
		}
	}
	if family.PlainGoVersion == "" {
		return nil, fmt.Errorf("repository go.mod has no go directive")
	}
	family.Environment = []string{"GOENV=off", "GOTOOLCHAIN=" + family.PlainGoVersion, "GOFLAGS=", "GOWORK=off"}
	if experimental {
		family.Environment = append(family.Environment, "GOEXPERIMENT=simd,runtimesecret")
	}
	baseEnvironment := append(inherited, family.Environment...)
	toolVersion, err := command(ctx, family.Root, baseEnvironment, family.Toolchain, "version")
	if err != nil {
		return nil, err
	}
	family.ToolVersion = string(toolVersion)
	versionText, hasPrefix := strings.CutPrefix(family.ToolVersion, "go version ")
	plainVersion, _, hasPlatform := strings.CutLast(versionText, " ")
	if !hasPrefix || !hasPlatform || plainVersion != family.PlainGoVersion {
		return nil, fmt.Errorf("selected fixture toolchain %q differs from repository expectation %q", family.ToolVersion, family.PlainGoVersion)
	}
	files := map[string]string{
		"go.mod":                      "module " + modulePath + "\n\ngo " + strings.TrimPrefix(family.PlainGoVersion, "go") + "\n",
		"LICENSE":                     string(family.License),
		"internal/version/version.go": "package version\nvar Version = \"development\"\n",
	}
	for _, name := range []string{"mitmdump", "mitmproxy", "mitmweb"} {
		files["cmd/"+name+"/main.go"] = "package main\nimport (\"fmt\"; \"" + modulePath + "/internal/version\")\nfunc main() { fmt.Println(version.Version) }\n"
	}
	for name, body := range files {
		filename := filepath.Join(family.Root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filename, []byte(body), 0o600); err != nil {
			return nil, err
		}
	}
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"add", "."},
		{"-c", "user.name=Release fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture: own immutable release inputs"},
	} {
		if _, err := command(ctx, family.Root, nil, "git", args...); err != nil {
			return nil, err
		}
	}
	commit, err := command(ctx, family.Root, nil, "git", "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	tree, err := command(ctx, family.Root, nil, "git", "rev-parse", "HEAD^{tree}")
	if err != nil {
		return nil, err
	}
	family.Commit, family.Tree = string(commit), string(tree)
	flags := "-s -w -X " + modulePath + "/internal/version.Version=" + Tag
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			stem := "mitmproxy-go_" + Tag + "_" + goos + "_" + arch
			var binaries []executable
			members := map[string][]byte{"LICENSE": family.License}
			for _, name := range []string{"mitmdump", "mitmproxy", "mitmweb"} {
				filename := name
				if goos == "windows" {
					filename += ".exe"
				}
				binary := filepath.Join(work, stem, filename)
				if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
					return nil, err
				}
				environment := append(slices.Clone(baseEnvironment), "GOOS="+goos, "GOARCH="+arch, "CGO_ENABLED=0")
				if _, err := command(ctx, family.Root, environment, family.Toolchain, "build", "-trimpath", "-buildvcs=true", "-ldflags", flags, "-o", binary, "./cmd/"+name); err != nil {
					return nil, err
				}
				info, err := buildinfo.ReadFile(binary)
				if err != nil {
					return nil, err
				}
				if family.GoVersion == "" {
					family.GoVersion = info.GoVersion
				}
				if info.GoVersion != family.GoVersion {
					return nil, fmt.Errorf("fixture toolchains disagree")
				}
				body, err := os.ReadFile(binary) //nolint:gosec // The path is an owned fixture output under the private temporary directory.
				if err != nil {
					return nil, err
				}
				buildText, err := command(ctx, family.Root, baseEnvironment, family.Toolchain, "version", "-m", binary)
				if err != nil {
					return nil, err
				}
				binaries = append(binaries, executable{filename, fmt.Sprintf("%x", sha256.Sum256(body)), string(buildText) + "\n"})
				members[filename] = body
				family.Members[stem+"/"+filename] = body
			}
			metadata := struct {
				Tag        string       `json:"tag"`
				Commit     string       `json:"commit"`
				Tree       string       `json:"tree"`
				GoVersion  string       `json:"go_version"`
				GOOS       string       `json:"goos"`
				GOARCH     string       `json:"goarch"`
				CGOEnabled string       `json:"cgo_enabled"`
				LDFlags    string       `json:"ldflags"`
				Modules    []string     `json:"module_versions"`
				Binaries   []executable `json:"binaries"`
			}{Tag, family.Commit, family.Tree, family.GoVersion, goos, arch, "0", flags, []string{modulePath}, binaries}
			data, err := json.Marshal(metadata)
			if err != nil {
				return nil, err
			}
			family.Files[stem+".provenance.json"] = append(data, '\n')
			var output bytes.Buffer
			compressed := gzip.NewWriter(&output)
			archive := tar.NewWriter(compressed)
			for _, name := range slices.Sorted(maps.Keys(members)) {
				body := members[name]
				mode := int64(0o755)
				if name == "LICENSE" {
					mode = 0o644
				}
				if err := archive.WriteHeader(&tar.Header{Name: stem + "/" + name, Mode: mode, Typeflag: tar.TypeReg, Size: int64(len(body))}); err != nil {
					return nil, err
				}
				if _, err := archive.Write(body); err != nil {
					return nil, err
				}
			}
			if err := archive.Close(); err != nil {
				return nil, err
			}
			if err := compressed.Close(); err != nil {
				return nil, err
			}
			family.Files[stem+".tar.gz"] = output.Bytes()
		}
	}
	var manifest strings.Builder
	for _, name := range slices.Sorted(maps.Keys(family.Files)) {
		_, _ = fmt.Fprintf(&manifest, "%x  %s\n", sha256.Sum256(family.Files[name]), name)
	}
	family.Files["SHA256SUMS"] = []byte(manifest.String())
	return family, nil
}
