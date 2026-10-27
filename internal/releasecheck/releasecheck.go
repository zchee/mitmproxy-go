// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package releasecheck validates release names, provenance and archive integrity.
package releasecheck

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
)

const modulePath = "github.com/zchee/mitmproxy-go"

var tagPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?(\+[0-9A-Za-z.]+)?$`)

// Target identifies one supported cross-build platform.
type Target struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
}

// Source identifies the immutable inputs shared by every release artifact.
type Source struct {
	Tag       string `json:"tag"`
	Commit    string `json:"commit"`
	Tree      string `json:"tree"`
	GoVersion string `json:"go_version"`
}

// Binary describes one executable's integrity and go version -m output.
type Binary struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	BuildInfo string `json:"build_info"`
}

// Provenance describes a target's source, build arguments and three executables.
type Provenance struct {
	Source
	Target
	CGOEnabled     string   `json:"cgo_enabled"`
	LDFlags        string   `json:"ldflags"`
	ModuleVersions []string `json:"module_versions"`
	Binaries       []Binary `json:"binaries"`
}

// ValidateTag rejects release versions outside the bounded ASCII tag format.
func ValidateTag(tag string) error {
	if len(tag) > 64 || !tagPattern.MatchString(tag) {
		return fmt.Errorf("invalid release tag %q", tag)
	}
	return nil
}

// PublishAllowed reports whether a valid tag may create a public release.
func PublishAllowed(tag string) bool {
	return ValidateTag(tag) == nil && !strings.HasPrefix(tag, "v0.0.0-test.")
}

// Targets returns the complete six-platform release matrix.
func Targets() []Target {
	return []Target{
		{GOOS: "linux", GOARCH: "amd64"},
		{GOOS: "linux", GOARCH: "arm64"},
		{GOOS: "darwin", GOARCH: "amd64"},
		{GOOS: "darwin", GOARCH: "arm64"},
		{GOOS: "windows", GOARCH: "amd64"},
		{GOOS: "windows", GOARCH: "arm64"},
	}
}

// BinaryNames returns the three executable names for a supported platform.
func BinaryNames(target Target) ([]string, error) {
	if !slices.Contains(Targets(), target) {
		return nil, fmt.Errorf("unsupported release target: %s/%s", target.GOOS, target.GOARCH)
	}
	suffix := ""
	if target.GOOS == "windows" {
		suffix = ".exe"
	}
	return []string{"mitmdump" + suffix, "mitmproxy" + suffix, "mitmweb" + suffix}, nil
}

// ArchiveRoot returns the archive's sole top-level directory name.
func ArchiveRoot(tag string, target Target) (string, error) {
	if err := ValidateTag(tag); err != nil {
		return "", err
	}
	if _, err := BinaryNames(target); err != nil {
		return "", err
	}
	return "mitmproxy-go_" + tag + "_" + target.GOOS + "_" + target.GOARCH, nil
}

// ExpectedFiles returns six archives and their six provenance documents, sorted.
func ExpectedFiles(tag string) ([]string, error) {
	var names []string
	for _, target := range Targets() {
		root, err := ArchiveRoot(tag, target)
		if err != nil {
			return nil, err
		}
		names = append(names, root+".tar.gz", root+".provenance.json")
	}
	slices.Sort(names)
	return names, nil
}

// LDFlags returns the single linker argument used for every release executable.
func LDFlags(tag string) (string, error) {
	if err := ValidateTag(tag); err != nil {
		return "", err
	}
	return "-s -w -X " + modulePath + "/internal/version.Version=" + tag, nil
}

// ValidateProvenance requires complete metadata matching the expected source.
func ValidateProvenance(p Provenance, source Source, modules []string) error {
	if err := ValidateTag(source.Tag); err != nil {
		return err
	}
	if !validHex(source.Commit, 40) || !validHex(source.Tree, 40) || !strings.HasPrefix(source.GoVersion, "go1.") || p.Source != source {
		return fmt.Errorf("release source provenance mismatch")
	}
	names, err := BinaryNames(p.Target)
	if err != nil {
		return err
	}
	flags, err := LDFlags(source.Tag)
	if err != nil {
		return err
	}
	if p.CGOEnabled != "0" || p.LDFlags != flags || len(modules) == 0 || !slices.Equal(p.ModuleVersions, modules) || len(p.Binaries) != len(names) {
		return fmt.Errorf("incomplete release build provenance")
	}
	seen := make(map[string]bool)
	for _, binary := range p.Binaries {
		if !slices.Contains(names, binary.Name) || seen[binary.Name] || !validHex(binary.SHA256, 64) {
			return fmt.Errorf("invalid executable provenance: %q", binary.Name)
		}
		seen[binary.Name] = true
		header, _, hasHeader := strings.Cut(binary.BuildInfo, "\n")
		filename, goVersion, hasVersion := strings.CutLast(header, ": ")
		if !hasHeader || !hasVersion || path.Base(strings.ReplaceAll(filename, "\\", "/")) != binary.Name || goVersion != source.GoVersion {
			return fmt.Errorf("invalid build-info header for executable %q", binary.Name)
		}
		for _, value := range []string{
			"\tpath\t" + modulePath + "/cmd/" + strings.TrimSuffix(binary.Name, ".exe") + "\n",
			"\tbuild\t-trimpath=true\n",
			"\tbuild\tCGO_ENABLED=0\n",
			"\tbuild\tGOOS=" + p.GOOS + "\n",
			"\tbuild\tGOARCH=" + p.GOARCH + "\n",
			"\tbuild\tvcs.revision=" + source.Commit + "\n",
			"\tbuild\tvcs.modified=false\n",
		} {
			if !strings.Contains(binary.BuildInfo, value) {
				return fmt.Errorf("executable %q lacks build provenance %q", binary.Name, value)
			}
		}
	}
	return nil
}

func validHex(value string, size int) bool {
	if len(value) != size || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// ChecksumManifest encodes the exact expected regular files in deterministic order.
func ChecksumManifest(digests map[string][sha256.Size]byte, expected []string) ([]byte, error) {
	if len(digests) != len(expected) {
		return nil, fmt.Errorf("release file count: got %d, want %d", len(digests), len(expected))
	}
	names := slices.Clone(expected)
	slices.Sort(names)
	var manifest strings.Builder
	for i, name := range names {
		digest, ok := digests[name]
		if !ok || (i > 0 && names[i-1] == name) || path.Base(name) != name || strings.ContainsAny(name, "\r\n\\") {
			return nil, fmt.Errorf("missing, duplicate or unsafe release file: %q", name)
		}
		_, _ = fmt.Fprintf(&manifest, "%x  %s\n", digest, name)
	}
	return []byte(manifest.String()), nil
}

// ValidateChecksums rejects missing, extra, duplicate or mismatched manifest entries.
func ValidateChecksums(manifest []byte, digests map[string][sha256.Size]byte, expected []string) error {
	want, err := ChecksumManifest(digests, expected)
	if err != nil {
		return err
	}
	if string(manifest) != string(want) {
		return fmt.Errorf("checksum manifest differs from the exact sorted release file set")
	}
	return nil
}

// ValidateArchive checks exact members and hashes without extracting any paths.
func ValidateArchive(input io.Reader, p Provenance, license [sha256.Size]byte) error {
	root, err := ArchiveRoot(p.Tag, p.Target)
	if err != nil {
		return err
	}
	names, err := BinaryNames(p.Target)
	if err != nil {
		return err
	}
	digests := make(map[string]string)
	for _, binary := range p.Binaries {
		if !slices.Contains(names, binary.Name) || digests[binary.Name] != "" || !validHex(binary.SHA256, 64) {
			return fmt.Errorf("invalid archive executable metadata")
		}
		digests[binary.Name] = binary.SHA256
	}
	if len(digests) != len(names) {
		return fmt.Errorf("incomplete archive executable metadata")
	}
	digests["LICENSE"] = hex.EncodeToString(license[:])
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return fmt.Errorf("read release gzip: %w", err)
	}
	defer func() { _ = compressed.Close() }()
	archive := tar.NewReader(compressed)
	seen := make(map[string]bool)
	var total int64
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read release tar: %w", err)
		}
		name := header.Name
		if seen[name] {
			return fmt.Errorf("duplicate archive member: %q", name)
		}
		seen[name] = true
		if name == root+"/" && header.Typeflag == tar.TypeDir {
			continue
		}
		file, ok := strings.CutPrefix(name, root+"/")
		want, exists := digests[file]
		if !ok || !exists || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > 512<<20 || header.Mode&0o7000 != 0 {
			return fmt.Errorf("unexpected archive member: %q", name)
		}
		total += header.Size
		if total > 1<<30 {
			return fmt.Errorf("release archive exceeds size bound")
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, archive); err != nil {
			return fmt.Errorf("hash release member: %w", err)
		}
		if hex.EncodeToString(hash.Sum(nil)) != want {
			return fmt.Errorf("archive member checksum mismatch: %q", name)
		}
	}
	for name := range digests {
		if !seen[root+"/"+name] {
			return fmt.Errorf("missing archive member: %q", name)
		}
	}
	trailer, err := io.ReadAll(io.LimitReader(compressed, 10<<10+1))
	if err != nil {
		return fmt.Errorf("verify gzip trailer: %w", err)
	}
	if len(trailer) > 10<<10 || len(bytes.Trim(trailer, "\x00")) != 0 {
		return fmt.Errorf("unexpected data after release tar terminator")
	}
	return nil
}
