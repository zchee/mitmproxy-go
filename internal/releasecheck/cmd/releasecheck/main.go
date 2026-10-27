// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Command releasecheck validates release artifact integrity and provenance.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/zchee/mitmproxy-go/internal/releasecheck"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	goTool, err := toolchainGo()
	if err == nil {
		err = run(ctx, goTool, os.Args[1:])
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func toolchainGo() (string, error) {
	tool, err := exec.LookPath("go")
	if err != nil {
		return "", fmt.Errorf("locate Go toolchain: %w", err)
	}
	tool, err = filepath.EvalSymlinks(tool)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(tool) {
		return "", fmt.Errorf("toolchain path must be absolute")
	}
	info, err := os.Stat(tool)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0) {
		return "", fmt.Errorf("toolchain is not a regular executable")
	}
	return tool, nil
}

func run(ctx context.Context, goTool string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: releasecheck tag VERSION | publish-tag VERSION | record VERSION GOOS GOARCH BIN_DIR | checksums DIR VERSION | verify DIR VERSION")
	}
	switch args[0] {
	case "tag", "publish-tag":
		if len(args) != 2 {
			return fmt.Errorf("tag expects one version")
		}
		if err := releasecheck.ValidateTag(args[1]); err != nil {
			return err
		}
		if args[0] == "publish-tag" && !releasecheck.PublishAllowed(args[1]) {
			return fmt.Errorf("test tags cannot publish releases")
		}
		_, err := fmt.Fprintln(os.Stdout, args[1])
		return err
	case "record":
		if len(args) != 5 {
			return fmt.Errorf("record expects version, GOOS, GOARCH and binary directory")
		}
		return record(ctx, goTool, args[1], releasecheck.Target{GOOS: args[2], GOARCH: args[3]}, args[4])
	case "checksums", "verify":
		if len(args) != 3 {
			return fmt.Errorf("%s expects an artifact directory and version", args[0])
		}
		return verify(ctx, goTool, args[1], args[2], args[0] == "checksums")
	default:
		return fmt.Errorf("unknown releasecheck command %q", args[0])
	}
}

func sourceMetadata(ctx context.Context, goTool, tag string) (releasecheck.Source, []string, error) {
	if err := releasecheck.ValidateTag(tag); err != nil {
		return releasecheck.Source{}, nil, err
	}
	commit, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if err != nil {
		return releasecheck.Source{}, nil, fmt.Errorf("read source commit: %w", err)
	}
	tree, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD^{tree}").Output()
	if err != nil {
		return releasecheck.Source{}, nil, fmt.Errorf("read source tree: %w", err)
	}
	modules, err := exec.CommandContext(ctx, goTool, "list", "-m", "all").Output() //nolint:gosec // goTool is the validated absolute toolchain executable; all arguments are fixed.
	if err != nil {
		return releasecheck.Source{}, nil, fmt.Errorf("read module versions: %w", err)
	}
	source := releasecheck.Source{Tag: tag, Commit: strings.TrimSpace(string(commit)), Tree: strings.TrimSpace(string(tree)), GoVersion: runtime.Version()}
	return source, strings.Split(strings.TrimSpace(string(modules)), "\n"), nil
}

func openArtifact(root *os.Root, name string, expected []string) (*os.File, error) {
	if name == "." || name == ".." || name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") || !slices.Contains(expected, name) {
		return nil, fmt.Errorf("unexpected release basename: %q", name)
	}
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular release file: %q", name)
	}
	return root.Open(name)
}

func hashFile(root *os.Root, name string, expected []string) ([sha256.Size]byte, error) {
	file, err := openArtifact(root, name, expected)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return [sha256.Size]byte{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func record(ctx context.Context, goTool, tag string, target releasecheck.Target, dir string) error {
	source, modules, err := sourceMetadata(ctx, goTool, tag)
	if err != nil {
		return err
	}
	names, err := releasecheck.BinaryNames(target)
	if err != nil {
		return err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	artifacts, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = artifacts.Close() }()
	entries, err := fs.ReadDir(artifacts.FS(), ".")
	if err != nil {
		return err
	}
	var actual []string
	for _, entry := range entries {
		actual = append(actual, entry.Name())
	}
	want := append(slices.Clone(names), "LICENSE")
	slices.Sort(want)
	if !slices.Equal(actual, want) {
		return fmt.Errorf("staged release file set mismatch: got %v, want %v", actual, want)
	}
	flags, err := releasecheck.LDFlags(tag)
	if err != nil {
		return err
	}
	provenance := releasecheck.Provenance{Source: source, Target: target, CGOEnabled: "0", LDFlags: flags, ModuleVersions: modules}
	for _, name := range names {
		digest, err := hashFile(artifacts, name, names)
		if err != nil {
			return fmt.Errorf("hash executable: %w", err)
		}
		binary := filepath.Join(dir, name)
		info, err := exec.CommandContext(ctx, goTool, "version", "-m", "--", binary).Output() //nolint:gosec // The absolute toolchain is validated; binary is a frozen basename from the validated Root listing, passed without a shell.
		if err != nil {
			return fmt.Errorf("inspect executable: %w", err)
		}
		provenance.Binaries = append(provenance.Binaries, releasecheck.Binary{Name: name, SHA256: hex.EncodeToString(digest[:]), BuildInfo: string(info)})
	}
	if err := releasecheck.ValidateProvenance(provenance, source, modules); err != nil {
		return err
	}
	data, err := json.Marshal(provenance)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(data, '\n'))
	return err
}

func verify(ctx context.Context, goTool, dir, tag string, create bool) error {
	expected, err := releasecheck.ExpectedFiles(tag)
	if err != nil {
		return err
	}
	artifacts, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = artifacts.Close() }()
	entries, err := fs.ReadDir(artifacts.FS(), ".")
	if err != nil {
		return err
	}
	want := slices.Clone(expected)
	if !create {
		want = append(want, "SHA256SUMS")
	}
	slices.Sort(want)
	var actual []string
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unexpected non-regular release file: %q", entry.Name())
		}
		actual = append(actual, entry.Name())
	}
	if !slices.Equal(actual, want) {
		return fmt.Errorf("release file set mismatch: got %v, want %v", actual, want)
	}
	digests := make(map[string][sha256.Size]byte)
	for _, name := range expected {
		digest, err := hashFile(artifacts, name, expected)
		if err != nil {
			return err
		}
		digests[name] = digest
	}
	source, modules, err := sourceMetadata(ctx, goTool, tag)
	if err != nil {
		return err
	}
	sourceRoot, err := os.OpenRoot(".")
	if err != nil {
		return err
	}
	license, err := hashFile(sourceRoot, "LICENSE", []string{"LICENSE"})
	closeErr := sourceRoot.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, target := range releasecheck.Targets() {
		stem, err := releasecheck.ArchiveRoot(tag, target)
		if err != nil {
			return err
		}
		metadata, err := openArtifact(artifacts, stem+".provenance.json", expected)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(metadata, 1<<20+1))
		closeErr := metadata.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(data) > 1<<20 {
			return fmt.Errorf("release provenance exceeds size bound")
		}
		var provenance releasecheck.Provenance
		if err := json.Unmarshal(data, &provenance, json.RejectUnknownMembers(true)); err != nil {
			return err
		}
		if provenance.Target != target {
			return fmt.Errorf("release target metadata mismatch")
		}
		if err := releasecheck.ValidateProvenance(provenance, source, modules); err != nil {
			return err
		}
		archive, err := openArtifact(artifacts, stem+".tar.gz", expected)
		if err != nil {
			return err
		}
		validationErr := releasecheck.ValidateArchive(archive, provenance, license)
		closeErr = archive.Close()
		if validationErr != nil {
			return validationErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if create {
		data, err := releasecheck.ChecksumManifest(digests, expected)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(data)
		return err
	}
	manifestFile, err := openArtifact(artifacts, "SHA256SUMS", want)
	if err != nil {
		return err
	}
	defer func() { _ = manifestFile.Close() }()
	manifest, err := io.ReadAll(io.LimitReader(manifestFile, 64<<10+1))
	if err != nil {
		return err
	}
	if len(manifest) > 64<<10 {
		return fmt.Errorf("checksum manifest exceeds size bound")
	}
	return releasecheck.ValidateChecksums(manifest, digests, expected)
}
