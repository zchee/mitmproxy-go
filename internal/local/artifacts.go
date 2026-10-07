// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	redirectorVersion     = "0.12.11"
	macOSWheelURL         = "https://files.pythonhosted.org/packages/fe/7f/7f77310e810ab3ee47357e4ce1bdafc05d429e411bad63c0e546ceef2f2e/mitmproxy_macos-0.12.11-py3-none-any.whl"
	macOSWheelSHA256      = "63349d9b46514ca679547651f7c0548f9222892edfbcba087b82b3244fbae859"
	windowsWheelURL       = "https://files.pythonhosted.org/packages/52/c9/969db83d2e72de672e88a4ff556d07763ac2a106ba676f6831ced8c4db4e/mitmproxy_windows-0.12.11-py3-none-any.whl"
	windowsWheelSHA256    = "59addc8864669a08f8cb48d8b29129efb1ca5f6cba9696e2d91f1f506b21a2d7"
	linuxARM64WheelURL    = "https://files.pythonhosted.org/packages/f0/2a/ad2ae5e4c6383175c89fbc1c24c9e084a2f5b9325951e91cc3eb4b2e1649/mitmproxy_linux-0.12.11-py3-none-manylinux_2_17_aarch64.manylinux2014_aarch64.whl"
	linuxARM64WheelSHA256 = "3de4f96c11565cca2d051655f8ca23f8f24f4b3220e9ca3b0ad81007f293e9da"
	linuxAMD64WheelURL    = "https://files.pythonhosted.org/packages/53/db/1a4295e7fc6d6d975ce93a49107514bd2e13873a39c643c75109391fd336/mitmproxy_linux-0.12.11-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
	linuxAMD64WheelSHA256 = "0e5670a6b82546ebc0f947d79adfcb3c001ba3136a10ce848a2f4e2f336611c4"
	maxArtifactBytes      = 64 << 20
	maxArtifactEntries    = 128
)

type artifactSpec struct {
	filename, url, sha256, entry string
}

var artifactAcquisition = make(chan struct{}, 1)

// AcquireArtifact returns a verified cached redirector payload, or overridePath.
// Overrides must name regular files, or app directories on macOS, and must not
// be symlinks. They never trigger network acquisition.
// Otherwise the pinned wheel is downloaded beneath confdir/redirector/0.12.11,
// verified before bounded extraction, and published atomically. macOS returns
// the application tar; Windows and Linux return their executables. It never
// installs applications, starts a redirector, or activates an extension.
// Invalid overrides, unsupported selectors, integrity failures, and canceled
// contexts return errors without publishing partial downloads.
func AcquireArtifact(ctx context.Context, confdir, overridePath, goos, goarch string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if overridePath != "" {
		info, err := os.Lstat(overridePath)
		if err != nil {
			return "", fmt.Errorf("redirector override: %w", err)
		}
		if !info.Mode().IsRegular() && (goos != "darwin" || !info.IsDir() || !strings.HasSuffix(info.Name(), ".app")) {
			return "", fmt.Errorf("redirector override is not a regular file or macOS app directory: %s", overridePath)
		}
		return overridePath, nil
	}
	var artifact artifactSpec
	switch goos {
	case "darwin":
		artifact = artifactSpec{"mitmproxy_macos-0.12.11-py3-none-any.whl", macOSWheelURL, macOSWheelSHA256, "mitmproxy_macos/Mitmproxy Redirector.app.tar"}
	case "windows":
		artifact = artifactSpec{"mitmproxy_windows-0.12.11-py3-none-any.whl", windowsWheelURL, windowsWheelSHA256, "mitmproxy_windows/windows-redirector.exe"}
	case "linux":
		switch goarch {
		case "arm64":
			artifact = artifactSpec{"mitmproxy_linux-0.12.11-py3-none-manylinux_2_17_aarch64.manylinux2014_aarch64.whl", linuxARM64WheelURL, linuxARM64WheelSHA256, "mitmproxy_linux-0.12.11.data/scripts/mitmproxy-linux-redirector"}
		case "amd64":
			artifact = artifactSpec{"mitmproxy_linux-0.12.11-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", linuxAMD64WheelURL, linuxAMD64WheelSHA256, "mitmproxy_linux-0.12.11.data/scripts/mitmproxy-linux-redirector"}
		default:
			return "", fmt.Errorf("unsupported redirector architecture: %s/%s", goos, goarch)
		}
	default:
		return "", errors.New(UnavailableReason(goos, 0))
	}
	if confdir == "" {
		return "", errors.New("redirector cache requires a configuration directory")
	}
	// Selectors used as path components must remain fixed, even for universal wheels.
	key := goos
	if goos == "linux" {
		key += "-" + goarch
	}
	cache := filepath.Join(confdir, "redirector", redirectorVersion, key)
	return acquireArtifact(ctx, cache, artifact, &http.Client{Timeout: time.Minute})
}

func acquireArtifact(ctx context.Context, cache string, artifact artifactSpec, client *http.Client) (result string, retErr error) {
	select {
	case artifactAcquisition <- struct{}{}:
		defer func() { <-artifactAcquisition }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if info, err := os.Lstat(cache); err == nil {
		if !info.IsDir() {
			return "", errors.New("redirector cache is not a directory")
		}
		return verifyArtifactCache(ctx, cache, artifact)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(filepath.Dir(cache))
	if err != nil {
		return "", err
	}
	defer func() {
		retErr = errors.Join(retErr, root.Close())
		if retErr != nil {
			result = ""
		}
	}()
	stage := ".download-" + rand.Text()
	if err := root.Mkdir(stage, 0o700); err != nil {
		return "", err
	}
	defer func() { retErr = errors.Join(retErr, root.RemoveAll(stage)) }()
	if err := downloadArtifact(ctx, root, stage+"/"+artifact.filename, artifact, client); err != nil {
		return "", err
	}
	if err := extractArtifact(ctx, root, stage, artifact); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := root.Rename(stage, filepath.Base(cache)); err != nil {
		// A different process may have published the same immutable artifact.
		if path, verifyErr := verifyArtifactCache(ctx, cache, artifact); verifyErr == nil {
			return path, nil
		}
		return "", fmt.Errorf("publish redirector artifact: %w", err)
	}
	return filepath.Join(cache, filepath.FromSlash(artifact.entry)), nil
}

func downloadArtifact(ctx context.Context, root *os.Root, path string, artifact artifactSpec, client *http.Client) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("download redirector artifact: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download redirector artifact: HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxArtifactBytes {
		return errors.New("redirector wheel exceeds size limit")
	}
	file, err := root.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	count, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, maxArtifactBytes+1))
	if err != nil {
		return err
	}
	if count > maxArtifactBytes {
		return errors.New("redirector wheel exceeds size limit")
	}
	if hex.EncodeToString(hash.Sum(nil)) != artifact.sha256 {
		return errors.New("redirector wheel SHA-256 mismatch")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

func artifactEntries(reader *zip.Reader, artifact artifactSpec) error {
	if len(reader.File) > maxArtifactEntries {
		return errors.New("redirector wheel exceeds entry limit")
	}
	var total uint64
	found := false
	names := make(map[string]bool, len(reader.File))
	for _, entry := range reader.File {
		name := entry.Name
		if name == "" || len(name) > 1024 || strings.ContainsAny(name, `\:`) || !filepath.IsLocal(filepath.FromSlash(name)) {
			return fmt.Errorf("unsafe redirector wheel path: %q", name)
		}
		for part := range strings.SplitSeq(name, "/") {
			if part == ".." {
				return fmt.Errorf("unsafe redirector wheel path: %q", name)
			}
		}
		if names[name] {
			return fmt.Errorf("duplicate redirector wheel path: %q", name)
		}
		names[name] = true
		mode := entry.Mode()
		if !mode.IsRegular() && !mode.IsDir() {
			return fmt.Errorf("redirector wheel link or special file: %q", name)
		}
		if entry.UncompressedSize64 > maxArtifactBytes || total > maxArtifactBytes-entry.UncompressedSize64 {
			return errors.New("redirector wheel exceeds extraction size limit")
		}
		total += entry.UncompressedSize64
		if name == artifact.entry && mode.IsRegular() && entry.UncompressedSize64 != 0 {
			found = true
		}
	}
	if !found {
		return errors.New("redirector wheel lacks a nonempty payload")
	}
	return nil
}

func extractArtifact(ctx context.Context, parent *os.Root, stage string, artifact artifactSpec) error {
	root, err := parent.OpenRoot(stage)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	wheel, err := root.Open(artifact.filename)
	if err != nil {
		return err
	}
	defer func() { _ = wheel.Close() }()
	info, err := wheel.Stat()
	if err != nil {
		return err
	}
	reader, err := zip.NewReader(wheel, info.Size())
	if err != nil {
		return err
	}
	if err := artifactEntries(reader, artifact); err != nil {
		return err
	}
	for _, entry := range reader.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := filepath.FromSlash(entry.Name)
		if entry.Mode().IsDir() {
			if err := root.MkdirAll(name, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return err
		}
		if err := extractArtifactEntry(root, name, entry); err != nil {
			return err
		}
	}
	return nil
}

func extractArtifactEntry(root *os.Root, name string, entry *zip.File) error {
	input, err := entry.Open()
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	output, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = output.Close() }()
	count, err := io.Copy(output, io.LimitReader(input, int64(entry.UncompressedSize64)+1))
	if err != nil {
		return err
	}
	if uint64(count) != entry.UncompressedSize64 {
		return errors.New("redirector wheel entry size mismatch")
	}
	if entry.Mode().Perm()&0o111 != 0 {
		if err := output.Chmod(0o700); err != nil {
			return err
		}
	}
	return output.Close()
}

func verifyArtifactCache(ctx context.Context, cache string, artifact artifactSpec) (string, error) {
	root, err := os.OpenRoot(cache)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	wheel, err := root.Open(artifact.filename)
	if err != nil {
		return "", err
	}
	defer func() { _ = wheel.Close() }()
	info, err := wheel.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > maxArtifactBytes {
		return "", errors.New("invalid cached redirector wheel")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(wheel, maxArtifactBytes+1)); err != nil {
		return "", err
	}
	if hex.EncodeToString(hash.Sum(nil)) != artifact.sha256 {
		return "", errors.New("cached redirector wheel SHA-256 mismatch")
	}
	reader, err := zip.NewReader(wheel, info.Size())
	if err != nil {
		return "", err
	}
	if err := artifactEntries(reader, artifact); err != nil {
		return "", err
	}
	for _, entry := range reader.File {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if entry.Mode().IsDir() {
			continue
		}
		if err := verifyArtifactEntry(root, entry); err != nil {
			return "", err
		}
	}
	return filepath.Join(cache, filepath.FromSlash(artifact.entry)), nil
}

func verifyArtifactEntry(root *os.Root, entry *zip.File) error {
	name := filepath.FromSlash(entry.Name)
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || uint64(info.Size()) != entry.UncompressedSize64 {
		return fmt.Errorf("invalid cached redirector payload: %s", name)
	}
	input, err := entry.Open()
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	cached, err := root.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = cached.Close() }()
	expected, actual := sha256.New(), sha256.New()
	if _, err := io.Copy(expected, io.LimitReader(input, int64(entry.UncompressedSize64)+1)); err != nil {
		return err
	}
	if _, err := io.Copy(actual, io.LimitReader(cached, int64(entry.UncompressedSize64)+1)); err != nil {
		return err
	}
	if !bytes.Equal(expected.Sum(nil), actual.Sum(nil)) {
		return fmt.Errorf("cached redirector payload mismatch: %s", name)
	}
	return nil
}
