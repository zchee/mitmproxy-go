// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package external

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	tea "charm.land/bubbletea/v2"

	"github.com/zchee/mitmproxy-go/internal/privfile"
	"github.com/zchee/mitmproxy-go/internal/strutil"
)

// Result carries edited bytes or an error after the child is reaped and cleaned up.
type Result struct {
	Data []byte
	Err  error
}

// Request describes a detached payload and whether it is display-only.
type Request struct {
	Data        []byte
	Viewer      bool
	ContentType string
}

// Resolve selects the configured program using upstream precedence.
// Environment and PATH lookup happen here, never during flow rendering.
func Resolve(data []byte, viewer bool) (string, error) {
	if viewer {
		for _, name := range []string{"MITMPROXY_EDITOR", "PAGER", "EDITOR"} {
			if value := os.Getenv(name); value != "" {
				return value, nil
			}
		}
		return "less", nil
	}
	if strutil.IsMostlyBin(data) {
		for _, name := range []string{"ghex", "hexedit", "hxd", "hexer", "hexcurse"} {
			if path, err := exec.LookPath(name); err == nil {
				return path, nil
			}
		}
	}
	for _, name := range []string{"MITMPROXY_EDITOR", "EDITOR"} {
		if value := os.Getenv(name); value != "" {
			return value, nil
		}
	}
	for _, name := range []string{"sensible-editor", "nano", "vim"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	if runtime.GOOS == "windows" {
		return "notepad", nil
	}
	return "vi", nil
}

// Process owns one private temporary directory and one cancellable child.
// Complete or Close must be called, including when the command is never started.
type Process struct {
	Command         *exec.Cmd
	directory, name string
	root            *os.Root
	viewer          bool
	input           []byte
	mu              sync.Mutex
	once            sync.Once
	stopCleanup     func() bool
	cleaned         chan struct{}
	closeErr        error
}

// Prepare creates a private payload file and an argv-only editor command.
// It performs file I/O and must be called outside addon dispatch.
func Prepare(ctx context.Context, request Request) (*Process, error) {
	command, err := Resolve(request.Data, request.Viewer)
	if err != nil {
		return nil, err
	}
	args, err := ParseArgv(command)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "mitmproxy-editor-")
	if err != nil {
		return nil, err
	}
	p := &Process{directory: dir, name: "payload" + extension(request.ContentType), viewer: request.Viewer, input: bytes.Clone(request.Data), cleaned: make(chan struct{})}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errors.Join(err, os.RemoveAll(dir))
	}
	p.root = root
	file, err := privfile.Create(filepath.Join(dir, p.name))
	if err != nil {
		return nil, errors.Join(err, p.Close())
	}
	_, writeErr := file.Write(request.Data)
	closeErr := file.Close()
	if err = errors.Join(writeErr, closeErr); err != nil {
		return nil, errors.Join(err, p.Close())
	}
	if request.Viewer {
		if err := root.Chmod(p.name, 0o400); err != nil {
			return nil, errors.Join(err, p.Close())
		}
	}
	p.Command = exec.CommandContext(ctx, args[0], append(args[1:], filepath.Join(dir, p.name))...) //nolint:gosec // Argv comes from the operator's editor setting; the payload is a literal file argument.
	p.mu.Lock()
	p.stopCleanup = context.AfterFunc(ctx, func() { _ = p.Close() })
	p.mu.Unlock()
	return p, nil
}

func extension(contentType string) string {
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	extensions, err := mime.ExtensionsByType(media)
	if err != nil {
		return ""
	}
	slices.Sort(extensions)
	for _, ext := range extensions {
		if len(ext) < 2 || len(ext) > 16 || ext[0] != '.' {
			continue
		}
		if strings.IndexFunc(ext[1:], func(r rune) bool { return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') }) < 0 {
			return ext
		}
	}
	return ""
}

// Tea suspends and restores the terminal using Bubble Tea's process executor.
// The callback runs only after process completion and owned-file cleanup.
func (p *Process) Tea(done func(Result) tea.Msg) tea.Cmd {
	return tea.ExecProcess(p.Command, func(err error) tea.Msg { return done(p.Complete(err)) })
}

// Complete reads a successful edit after validating its opened regular file.
// Any process, read, validation or cleanup failure is returned to the caller.
func (p *Process) Complete(processErr error) Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := Result{Err: processErr}
	if processErr == nil {
		if p.viewer {
			result.Data = bytes.Clone(p.input)
		} else {
			result.Data, result.Err = p.read()
		}
	}
	result.Err = errors.Join(result.Err, p.close())
	return result
}

func (p *Process) read() ([]byte, error) {
	before, err := p.root.Lstat(p.name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("editor output is not a regular file")
	}
	file, err := p.root.Open(p.name)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	after, linkErr := p.root.Lstat(p.name)
	if statErr != nil || linkErr != nil || !info.Mode().IsRegular() || !after.Mode().IsRegular() || !os.SameFile(before, info) || !os.SameFile(info, after) {
		return nil, errors.Join(errors.New("editor output changed while opening"), statErr, linkErr, file.Close())
	}
	data, readErr := io.ReadAll(file)
	return data, errors.Join(readErr, file.Close())
}

// Close removes the owned files; it does not terminate a running child.
// Cancel the context and wait for Command before closing a running process.
func (p *Process) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.close()
}

func (p *Process) close() error {
	if p.stopCleanup != nil {
		p.stopCleanup()
	}
	p.once.Do(func() {
		if p.root != nil {
			p.closeErr = p.root.Close()
		}
		p.closeErr = errors.Join(p.closeErr, os.RemoveAll(p.directory))
		close(p.cleaned)
	})
	return p.closeErr
}

// StripNewlines applies the source's part-specific external-edit policy.
func StripNewlines(data []byte, part string, enabled bool) []byte {
	if enabled || part == "url" || part == "tcp-message" || part == "udp-message" || part == "websocket-message" {
		return bytes.TrimRight(data, "\n")
	}
	return data
}
