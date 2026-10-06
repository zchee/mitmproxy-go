// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package commandhistory persists command history and navigates filtered commands.
package commandhistory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/internal/privfile"
	"github.com/zchee/mitmproxy-go/options"
)

const maxHistoryBytes = 16 << 20

// Addon maintains command history. Hooks and commands run under the addon dispatch lock.
type Addon struct {
	options         *options.Manager
	history         []string
	filteredHistory []string
	currentIndex    int
	vacuumSize      int
}

// New returns a command-history addon using opts.
func New(opts *options.Manager) *Addon {
	return &Addon{options: opts, history: []string{}, filteredHistory: []string{""}, vacuumSize: 1024}
}

// Name identifies the addon with upstream's spelling.
func (*Addon) Name() string { return "commandhistory" }

// Load registers the persistence option and history commands.
func (a *Addon) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "command_history", options.TypeBool, true, "Persist command history between mitmproxy invocations."); err != nil {
		return err
	}
	if err := loader.AddCommand("commands.history.add", a.add, command.WithParams("command")); err != nil {
		return err
	}
	if err := loader.AddCommand("commands.history.get", a.get, command.WithHelp("Get the entire command history.")); err != nil {
		return err
	}
	if err := loader.AddCommand("commands.history.clear", a.clear); err != nil {
		return err
	}
	if err := loader.AddCommand("commands.history.filter", a.setFilter, command.WithParams("prefix")); err != nil {
		return err
	}
	if err := loader.AddCommand("commands.history.next", a.next); err != nil {
		return err
	}
	return loader.AddCommand("commands.history.prev", a.prev)
}

func (a *Addon) historyFile(ctx context.Context) string {
	dir := a.options.Str("confdir")
	if expanded, err := command.PathType.Parse(ctx, nil, dir); err == nil {
		dir = string(expanded.(command.Path))
	}
	return filepath.Join(dir, "command_history")
}

// Configure reloads a regular history file when persistence or confdir changes.
// Read failures are returned to the addon dispatcher; existing history is retained.
func (a *Addon) Configure(ctx context.Context, updated map[string]struct{}) error {
	_, persistenceChanged := updated["command_history"]
	_, directoryChanged := updated["confdir"]
	if (!persistenceChanged && !directoryChanged) || !a.options.Bool("command_history") {
		return nil
	}
	path := a.historyFile(ctx)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	data, err := readHistory(path)
	if err != nil {
		return err
	}
	a.history = splitLines(string(data))
	a.setFilter(ctx, "")
	return nil
}

func readHistory(path string) (data []byte, err error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err = io.ReadAll(io.LimitReader(file, maxHistoryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxHistoryBytes {
		return nil, fmt.Errorf("command history exceeds %d bytes", maxHistoryBytes)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("command history is not valid UTF-8")
	}
	return data, nil
}

// splitLines matches str.splitlines, including Unicode separators and CRLF pairs.
func splitLines(text string) []string {
	lines := []string{}
	start := 0
	for i, r := range text {
		if i < start {
			continue
		}
		switch r {
		case '\n', '\r', '\v', '\f', '\x1c', '\x1d', '\x1e', 0x85, 0x2028, 0x2029:
			lines = append(lines, text[start:i])
			start = i + utf8.RuneLen(r)
			if r == '\r' && start < len(text) && text[start] == '\n' {
				start++
			}
		}
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}

// Running reloads history at startup, even when no relevant option changed.
func (a *Addon) Running(ctx context.Context) error {
	return a.Configure(ctx, map[string]struct{}{"command_history": {}})
}

// Done vacuums persisted history once it reaches the retention threshold.
// A failed write is logged without preventing shutdown or changing memory.
func (a *Addon) Done(ctx context.Context) error {
	if a.options.Bool("command_history") && len(a.history) >= a.vacuumSize {
		// Python floors negative division, so an odd threshold keeps the ceiling half.
		keep := (a.vacuumSize + 1) / 2
		text := strings.Join(a.history[len(a.history)-keep:], "\n") + "\n"
		path := a.historyFile(ctx)
		if err := writeHistory(path, text, os.O_TRUNC); err != nil {
			slog.WarnContext(ctx, fmt.Sprintf("Failed writing to %s: %v", path, err))
		}
	}
	return nil
}

func writeHistory(path, text string, flags int) (err error) {
	if !utf8.ValidString(text) {
		return errors.New("command history is not valid UTF-8")
	}
	open := privfile.Create
	if flags&os.O_APPEND != 0 {
		open = privfile.Append
	}
	file, err := open(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if runtime.GOOS == "windows" {
		text = strings.ReplaceAll(text, "\n", "\r\n")
	}
	_, err = io.WriteString(file, text)
	return err
}

func (a *Addon) add(ctx context.Context, text string) {
	if strings.TrimFunc(text, func(r rune) bool { return unicode.IsSpace(r) || r >= '\x1c' && r <= '\x1f' }) == "" {
		return
	}
	a.history = append(a.history, text)
	if a.options.Bool("command_history") {
		path := a.historyFile(ctx)
		if err := writeHistory(path, text+"\n", os.O_APPEND); err != nil {
			slog.WarnContext(ctx, fmt.Sprintf("Failed writing to %s: %v", path, err))
		}
	}
	a.setFilter(ctx, "")
}

func (a *Addon) get(context.Context) []string { return slices.Clone(a.history) }

func (a *Addon) clear(ctx context.Context) {
	path := a.historyFile(ctx)
	if _, err := os.Stat(path); err == nil {
		// os.Remove also deletes empty directories; Python Path.unlink does not.
		info, err := os.Lstat(path)
		if err == nil && info.IsDir() {
			err = &os.PathError{Op: "unlink", Path: path, Err: errors.New("is a directory")}
		} else if err == nil {
			err = os.Remove(path)
		}
		if err != nil {
			slog.WarnContext(ctx, fmt.Sprintf("Failed deleting %s: %v", path, err))
		}
	}
	a.history = []string{}
	a.setFilter(ctx, "")
}

func (a *Addon) setFilter(_ context.Context, prefix string) {
	a.filteredHistory = nil
	for _, text := range a.history {
		if strings.HasPrefix(text, prefix) {
			a.filteredHistory = append(a.filteredHistory, text)
		}
	}
	a.filteredHistory = append(a.filteredHistory, prefix)
	a.currentIndex = len(a.filteredHistory) - 1
}

func (a *Addon) next(context.Context) string {
	a.currentIndex = min(a.currentIndex+1, len(a.filteredHistory)-1)
	return a.filteredHistory[a.currentIndex]
}

func (a *Addon) prev(context.Context) string {
	a.currentIndex = max(0, a.currentIndex-1)
	return a.filteredHistory[a.currentIndex]
}
