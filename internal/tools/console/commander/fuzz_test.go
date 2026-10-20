// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package commander_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/internal/tools/console/commander"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

func FuzzConsoleCommander(f *testing.F) {
	for _, seed := range []string{"", "set view_filter '~bq test'", "echo é👩‍💻", "pick \"unfinished", "\x1b]52;c;payload\a"} {
		f.Add(seed, seed, 0)
	}
	f.Fuzz(func(t *testing.T, text, insertion string, cursor int) {
		b := commander.NewBuffer(text)
		b.SetCursor(cursor)
		b.Insert(insertion)
		b.Left()
		b.Right()
		b.Backspace()
		b.Delete()
		b.Complete(contract.Completion{Start: 0, Choices: []string{b.BeforeCursor()}}, true)
		if !utf8.ValidString(b.Text()) {
			t.Fatal("editing produced invalid UTF-8")
		}
		if b.Cursor() < 0 || b.Cursor() > utf8.RuneCountInString(b.Text()) {
			t.Fatal("cursor outside line")
		}
	})
}

func FuzzConsoleFilterInput(f *testing.F) {
	for _, seed := range []string{"", "~bq test", "~d example.com & ~m GET", "'unterminated", "日本", "\x00\x1b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, fragment string) {
		fragment = strings.ToValidUTF8(fragment, "�")
		line := "set view_filter " + command.Quote(fragment)
		b := commander.NewBuffer(line)
		b.SetCursor(utf8.RuneCountInString(line))
		_, _ = filter.Parse(fragment)
		parts := command.Lex(b.Text())
		if len(parts) < 3 {
			t.Fatal("quoted fragment lost its argument")
		}
		b.Left()
		b.Backspace()
		if !utf8.ValidString(b.Text()) {
			t.Fatal("filter edit split UTF-8")
		}
	})
}
