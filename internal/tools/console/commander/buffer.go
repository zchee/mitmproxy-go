// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package commander implements command prompts and the command reference.
package commander

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

// Buffer is a UTF-8 command line with a rune-indexed, grapheme-aligned cursor.
// It owns no live registry or dispatch context.
type Buffer struct {
	text   string
	cursor int
	cycle  *completionCycle
}

type completionCycle struct {
	choices        []string
	prefix, suffix string
	quote          rune
	position       int
}

// NewBuffer returns an editable command line with its cursor at the end.
func NewBuffer(text string) Buffer {
	var b Buffer
	b.SetText(text)
	return b
}

// Text returns the entire command line.
func (b *Buffer) Text() string { return b.text }

// Cursor returns the rune offset of the cursor.
func (b *Buffer) Cursor() int { return b.cursor }

// BeforeCursor returns the command fragment supplied to dynamic completion.
func (b *Buffer) BeforeCursor() string { return string([]rune(b.text)[:b.cursor]) }

// SetText replaces the line and clears completion state.
func (b *Buffer) SetText(text string) {
	b.text = strings.ToValidUTF8(text, "�")
	b.cursor = utf8.RuneCountInString(b.text)
	b.cycle = nil
}

// SetCursor clamps a rune offset to the preceding grapheme boundary.
func (b *Buffer) SetCursor(cursor int) {
	length := utf8.RuneCountInString(b.text)
	b.cursor = min(max(cursor, 0), length)
	if b.cursor < length {
		b.cursor = style.PreviousGrapheme(b.text, b.cursor+1)
	}
	b.cycle = nil
}

// Left moves to the preceding grapheme boundary.
func (b *Buffer) Left() { b.SetCursor(style.PreviousGrapheme(b.text, b.cursor)) }

// Right moves to the next grapheme boundary.
func (b *Buffer) Right() { b.SetCursor(style.NextGrapheme(b.text, b.cursor)) }

// Insert inserts text without executing it; a leading single space is ignored.
func (b *Buffer) Insert(text string) {
	if text == " " && strings.TrimSpace(b.BeforeCursor()) == "" {
		return
	}
	runes := []rune(b.text)
	text = strings.ToValidUTF8(text, "�")
	b.text = string(runes[:b.cursor]) + text + string(runes[b.cursor:])
	b.SetCursor(b.cursor + utf8.RuneCountInString(text))
}

// Backspace removes the grapheme before the cursor.
func (b *Buffer) Backspace() {
	end := b.cursor
	b.Left()
	runes := []rune(b.text)
	b.text = string(runes[:b.cursor]) + string(runes[end:])
}

// Delete removes the grapheme at the cursor.
func (b *Buffer) Delete() {
	start := b.cursor
	b.Right()
	runes := []rune(b.text)
	b.text = string(runes[:start]) + string(runes[b.cursor:])
	b.SetCursor(start)
}

// WordLeft moves to the preceding space, matching the command editor's word motion.
func (b *Buffer) WordLeft() {
	before := []rune(b.BeforeCursor())
	for i := len(before) - 1; i >= 0; i-- {
		if before[i] == ' ' {
			b.SetCursor(i)
			return
		}
	}
	b.SetCursor(0)
}

// WordRight moves to the next space or the end of the line.
func (b *Buffer) WordRight() {
	runes := []rune(b.text)
	for i := b.cursor + 1; i < len(runes); i++ {
		if runes[i] == ' ' {
			b.SetCursor(i)
			return
		}
	}
	b.SetCursor(len(runes))
}

// DeleteWord removes the preceding space-delimited word.
func (b *Buffer) DeleteWord() {
	runes := []rune(b.text)
	start := 0
	for i := b.cursor - 2; i >= 0; i-- {
		if runes[i] == ' ' {
			start = i + 1
			break
		}
	}
	b.text = string(runes[:start]) + string(runes[b.cursor:])
	b.SetCursor(start)
}

// Completing reports whether a completion cycle already has a candidate snapshot.
func (b *Buffer) Completing() bool { return b.cycle != nil }

// Complete snapshots prefix-matching candidates or advances the current cycle.
// It replaces only the token containing the cursor, preserving following arguments.
func (b *Buffer) Complete(result contract.Completion, forward bool) {
	if b.cycle == nil {
		runes := []rune(b.text)
		start := min(max(result.Start, 0), b.cursor)
		fragment := string(runes[start:b.cursor])
		prefix := result.Prefix
		var quote rune
		if len(fragment) > 0 && (fragment[0] == '\'' || fragment[0] == '"') {
			quote = rune(fragment[0])
			prefix = strings.TrimPrefix(fragment, string(quote))
			prefix = strings.TrimSuffix(prefix, string(quote))
		}
		end := b.cursor
		if parts := command.Lex(string(runes[start:])); len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
			end = min(len(runes), start+utf8.RuneCountInString(parts[0]))
		}
		choices := make([]string, 0, len(result.Choices))
		for _, candidate := range result.Choices {
			if strings.HasPrefix(candidate, prefix) {
				choices = append(choices, candidate)
			}
		}
		slices.Sort(choices)
		if len(choices) == 0 {
			return
		}
		b.cycle = &completionCycle{choices: choices, prefix: string(runes[:start]), suffix: string(runes[end:]), quote: quote, position: -1}
	}
	c := b.cycle
	if c.position < 0 {
		if forward {
			c.position = 0
		} else {
			c.position = len(c.choices) - 1
		}
	} else if forward {
		c.position = (c.position + 1) % len(c.choices)
	} else {
		c.position = (c.position + len(c.choices) - 1) % len(c.choices)
	}
	value := command.Quote(c.choices[c.position])
	if c.quote != 0 && !strings.ContainsRune(c.choices[c.position], c.quote) {
		value = string(c.quote) + c.choices[c.position] + string(c.quote)
	}
	b.text = c.prefix + value + c.suffix
	b.cursor = utf8.RuneCountInString(c.prefix + value)
}
