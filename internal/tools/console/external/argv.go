// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package external runs user-configured editors without invoking a shell.
package external

import (
	"errors"
	"strings"
)

// ParseArgv splits shell-like quotes and backslash escapes, without expansion.
// Unclosed quotes, a trailing escape, NUL, and input over 64 KiB are rejected.
// Metacharacters, variable references and command substitutions remain literal.
func ParseArgv(input string) ([]string, error) {
	if len(input) > 65536 || strings.IndexByte(input, 0) >= 0 {
		return nil, errors.New("invalid editor command")
	}
	var args []string
	var word strings.Builder
	var quote byte
	started := false
	for i := 0; i < len(input); i++ {
		ch := input[i]
		if quote == '\'' {
			if ch == quote {
				quote = 0
			} else {
				word.WriteByte(ch)
			}
			continue
		}
		if ch == '\\' {
			i++
			if i == len(input) {
				return nil, errors.New("trailing escape in editor command")
			}
			next := input[i]
			if quote == '"' && next != '"' && next != '\\' {
				word.WriteByte('\\')
			}
			word.WriteByte(next)
			started = true
			continue
		}
		if quote == '"' {
			if ch == quote {
				quote = 0
			} else {
				word.WriteByte(ch)
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
			started = true
		case ' ', '\t', '\r', '\n':
			if started {
				args = append(args, word.String())
				word.Reset()
				started = false
			}
		default:
			word.WriteByte(ch)
			started = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unclosed quote in editor command")
	}
	if started {
		args = append(args, word.String())
	}
	if len(args) == 0 || args[0] == "" {
		return nil, errors.New("empty editor command")
	}
	return args, nil
}
