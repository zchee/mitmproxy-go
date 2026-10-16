// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build ignore

package dumper

import (
	"strings"
	"unicode"
	"unicode/utf8"

	highlight "github.com/zchee/mitmproxy-go/contentviews/highlight"
	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/internal/vtcodes"
)

func (d *Dumper) echoContentview(text, language string) error {
	if !d.outHasVT {
		return d.echo(text, 4, vtcodes.Style{})
	}
	chunks, err := highlight.Highlight(strutil.EscapeControlCharacters(text, true), language)
	if err != nil {
		return err
	}
	var plain strings.Builder
	for _, chunk := range chunks {
		plain.WriteString(chunk.Text)
	}
	body := plain.String()
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return d.echo("", 0, vtcodes.Style{})
	}
	left := len(body) - len(strings.TrimLeftFunc(body, unicode.IsSpace))
	right := left + len(trimmed)
	var output strings.Builder
	output.WriteString("    ")
	position := 0
	skipLF := false
	for _, chunk := range chunks {
		end := position + len(chunk.Text)
		if end <= left || position >= right {
			position = end
			continue
		}
		text := chunk.Text[max(0, left-position):min(len(chunk.Text), right-position)]
		position = end
		style := vtcodes.Style{}
		switch chunk.Tag {
		case "name":
			style.FG = "yellow"
		case "string":
			style.FG = "green"
		case "number":
			style.FG = "blue"
		case "boolean":
			style.FG = "magenta"
		case "comment":
			style.Dim = new(true)
		case "error":
			style.FG = "red"
		}
		start := 0
		for index, r := range text {
			if skipLF {
				skipLF = false
				if r == '\n' {
					start = index + 1
					continue
				}
			}
			if r != '\r' && r != '\n' && r != '\u0085' && r != ' ' && r != ' ' {
				continue
			}
			if start < index {
				output.WriteString(d.style(text[start:index], style))
			}
			output.WriteString("\n    ")
			start = index + utf8.RuneLen(r)
			skipLF = r == '\r'
		}
		if start < len(text) {
			output.WriteString(d.style(text[start:], style))
		}
	}
	return d.echo(output.String(), 0, vtcodes.Style{})
}
