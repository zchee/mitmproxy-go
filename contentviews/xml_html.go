// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"iter"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/internal/textwrap"
)

// XMLHTML formats XML or HTML by changing whitespace only, even in malformed input.
type XMLHTML struct{}

// Name returns the registered view name.
func (XMLHTML) Name() string { return "XML/HTML" }

// SyntaxHighlight returns the view's highlighting language.
func (XMLHTML) SyntaxHighlight() string { return "xml" }

// RenderPriority prefers XML and HTML content types, then XML-looking bytes.
func (XMLHTML) RenderPriority(data []byte, metadata Metadata) float64 {
	if len(data) == 0 {
		return 0
	}
	if metadata.ContentType == "text/xml" || metadata.ContentType == "text/html" {
		return 1
	}
	if strutil.IsXML(data) {
		return 0.4
	}
	return 0
}

// Prettify indents markup without repairing it or changing its tags.
// HTTP metadata supplies decoded text when available. It never returns an error.
func (XMLHTML) Prettify(data []byte, metadata Metadata) (string, error) {
	text, _ := (Raw{}).Prettify(data, metadata)
	if metadata.HTTPMessage != nil {
		text = metadata.HTTPMessage.TextOrRaw()
	}
	next, stop := iter.Pull(xmlTokens(text))
	defer stop()
	var window [5]xmlToken
	window[2], _ = next()
	window[3], _ = next()
	window[4], _ = next()
	var out strings.Builder
	var stack []string
	indent := 0
	for window[2].data != "" {
		token := window[2]
		inline := xmlInline(window)
		switch {
		case token.opening():
			out.WriteString(indentXMLText(token.data, indent))
			if !inline {
				out.WriteByte('\n')
			}
			if len(stack) <= 16 {
				stack = append(stack, token.name)
				if !xmlNoIndent(token.name) {
					indent += 2
				}
			}
		case token.closing:
			for i, s := range slices.Backward(stack) {
				if s != token.name {
					continue
				}
				removed := 0
				for _, name := range stack[i:] {
					if !xmlNoIndent(name) {
						removed += 2
					}
				}
				stack = stack[:i]
				indent = max(0, indent-removed)
				if removed == 0 {
					// Python's indent[:-0] clears the entire indentation.
					indent = 0
				}
				break
			}
			if inline {
				out.WriteString(token.data)
			} else {
				out.WriteString(indentXMLText(token.data, indent))
			}
			out.WriteByte('\n')
		case token.tag || !inline:
			out.WriteString(indentXMLText(token.data, indent))
			out.WriteByte('\n')
		default:
			out.WriteString(trimPythonSpace(token.data))
		}
		copy(window[:], window[1:])
		window[4], _ = next()
	}
	return out.String(), nil
}

type xmlToken struct {
	data        string
	name        string
	tag         bool
	closing     bool
	selfClosing bool
}

func (t xmlToken) opening() bool { return t.tag && !t.closing && !t.selfClosing }

func xmlTokens(text string) iter.Seq[xmlToken] {
	return func(yield func(xmlToken) bool) {
		for len(text) != 0 {
			if text[0] != '<' {
				end := strings.IndexByte(text, '<')
				if end < 0 {
					end = len(text)
				}
				data := text[:end]
				text = text[end:]
				if trimPythonSpace(data) != "" && !yield(xmlToken{data: data}) {
					return
				}
				continue
			}
			endMarker := ">"
			comment := strings.HasPrefix(text, "<!--")
			cdata := strings.HasPrefix(text, "<![CDATA[")
			if comment {
				endMarker = "-->"
			} else if cdata {
				endMarker = "]]>"
			}
			end := strings.Index(text, endMarker)
			if end < 0 {
				end = len(text)
			} else {
				end += len(endMarker)
			}
			data := text[:end]
			name := xmlTagName(data)
			token := xmlToken{
				data: data, name: name, tag: true,
				closing:     strings.HasPrefix(data, "</"),
				selfClosing: comment || cdata || strings.HasSuffix(data, "/>") || xmlVoid(name),
			}
			if !yield(token) {
				return
			}
			text = text[end:]
		}
	}
}

func xmlTagName(text string) string {
	start := -1
	for i := 0; i <= len(text); i++ {
		if i < len(text) && (text[i] >= 'a' && text[i] <= 'z' || text[i] >= 'A' && text[i] <= 'Z' || text[i] >= '0' && text[i] <= '9' || strings.ContainsRune("._:-", rune(text[i]))) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			end := i
			if i < len(text) && text[i] == '=' {
				// Upstream's negative lookahead backtracks one character
				// when the greedy name match is followed by '='.
				end--
			}
			if end > start {
				return strings.ToLower(text[start:end])
			}
			start = -1
		}
	}
	return "<empty>"
}

func xmlVoid(name string) bool {
	switch name {
	case "area", "base", "br", "col", "embed", "hr", "img", "input", "keygen", "link", "meta", "param", "source", "track", "wbr":
		return true
	}
	return false
}

func xmlNoIndent(name string) bool { return name == "xml" || name == "doctype" || name == "html" }

func xmlInlineText(a, b, c xmlToken) bool {
	return a.opening() && !b.tag && !strings.Contains(b.data, "\n") && c.closing && a.name == c.name
}

func xmlInline(w [5]xmlToken) bool {
	t := w[2]
	if !t.tag {
		return xmlInlineText(w[1], t, w[3])
	}
	return xmlInlineText(w[0], w[1], t) || xmlInlineText(t, w[3], w[4]) ||
		t.opening() && w[3].closing && t.name == w[3].name ||
		w[1].opening() && t.closing && w[1].name == t.name
}

func trimPythonSpace(text string) string {
	return strings.TrimFunc(text, func(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f })
}

func indentXMLText(text string, indent int) string {
	text = trimPythonSpace(textwrap.Dedent(strings.Repeat(" ", 32) + text))
	prefix := strings.Repeat(" ", min(indent, 32))
	var out strings.Builder
	for len(text) != 0 {
		end := strings.IndexAny(text, "\n\r\v\f\x1c\x1d\x1e\u0085  ")
		if end < 0 {
			end = len(text)
		} else {
			r, size := utf8.DecodeRuneInString(text[end:])
			end += size
			if r == '\r' && end < len(text) && text[end] == '\n' {
				end++
			}
		}
		line := text[:end]
		if trimPythonSpace(line) != "" {
			out.WriteString(prefix)
		}
		out.WriteString(line)
		text = text[end:]
	}
	return out.String()
}
