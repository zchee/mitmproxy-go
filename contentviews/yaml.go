// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	yaml "go.yaml.in/yaml/v4"
)

// yamlPairs preserves the first position of each key and merges nonempty
// repeated values into sequences, as the upstream contentview helpers do.
func yamlPairs(pairs [][2]string) (string, error) {
	if len(pairs) == 0 {
		return "", nil
	}
	root := &yaml.Node{Kind: yaml.MappingNode}
	values := make(map[string]*yaml.Node)
	hasInvalidUTF8 := false
	for _, pair := range pairs {
		hasInvalidUTF8 = hasInvalidUTF8 || !utf8.ValidString(pair[0]) || !utf8.ValidString(pair[1])
		value := yamlString(pair[1])
		previous, ok := values[pair[0]]
		switch {
		case !ok:
			values[pair[0]] = value
			root.Content = append(root.Content, yamlString(pair[0]), value)
		case previous.Kind == yaml.SequenceNode:
			previous.Content = append(previous.Content, value)
		case previous.Value == "":
			// Upstream tests the previous value's truthiness, not membership.
			*previous = *value
		default:
			first := *previous
			*previous = yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{&first, value}}
		}
	}
	if !hasInvalidUTF8 {
		data, err := yaml.Dump(root, yaml.WithV4Defaults())
		return string(data), err
	}
	// go-yaml turns invalid UTF-8 into !!binary. Python instead represents each
	// undecodable byte as a surrogate escape in a string. Reserve scalar tokens
	// absent from every input, then replace only their complete quoted spelling.
	used := make(map[string]bool)
	for _, pair := range pairs {
		for _, text := range pair {
			for {
				_, rest, found := strings.Cut(text, "\x00")
				if !found {
					break
				}
				field, _, found := strings.Cut(rest, "\x00")
				if !found {
					break
				}
				used[field] = true
				text = rest[len(field):]
			}
		}
	}
	nonce := 0
	for used[strconv.Itoa(nonce)] {
		nonce++
	}
	prefix := "\x00" + strconv.Itoa(nonce) + "\x00"
	var replacements []string
	prepare := func(node *yaml.Node, key bool) {
		if utf8.ValidString(node.Value) {
			return
		}
		original := node.Value
		marker := prefix + strconv.Itoa(len(replacements))
		if key && (utf8.RuneCountInString(original) >= 128 || strings.ContainsAny(original, "\n\U00000085\U00002028\U00002029")) {
			marker += "\n"
		}
		node.Value = marker
		node.Style = yaml.DoubleQuotedStyle
		replacements = append(replacements, yamlSurrogateQuote(marker), yamlSurrogateQuote(original))
	}
	for i, node := range root.Content {
		if node.Kind == yaml.SequenceNode {
			for _, value := range node.Content {
				prepare(value, false)
			}
		} else {
			prepare(node, i%2 == 0)
		}
	}
	data, err := yaml.Dump(root, yaml.WithV4Defaults())
	if err != nil || len(replacements) == 0 {
		return string(data), err
	}
	return strings.NewReplacer(replacements...).Replace(string(data)), nil
}

// yamlSurrogateQuote is the double-quoted scalar spelling for malformed UTF-8.
// Unlike strconv.Quote, its invalid bytes become Python surrogateescape values.
func yamlSurrogateQuote(text string) string {
	var out strings.Builder
	out.WriteByte('"')
	for len(text) != 0 {
		r, size := utf8.DecodeRuneInString(text)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&out, "\\uDC%02X", text[0])
			text = text[1:]
			continue
		}
		text = text[size:]
		switch r {
		case 0:
			out.WriteString(`\0`)
		case '\a':
			out.WriteString(`\a`)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\v':
			out.WriteString(`\v`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		case 0x1b:
			out.WriteString(`\e`)
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case 0x85:
			out.WriteString(`\N`)
		case 0x2028:
			out.WriteString(`\L`)
		case 0x2029:
			out.WriteString(`\P`)
		default:
			switch {
			case r < 0x20 || r >= 0x7f && r < 0xa0:
				fmt.Fprintf(&out, "\\x%02X", r)
			case r == 0xfeff || r == 0xfffe || r == 0xffff:
				fmt.Fprintf(&out, "\\u%04X", r)
			default:
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

// These YAML 1.2 implicit types are resolved lexically by ruamel, even when
// numbers overflow float64 or a timestamp names an invalid calendar date.
var yamlImplicitScalar = regexp.MustCompile(`^(?:=|[-+]?(?:0b[01_]+|0o?[0-7_]+|[0-9][0-9_]*|0x[0-9a-fA-F_]+)|` +
	`[-+]?(?:[0-9][0-9_]*\.[0-9_]*(?:[eE][-+]?[0-9]+)?|[0-9][0-9_]*[eE][-+]?[0-9]+|\.[0-9_]+(?:[eE][-+][0-9]+)?)|` +
	`[0-9]{4}-(?:[0-9]{2}-[0-9]{2}|[0-9]{1,2}-[0-9]{1,2}(?:[Tt]|[ \t]+)[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9]{1,2}(?::[0-9]{2})?))?))$`)

func yamlString(text string) *yaml.Node {
	node := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: text}
	if strings.ContainsRune(text, '\n') || strings.ContainsRune(text, '\'') && !yamlPlain(text) {
		node.Style = yaml.DoubleQuotedStyle
	} else if yamlImplicitScalar.MatchString(text) {
		node.Style = yaml.SingleQuotedStyle
	}
	return node
}

func yamlPlain(text string) bool {
	if text == "" || strings.ContainsAny(text[:1], "#,[]{}&*!|>'\"%@` ") ||
		strings.HasPrefix(text, "---") || strings.HasPrefix(text, "...") || strings.HasSuffix(text, " ") {
		return false
	}
	for i, r := range text {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 || r == 0xfeff {
			return false
		}
		if r == ':' || i == 0 && (r == '?' || r == '-') {
			if i+1 == len(text) || strings.ContainsAny(text[i+1:i+2], " \t\r\n") {
				return false
			}
		}
		if r == '#' && i > 0 && text[i-1] == ' ' {
			return false
		}
	}
	return true
}
