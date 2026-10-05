// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"regexp"
	"strings"

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
	for _, pair := range pairs {
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
	data, err := yaml.Dump(root, yaml.WithV4Defaults())
	return string(data), err
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
