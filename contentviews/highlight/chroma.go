// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package highlight supplies syntax-token adapters for content presentation.
package highlight

import (
	"fmt"
	"strings"

	chroma "github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
)

func tokenizeChroma(text, language string) (tokens []chroma.Token, err error) {
	var name string
	switch language {
	case "css":
		name = "CSS"
	case "javascript":
		name = "JavaScript"
	case "xml":
		name = "XML"
	case "yaml":
		name = "YAML"
	default:
		return nil, fmt.Errorf("unsupported highlighting language %q", language)
	}
	// Chroma iterators can panic after Tokenise has returned successfully.
	defer func() {
		if recover() != nil {
			tokens, err = nil, fmt.Errorf("%s lexer failed", name)
		}
	}()
	lexer := lexers.Get(name)
	if lexer == nil {
		return nil, fmt.Errorf("%s lexer unavailable", name)
	}
	iterator, err := lexer.Tokenise(&chroma.TokeniseOptions{State: "root", EnsureLF: false}, text)
	if err != nil {
		return nil, err
	}
	for token := iterator(); token != chroma.EOF; token = iterator() {
		tokens = append(tokens, token)
	}
	length := 0
	for _, token := range tokens {
		length += len(token.Value)
	}
	if !strings.HasSuffix(text, "\n") && length == len(text)+1 && len(tokens) != 0 {
		last := &tokens[len(tokens)-1]
		if before, ok := strings.CutSuffix(last.Value, "\n"); ok {
			last.Value = before
			if last.Value == "" {
				tokens = tokens[:len(tokens)-1]
			}
		}
	}
	position := 0
	for _, token := range tokens {
		if !strings.HasPrefix(text[position:], token.Value) {
			return nil, fmt.Errorf("%s lexer changed input", name)
		}
		position += len(token.Value)
	}
	if position != len(text) {
		return nil, fmt.Errorf("%s lexer changed input", name)
	}
	return tokens, nil
}
