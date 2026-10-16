// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build ignore

package highlight

import (
	"fmt"
	"strings"

	chroma "github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
)

func highlightSyntax(text, language string) ([]Chunk, error) {
	lexer := lexers.Get(language)
	if lexer == nil {
		return nil, fmt.Errorf("missing syntax lexer: %s", language)
	}
	iterator, err := lexer.Tokenise(&chroma.TokeniseOptions{State: "root", EnsureLF: false}, text)
	if err != nil {
		return nil, fmt.Errorf("highlight %s: %w", language, err)
	}
	var tokens []chroma.Token
	var reconstructed strings.Builder
	for token := iterator(); token != chroma.EOF; token = iterator() {
		tokens = append(tokens, token)
		reconstructed.WriteString(token.Value)
	}
	if reconstructed.String() != text {
		return nil, fmt.Errorf("highlight %s: lexer changed source text", language)
	}
	if language == "yaml" {
		tokens, err = refineYAMLTags(tokens, lexer)
		if err != nil {
			return nil, err
		}
	}
	var chunks []Chunk
	for i, token := range tokens {
		if language == "xml" && token.Type.InSubCategory(chroma.LiteralString) {
			value := token.Value
			if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
				chunks = append(chunks, Chunk{Tag: "name", Text: value[:1]}, Chunk{Text: value[1 : len(value)-1]}, Chunk{Tag: "name", Text: value[len(value)-1:]})
				continue
			}
		}
		chunks = append(chunks, Chunk{Tag: tokenTag(tokens, i, language), Text: token.Value})
	}
	return coalesce(chunks), nil
}

func tokenTag(tokens []chroma.Token, index int, language string) string {
	token := tokens[index]
	typ := token.Type
	if language == "xml" {
		switch {
		case typ == chroma.NameTag || typ == chroma.NameAttribute:
			return "name"
		case typ.InSubCategory(chroma.Comment):
			return "comment"
		default:
			return ""
		}
	}
	if typ.InSubCategory(chroma.Comment) {
		return "comment"
	}
	if typ.InSubCategory(chroma.LiteralNumber) {
		return "number"
	}
	if typ.InSubCategory(chroma.LiteralString) {
		return "string"
	}
	switch language {
	case "css":
		if typ == chroma.NameTag {
			return "name"
		}
		if typ == chroma.KeywordType && index > 0 && tokens[index-1].Type.InSubCategory(chroma.LiteralNumber) {
			return "number"
		}
		if typ == chroma.Keyword || typ == chroma.Name {
			for _, next := range tokens[index+1:] {
				if strings.Trim(next.Value, " \t\n\r\v\f") == "" {
					continue
				}
				if next.Value == ":" {
					return "boolean"
				}
				break
			}
		}
	case "javascript":
		if typ == chroma.KeywordConstant {
			return "boolean"
		}
		if typ.InCategory(chroma.Keyword) {
			return "name"
		}
	case "yaml":
		if typ == chroma.NameTag || typ == chroma.NameProperty || typ == chroma.CommentPreproc && strings.HasPrefix(token.Value, "!") {
			return "name"
		}
		if typ == chroma.KeywordConstant {
			return "boolean"
		}
		if typ == chroma.Literal || typ == chroma.LiteralDate {
			return "string"
		}
	}
	return ""
}

func refineYAMLTags(tokens []chroma.Token, lexer chroma.Lexer) ([]chroma.Token, error) {
	var result []chroma.Token
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if token.Value != "!" || token.Type != chroma.Text && token.Type != chroma.Error {
			result = append(result, token)
			continue
		}
		tag := "!"
		if i+1 < len(tokens) {
			next := tokens[i+1]
			if next.Type == chroma.Literal {
				end := strings.IndexAny(next.Value, " \t\r\n,[]{}")
				if strings.HasPrefix(next.Value, "<") {
					if close := strings.IndexByte(next.Value, '>'); close >= 0 {
						end = close + 1
					}
				}
				if end < 0 {
					end = len(next.Value)
				}
				tag += next.Value[:end]
				result = append(result, chroma.Token{Type: chroma.NameProperty, Value: tag})
				// The plain-scalar rule swallowed the value after the tag. Lex
				// that suffix separately so its scalar type is visible again.
				it, err := lexer.Tokenise(&chroma.TokeniseOptions{State: "root", EnsureLF: false}, next.Value[end:])
				if err != nil {
					return nil, fmt.Errorf("highlight yaml tag value: %w", err)
				}
				for tail := it(); tail != chroma.EOF; tail = it() {
					result = append(result, tail)
				}
				i++
				continue
			}
		}
		result = append(result, chroma.Token{Type: chroma.NameProperty, Value: tag})
	}
	return result, nil
}
