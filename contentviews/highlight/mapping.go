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
		if !strings.HasSuffix(text, "\n") && reconstructed.String() == text+"\n" && len(tokens) > 0 {
			last := &tokens[len(tokens)-1]
			last.Value = strings.TrimSuffix(last.Value, "\n")
		} else {
			return nil, fmt.Errorf("highlight %s: lexer changed source text", language)
		}
	}
	if language == "yaml" {
		tokens, err = refineYAMLTags(tokens, lexer)
		if err != nil {
			return nil, err
		}
	}
	var chunks []Chunk
	var gap strings.Builder
	emit := func(tag, text string, captured bool) {
		if !captured {
			gap.WriteString(text)
			return
		}
		if gap.Len() != 0 {
			chunks = append(chunks, Chunk{Text: gap.String()})
			gap.Reset()
		}
		chunks = append(chunks, Chunk{Tag: tag, Text: text})
	}
	attribute := false
	attributeValue := false
	condition := false
	type templateState struct {
		expression bool
		reset      bool
	}
	var templates []templateState
	for i, token := range tokens {
		if language == "xml" && token.Type == chroma.CommentPreproc && strings.HasPrefix(token.Value, "<?") && strings.HasSuffix(token.Value, "?>") {
			instruction, err := xmlInstruction(token.Value)
			if err != nil {
				return nil, err
			}
			for _, chunk := range instruction {
				emit(chunk.Tag, chunk.Text, true)
			}
			continue
		}
		if language == "xml" && token.Type.InSubCategory(chroma.LiteralString) {
			value := token.Value
			if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
				emit("name", value[:1], true)
				emit("", value[1:len(value)-1], true)
				emit("name", value[len(value)-1:], true)
				continue
			}
		}
		tag := tokenTag(tokens, i, language)
		captured := tag != "" || capturedText(tokens, i, language)
		if language == "css" {
			if token.Type == chroma.Keyword && (token.Value == "media" || token.Value == "supports" || token.Value == "container") {
				condition = true
			}
			if token.Value == "{" {
				condition = false
			}
			if token.Value == "*" && !attribute && cssUniversal(tokens, i) {
				tag, captured = "name", true
			}
			if condition && token.Type == chroma.NameTag {
				tag, captured = "", false
				for _, next := range tokens[i+1:] {
					if strings.TrimSpace(next.Value) == "" {
						continue
					}
					if next.Value == ":" {
						tag, captured = "boolean", true
					}
					break
				}
			}
			switch token.Value {
			case "[":
				attribute = true
				attributeValue = false
			case "]":
				attribute = false
			case "=", "~=", "|=", "^=", "$=", "*=":
				attributeValue = attribute
			}
			if attribute && token.Type == chroma.NameTag {
				tag, captured = "", false
				if attributeValue {
					tag, captured = "string", true
				}
			}
		}
		if language == "javascript" {
			closing := false
			if token.Type == chroma.LiteralStringBacktick && token.Value == "`" {
				if len(templates) == 0 || templates[len(templates)-1].expression {
					if len(templates) > 0 {
						templates[len(templates)-1].reset = true
					}
					templates = append(templates, templateState{})
				} else {
					closing = true
				}
			}
			if len(templates) > 0 {
				current := &templates[len(templates)-1]
				if token.Type == chroma.LiteralStringBacktick || token.Type == chroma.LiteralStringInterpol {
					if current.reset {
						tag, captured = "", false
					}
					if token.Type == chroma.LiteralStringInterpol {
						current.expression = token.Value == "${"
					}
				} else if current.expression && captured {
					// A nested capture ending resets the upstream active tag to
					// Text; it does not restore the surrounding template's tag.
					current.reset = true
				}
			}
			if closing {
				templates = templates[:len(templates)-1]
			}
		}
		emit(tag, token.Value, captured)
	}
	if gap.Len() != 0 {
		chunks = append(chunks, Chunk{Text: gap.String()})
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
	if language == "css" && typ == chroma.LiteralNumberHex {
		return "string"
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
		if typ == chroma.Keyword || typ == chroma.Name || typ == chroma.NameVariable {
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
		if token.Value == "this" || token.Value == "super" || token.Value == "NaN" || token.Value == "Infinity" {
			return ""
		}
		if typ == chroma.KeywordConstant || typ.InCategory(chroma.Name) && uppercaseConstant(token.Value) && !javascriptProperty(tokens, index) {
			return "boolean"
		}
		if typ.InCategory(chroma.Keyword) || token.Value == "from" && followedByString(tokens, index) || (token.Value == "get" || token.Value == "set") && !javascriptProperty(tokens, index) && followedByMethod(tokens, index) {
			return "name"
		}
	case "yaml":
		if token.Type == chroma.Punctuation && (strings.HasPrefix(token.Value, "|") || strings.HasPrefix(token.Value, ">")) {
			return "string"
		}
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

func cssUniversal(tokens []chroma.Token, index int) bool {
	for _, token := range tokens[index+1:] {
		if strings.TrimSpace(token.Value) == "" {
			continue
		}
		return token.Type == chroma.NameTag || strings.HasPrefix(token.Value, ":") || strings.Contains(",:{[.>+~", token.Value)
	}
	return true
}

func xmlInstruction(text string) ([]Chunk, error) {
	body := text[2 : len(text)-2]
	nameEnd := strings.IndexAny(body, " \t\r\n")
	if nameEnd < 0 {
		nameEnd = len(body)
	}
	for nameEnd < len(body) && strings.ContainsRune(" \t\r\n", rune(body[nameEnd])) {
		nameEnd++
	}
	wrapped, err := highlightSyntax("<"+body+">", "xml")
	if err != nil {
		return nil, err
	}
	result := []Chunk{{Tag: "name", Text: "<?"}, {Text: body[:nameEnd]}}
	position, start, end := 0, 1+nameEnd, 1+len(body)
	for _, chunk := range wrapped {
		chunkEnd := position + len(chunk.Text)
		if chunkEnd > start && position < end {
			result = append(result, Chunk{Tag: chunk.Tag, Text: chunk.Text[max(0, start-position):min(len(chunk.Text), end-position)]})
		}
		position = chunkEnd
	}
	return append(result, Chunk{Tag: "name", Text: "?>"}), nil
}

func uppercaseConstant(text string) bool {
	if len(text) < 2 {
		return false
	}
	for _, c := range text {
		if c != '_' && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return text[0] == '_' || text[0] >= 'A' && text[0] <= 'Z'
}

func javascriptProperty(tokens []chroma.Token, index int) bool {
	for _, token := range tokens[index+1:] {
		if strings.TrimSpace(token.Value) != "" {
			if token.Value == ":" {
				return true
			}
			break
		}
	}
	for i := index - 1; i >= 0; i-- {
		if strings.TrimSpace(tokens[i].Value) != "" {
			return tokens[i].Value == "." || tokens[i].Value == "get" || tokens[i].Value == "set"
		}
	}
	return false
}

func followedByMethod(tokens []chroma.Token, index int) bool {
	seenName := false
	for _, token := range tokens[index+1:] {
		if strings.TrimSpace(token.Value) == "" {
			continue
		}
		if seenName {
			return token.Value == "("
		}
		if !token.Type.InCategory(chroma.Name) {
			return false
		}
		seenName = true
	}
	return false
}

func followedByString(tokens []chroma.Token, index int) bool {
	for _, token := range tokens[index+1:] {
		if strings.TrimSpace(token.Value) != "" {
			return token.Type.InSubCategory(chroma.LiteralString)
		}
	}
	return false
}

func capturedText(tokens []chroma.Token, index int, language string) bool {
	token := tokens[index]
	switch language {
	case "css":
		return token.Type == chroma.NameVariable || token.Type == chroma.NameFunction || token.Type == chroma.NameBuiltin
	case "javascript":
		if token.Value == "this" || token.Value == "super" {
			return true
		}
		if token.Type.InCategory(chroma.Name) {
			if !javascriptProperty(tokens, index) && len(token.Value) > 0 && token.Value[0] >= 'A' && token.Value[0] <= 'Z' && !uppercaseConstant(token.Value) {
				return false
			}
			return true
		}
	}
	return false
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
