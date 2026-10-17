// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package highlight supplies syntax-token adapters for content presentation.
package highlight

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	chroma "github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
)

const (
	maxHighlightBytes = 256 << 10
	lexerDeadlineBase = 250 * time.Millisecond
)

// lexerDeadline bounds the wait for tokenization. It is lexerDeadlineBase in
// production builds and raceMultiplier times longer under the race detector,
// whose instrumentation slows the lexers far beyond the production budget.
var lexerDeadline = lexerDeadlineBase * raceMultiplier

// ErrInputTooLarge indicates that syntax highlighting would exceed its input cap.
var ErrInputTooLarge = errors.New("syntax highlighting input exceeds 256 KiB")

// ErrTimeout indicates that syntax highlighting exceeded its time budget.
var ErrTimeout = errors.New("syntax highlighting exceeded its deadline")

func tokenizeChroma(text, language string) ([]chroma.Token, error) {
	if len(text) > maxHighlightBytes {
		return nil, ErrInputTooLarge
	}
	ctx, cancel := context.WithTimeout(context.Background(), lexerDeadline)
	defer cancel()
	type result struct {
		tokens []chroma.Token
		err    error
	}
	finished := make(chan result, 1)
	go func() {
		tokens, err := tokenizeChromaContext(ctx, text, language)
		finished <- result{tokens: tokens, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ErrTimeout
	case value := <-finished:
		return value.tokens, value.err
	}
}

func tokenizeChromaContext(ctx context.Context, text, language string) (tokens []chroma.Token, err error) {
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
		if value := recover(); value != nil {
			slog.Error("syntax lexer panicked", "language", name, "panic_type", fmt.Sprintf("%T", value))
			panic(value)
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
	for {
		if ctx.Err() != nil {
			return nil, ErrTimeout
		}
		token := iterator()
		if token == chroma.EOF {
			break
		}
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
