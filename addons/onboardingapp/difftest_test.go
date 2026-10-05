// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package onboardingapp

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/html"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/options"
)

func TestIndexPython(t *testing.T) {
	python := difftest.Python(t, `
import sys
from mitmproxy.addons.onboardingapp import app
with app.test_client() as client:
    sys.stdout.buffer.write(client.get("/").data)
`, nil)
	w := httptest.NewRecorder()
	New(options.New()).ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), "GET", "/", nil))
	if diff := gocmp.Diff(htmlTokens(t, python), htmlTokens(t, w.Body.Bytes())); diff != "" {
		t.Errorf("rendered page (-python +go):\n%s", diff)
	}
}

// Compare tags, attributes and non-whitespace text. Template indentation and
// html/template's removal of comments do not affect the rendered page.
func htmlTokens(t *testing.T, document []byte) []html.Token {
	t.Helper()
	var tokens []html.Token
	parser := html.NewTokenizer(bytes.NewReader(document))
	for {
		switch kind := parser.Next(); kind {
		case html.ErrorToken:
			if err := parser.Err(); err != io.EOF {
				t.Fatal(err)
			}
			return tokens
		case html.CommentToken:
			continue
		default:
			token := parser.Token()
			if kind == html.TextToken {
				token.Data = strings.Join(strings.Fields(token.Data), " ")
				if token.Data == "" {
					continue
				}
			}
			tokens = append(tokens, token)
		}
	}
}
