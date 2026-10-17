// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package highlight

import (
	"strings"
	"sync"
	"testing"

	chroma "github.com/alecthomas/chroma/v2"
	gocmp "github.com/google/go-cmp/cmp"
)

func TestChromaTokenization(t *testing.T) {
	tests := map[string]struct {
		language string
		text     string
	}{
		"css":                {"css", "a { color: red; }\n"},
		"javascript":         {"javascript", "const value = 7;\n"},
		"xml":                {"xml", "<root key=\"value\">text</root>\n"},
		"yaml":               {"yaml", "key: true\n"},
		"empty":              {"yaml", ""},
		"carriage_returns":   {"javascript", "let a = 1;\r\nlet b = 2;\r"},
		"eof_comment":        {"javascript", "// comment"},
		"real_final_newline": {"javascript", "// comment\n"},
		"no_final_newline":   {"css", "a {}"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tokens, err := tokenizeChroma(test.text, test.language)
			if err != nil {
				t.Fatal(err)
			}
			var reconstructed strings.Builder
			for _, token := range tokens {
				reconstructed.WriteString(token.Value)
			}
			if diff := gocmp.Diff(test.text, reconstructed.String()); diff != "" {
				t.Fatalf("reconstruction (-want +got):\n%s", diff)
			}
			if name == "eof_comment" {
				comments := 0
				for _, token := range tokens {
					if token.Value == "" {
						continue
					}
					if token.Type != chroma.CommentSingle {
						t.Fatalf("EOF comment classification: %#v", tokens)
					}
					comments++
				}
				if comments != 1 {
					t.Fatalf("EOF comment token count: %d", comments)
				}
			}
		})
	}
}

func TestChromaUnsupportedLanguage(t *testing.T) {
	for name, language := range map[string]string{"unknown": "not-a-language", "none": "none", "error": "error"} {
		t.Run(name, func(t *testing.T) {
			if tokens, err := tokenizeChroma("text", language); err == nil || tokens != nil {
				t.Fatalf("got %v, %v", tokens, err)
			}
		})
	}
}

func TestChromaIndependentCalls(t *testing.T) {
	const text = "const value = 'hello'; // tail"
	want, err := tokenizeChroma(text, "javascript")
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			got, err := tokenizeChroma(text, "javascript")
			if err != nil {
				t.Error(err)
				return
			}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Errorf("tokens (-want +got):\n%s", diff)
			}
			if len(got) != 0 {
				got[0].Value = "changed"
			}
		})
	}
	group.Wait()
	got, err := tokenizeChroma(text, "javascript")
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Fatalf("caller mutation leaked:\n%s", diff)
	}
}
