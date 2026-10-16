// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build ignore

package highlight

import (
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestHighlightLanguagesTags(t *testing.T) {
	tests := map[string]struct {
		get  func() []string
		want []string
	}{
		"languages": {Languages, []string{"css", "javascript", "xml", "yaml", "none", "error"}},
		"tags":      {Tags, []string{"name", "string", "number", "boolean", "comment", "error"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := tt.get()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("vocabulary mismatch (-want +got):\n%s", diff)
			}
			got[0] = "changed"
			if diff := cmp.Diff(tt.want, tt.get()); diff != "" {
				t.Fatalf("caller mutated shared vocabulary (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHighlightChunks(t *testing.T) {
	tests := map[string]struct {
		text     string
		language string
		want     []Chunk
		wantErr  string
	}{
		"none empty":                  {language: "none", want: []Chunk{{}}},
		"error empty":                 {language: "error", want: []Chunk{{Tag: "error"}}},
		"none preserves controls":     {text: "a\r\n\x1b[31m\t", language: "none", want: []Chunk{{Text: "a\r\n\x1b[31m\t"}}},
		"error text":                  {text: "failure", language: "error", want: []Chunk{{Tag: "error", Text: "failure"}}},
		"unsupported exact case":      {language: "CSS", wantErr: "Unsupported language: CSS"},
		"unsupported empty":           {wantErr: "Unsupported language: "},
		"lossy invalid bytes":         {text: "a\xff\xfez", language: "none", want: []Chunk{{Text: "a��z"}}},
		"lossy incomplete prefix":     {text: "a\xe2\x82z", language: "error", want: []Chunk{{Tag: "error", Text: "a�z"}}},
		"lossy overlong":              {text: "\xe0\x80\x80", language: "none", want: []Chunk{{Text: "���"}}},
		"valid replacement character": {text: "�", language: "none", want: []Chunk{{Text: "�"}}},
		"xml attribute quote boundaries": {
			text: "<item key='value'>text</item>", language: "xml",
			want: []Chunk{{Tag: "name", Text: "<item key='"}, {Text: "value"}, {Tag: "name", Text: "'>"}, {Text: "text"}, {Tag: "name", Text: "</item>"}},
		},
		"css units and property": {
			text: "p { width: 12px; }", language: "css",
			want: []Chunk{{Tag: "name", Text: "p "}, {Text: "{ "}, {Tag: "boolean", Text: "width"}, {Text: ": "}, {Tag: "number", Text: "12px"}, {Text: "; }"}},
		},
		"javascript keyword whitespace": {
			text: "let value = true;\r\n", language: "javascript",
			want: []Chunk{{Tag: "name", Text: "let "}, {Text: "value = "}, {Tag: "boolean", Text: "true"}, {Text: ";\r\n"}},
		},
		"yaml local tag with string": {
			text: "value: !custom-type 'text'\n", language: "yaml",
			want: []Chunk{{Tag: "name", Text: "value"}, {Text: ": "}, {Tag: "name", Text: "!custom-type "}, {Tag: "string", Text: "'text'\n"}},
		},
		"yaml verbatim tag": {
			text: "value: !<tag:example.org,2000:kind> 42\n", language: "yaml",
			want: []Chunk{{Tag: "name", Text: "value"}, {Text: ": "}, {Tag: "name", Text: "!<tag:example.org,2000:kind> "}, {Tag: "number", Text: "42\n"}},
		},
		"yaml tag syntax inside a string": {
			text: "value: '!custom text'\n", language: "yaml",
			want: []Chunk{{Tag: "name", Text: "value"}, {Text: ": "}, {Tag: "string", Text: "'!custom text'\n"}},
		},
		"yaml tag syntax inside a comment": {
			text: "# !custom text\n", language: "yaml",
			want: []Chunk{{Tag: "comment", Text: "# !custom text\n"}},
		},
		"yaml explicit local tag": {
			text: "number: !fixed32 42  # comment\n", language: "yaml",
			want: []Chunk{{Tag: "name", Text: "number"}, {Text: ": "}, {Tag: "name", Text: "!fixed32 "}, {Tag: "number", Text: "42  "}, {Tag: "comment", Text: "# comment\n"}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Highlight(tt.text, tt.language)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("Highlight error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("chunks differ (-want +got):\n%s", diff)
			}
		})
	}
}

func TestChunkCoalescing(t *testing.T) {
	tests := map[string]struct {
		input []Chunk
		want  []Chunk
	}{
		"ascii whitespace inherits preceding tag": {
			input: []Chunk{{Tag: "name", Text: "key"}, {Text: " \t\n\r\v\f"}, {Text: ":"}},
			want:  []Chunk{{Tag: "name", Text: "key \t\n\r\v\f"}, {Text: ":"}},
		},
		"unicode whitespace is not ascii": {
			input: []Chunk{{Tag: "name", Text: "key"}, {Text: " "}},
			want:  []Chunk{{Tag: "name", Text: "key"}, {Text: " "}},
		},
		"leading whitespace stays unstyled": {
			input: []Chunk{{Text: "  "}, {Tag: "name", Text: "key"}},
			want:  []Chunk{{Text: "  "}, {Tag: "name", Text: "key"}},
		},
		"same tag joins": {
			input: []Chunk{{Tag: "name", Text: "one"}, {Tag: "name", Text: "two"}},
			want:  []Chunk{{Tag: "name", Text: "onetwo"}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, coalesce(tt.input)); diff != "" {
				t.Fatalf("coalescing mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHighlightConcurrent(t *testing.T) {
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			chunks, err := Highlight("<item key='value'>text</item>", "xml")
			if err != nil {
				t.Error(err)
				return
			}
			var text strings.Builder
			for _, chunk := range chunks {
				text.WriteString(chunk.Text)
			}
			if text.String() != "<item key='value'>text</item>" {
				t.Errorf("concurrent render changed source: %q", text.String())
			}
		})
	}
	workers.Wait()
}
