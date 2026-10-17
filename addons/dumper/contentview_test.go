// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dumper

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/internal/vtcodes"
)

func TestContentviewHighlight(t *testing.T) {
	yellow := vtcodes.Style{FG: "yellow"}.Render
	green := vtcodes.Style{FG: "green"}.Render
	blue := vtcodes.Style{FG: "blue"}.Render
	magenta := vtcodes.Style{FG: "magenta"}.Render
	dim := vtcodes.Style{Dim: new(true)}.Render
	red := vtcodes.Style{FG: "red"}.Render
	stripANSI := regexp.MustCompile("\x1b\\[[0-9;]*m")
	tests := map[string]struct {
		text      string
		language  string
		vt        bool
		want      string
		plain     string
		wantError bool
	}{
		"pipe remains plain":               {text: "name: 'value'", language: "yaml", want: "    name: 'value'\n"},
		"pipe does not invoke highlighter": {text: "text", language: "unsupported", want: "    text\n"},
		"yaml exact styled spans": {
			text: "name: 'value'\ncount: 2\nflag: true\n# note", language: "yaml", vt: true,
			want:  "    " + yellow("name") + ": " + green("'value'") + "\n    " + yellow("count") + ": " + blue("2") + "\n    " + yellow("flag") + ": " + magenta("true") + "\n    " + dim("# note") + "\n",
			plain: "    name: 'value'\n    count: 2\n    flag: true\n    # note\n",
		},
		"error style": {text: "failure", language: "error", vt: true, want: "    " + red("failure") + "\n", plain: "    failure\n"},
		"untrusted escape is not terminal control": {text: "\x1b[31munsafe", language: "none", vt: true, want: "    .[31munsafe\n", plain: "    .[31munsafe\n"},
		"trim logical content before styling":      {text: " \n  text \n ", language: "none", vt: true, want: "    text\n", plain: "    text\n"},
		"whitespace only":                          {text: "\n \t", language: "none", vt: true, want: "\n", plain: "\n"},
		"all line separators":                      {text: "a\r\nb\rc\u0085d e f", language: "none", vt: true, want: "    a\n    b\n    c\n    d\n    e\n    f\n", plain: "    a\n    b\n    c\n    d\n    e\n    f\n"},
		"invalid utf8":                             {text: "x\xff", language: "none", vt: true, want: "    x�\n", plain: "    x�\n"},
		"unknown syntax returns an error":          {text: "text", language: "unsupported", vt: true, wantError: true},
		"internal blank line":                      {text: "a\n\nb", language: "none", vt: true, want: "    a\n    \n    b\n", plain: "    a\n    \n    b\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			dumper := Dumper{out: &output, outHasVT: tt.vt}
			err := dumper.echoContentview(tt.text, tt.language)
			if (err != nil) != tt.wantError {
				t.Fatalf("echoContentview error=%v, want error %v", err, tt.wantError)
			}
			if diff := cmp.Diff(tt.want, output.String()); diff != "" {
				t.Fatalf("styled output differs (-want +got):\n%s", diff)
			}
			if tt.vt && !tt.wantError {
				if diff := cmp.Diff(tt.plain, stripANSI.ReplaceAllString(output.String(), "")); diff != "" {
					t.Fatalf("ANSI-free output differs (-want +got):\n%s", diff)
				}
			}
		})
	}
	t.Run("message", func(t *testing.T) {
		tests := map[string]struct {
			detail int
			cutoff int
			cut    bool
		}{
			"cutoff keeps full formatted body": {detail: 3, cutoff: 1, cut: true},
			"full detail":                      {detail: 4, cutoff: 1},
			"within cutoff":                    {detail: 3, cutoff: 100},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				f := testflow.TFlow(testflow.WithResponse)
				f.Response.Headers.Set("content-type", "text/css")
				f.Response.SetContent([]byte("p { color: red; width: 1px; }"))
				render := func(vt bool) string {
					d, m, out := setup(t)
					d.outHasVT = vt
					if err := configure(t, m, map[string]any{"flow_detail": tt.detail, "content_view_lines_cutoff": tt.cutoff}); err != nil {
						t.Fatal(err)
					}
					if err := d.echoMessage(f.Response, f); err != nil {
						t.Fatal(err)
					}
					return out.String()
				}
				plain, styled := render(false), render(true)
				if !strings.Contains(styled, "\x1b[") {
					t.Fatal("terminal body has no styles")
				}
				if diff := cmp.Diff(plain, stripANSI.ReplaceAllString(styled, "")); diff != "" {
					t.Fatalf("terminal and pipe body differ (-pipe +terminal):\n%s", diff)
				}
				if got := strings.Contains(plain, "(cut off)"); got != tt.cut {
					t.Fatalf("cutoff notice=%v, want %v", got, tt.cut)
				}
				if !strings.Contains(plain, "color: red") || !strings.Contains(plain, "width: 1px") {
					t.Fatalf("full body was not preserved: %q", plain)
				}
			})
		}
	})
}

func TestContentviewHighlightBounds(t *testing.T) {
	tests := map[string]struct {
		text string
		want string
	}{
		"input above the syntax cap": {
			text: strings.Repeat("a: 1\n", 60000),
			want: strings.Repeat("    a: 1\n", 60000),
		},
		"lexer deadline": {
			text: strings.Repeat("! ", 4000),
			want: "    " + strings.TrimSpace(strings.Repeat("! ", 4000)) + "\n",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			dumper := Dumper{out: &output, outHasVT: true}
			if err := dumper.echoContentview(tt.text, "yaml"); err != nil {
				t.Fatalf("echoContentview returned %v, want the uncoloured text", err)
			}
			if strings.Contains(output.String(), "\x1b[") {
				t.Fatal("bounded highlighting emitted terminal styles")
			}
			if diff := cmp.Diff(tt.want, output.String()); diff != "" {
				t.Fatalf("uncoloured output differs (-want +got):\n%s", diff)
			}
		})
	}
}
