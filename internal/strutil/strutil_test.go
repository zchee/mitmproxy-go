// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package strutil

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func asciiTable() string {
	b := make([]byte, 128)
	for i := range b {
		b[i] = byte(i)
	}
	return string(b)
}

func TestEscapeControlCharacters(t *testing.T) {
	tests := map[string]struct {
		text        string
		keepSpacing bool
		want        string
	}{
		"success: plain text":                {text: "one", keepSpacing: true, want: "one"},
		"success: NUL":                       {text: "\x00ne", keepSpacing: true, want: ".ne"},
		"success: newline kept":              {text: "\nne", keepSpacing: true, want: "\nne"},
		"success: newline replaced":          {text: "\nne", keepSpacing: false, want: ".ne"},
		"success: non-ASCII kept":            {text: "★", keepSpacing: true, want: "★"},
		"success: invalid UTF-8 kept":        {text: "\xff\x01", keepSpacing: true, want: "\xff."},
		"success: C1 controls are not ASCII": {text: "\u0085", keepSpacing: false, want: "\u0085"},
		"success: ASCII table keeping spacing": {
			text: asciiTable(), keepSpacing: true,
			want: ".........\t\n..\r.................. !\"#$%&'()*+,-./0123456789:;<" +
				"=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.",
		},
		"success: ASCII table": {
			text: asciiTable(), keepSpacing: false,
			want: "................................ !\"#$%&'()*+,-./0123456789:;<" +
				"=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := EscapeControlCharacters(tt.text, tt.keepSpacing)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("EscapeControlCharacters(%q, %t) mismatch (-want +got):\n%s", tt.text, tt.keepSpacing, diff)
			}
		})
	}
}

func TestBytesToEscapedStr(t *testing.T) {
	tests := map[string]struct {
		data               string
		keepSpacing        bool
		escapeSingleQuotes bool
		want               string
	}{
		"success: plain":                          {data: "foo", want: "foo"},
		"success: backspace":                      {data: "\b", want: `\x08`},
		"success: backslash":                      {data: `&!?=\)`, want: `&!?=\\)`},
		"success: UTF-8 bytes":                    {data: "\xc3\xbc", want: `\xc3\xbc`},
		"success: single quote":                   {data: "'", want: "'"},
		"success: double quote":                   {data: `"`, want: `"`},
		"success: escaped single quote":           {data: "'", escapeSingleQuotes: true, want: `\'`},
		"success: double quote never escaped":     {data: `"`, escapeSingleQuotes: true, want: `"`},
		"success: spacing escaped":                {data: "\r\n\t", want: `\r\n\t`},
		"success: spacing kept":                   {data: "\r\n\t", keepSpacing: true, want: "\r\n\t"},
		"success: newline escaped":                {data: "\n", want: `\n`},
		"success: newline kept":                   {data: "\n", keepSpacing: true, want: "\n"},
		"success: literal backslash n":            {data: `\n`, keepSpacing: true, want: `\\n`},
		"success: backslash then newline":         {data: "\\\n", keepSpacing: true, want: "\\\\\n"},
		"success: two backslashes then n":         {data: `\\n`, keepSpacing: true, want: `\\\\n`},
		"success: DEL and high bytes":             {data: "\x7f\x80\xff", want: `\x7f\x80\xff`},
		"success: quote after backslash":          {data: `\'`, want: `\\'`},
		"success: quote after backslash, escaped": {data: `\'`, escapeSingleQuotes: true, want: `\\\'`},
		// Upstream drops a backslash pair in the next two cases.
		"success: two backslashes before a quote":        {data: `\\'`, want: `\\\\'`},
		"success: two backslashes before a kept newline": {data: "\\\\\n", keepSpacing: true, want: "\\\\\\\\\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := BytesToEscapedStr([]byte(tt.data), tt.keepSpacing, tt.escapeSingleQuotes)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("BytesToEscapedStr(%q, %t, %t) mismatch (-want +got):\n%s", tt.data, tt.keepSpacing, tt.escapeSingleQuotes, diff)
			}
		})
	}
}

// Expectations beyond upstream's test cases come from CPython 3.14's
// codecs.escape_decode.
func TestEscapedStrToBytes(t *testing.T) {
	tests := map[string]struct {
		data    string
		want    string
		wantErr string
	}{
		"success: plain":                     {data: "foo", want: "foo"},
		"success: raw control byte":          {data: "\x08", want: "\b"},
		"success: escaped backslash":         {data: `&!?=\\)`, want: `&!?=\)`},
		"success: hex escape":                {data: `\x08`, want: "\b"},
		"success: non-ASCII is UTF-8":        {data: "ü", want: "\xc3\xbc"},
		"success: octal keeps the low byte":  {data: `\777`, want: "\xff"},
		"success: octal 400 wraps to zero":   {data: `\400`, want: "\x00"},
		"success: single octal digit":        {data: `\0`, want: "\x00"},
		"success: octal stops at non-digit":  {data: `\12x`, want: "\nx"},
		"success: unknown escape is kept":    {data: `\q`, want: `\q`},
		"success: escaped non-ASCII is kept": {data: "\\ü", want: "\\\xc3\xbc"},
		"success: line continuation":         {data: "a\\\nb", want: "ab"},
		"success: named escapes":             {data: `\a\b\f\v\"\'`, want: "\a\b\f\v\"'"},
		"success: unicode escapes are kept":  {data: `\N{DASH}ü`, want: `\N{DASH}ü`},
		"success: 8 is not octal":            {data: `\8`, want: `\8`},
		"success: upper-case hex":            {data: `\xAB`, want: "\xab"},
		"error: short hex escape":            {data: `\x4`, wantErr: `invalid \x escape at position 0`},
		"error: bad hex escape":              {data: `ab\xZZ`, wantErr: `invalid \x escape at position 2`},
		"error: trailing backslash":          {data: `abc\`, wantErr: `Trailing \ in string`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := EscapedStrToBytes(tt.data)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("EscapedStrToBytes(%q) error = %v, want %q", tt.data, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("EscapedStrToBytes(%q) error: %v", tt.data, err)
			}
			if diff := cmp.Diff([]byte(tt.want), got); diff != "" {
				t.Errorf("EscapedStrToBytes(%q) mismatch (-want +got):\n%s", tt.data, diff)
			}
		})
	}
}

func TestIsMostlyBin(t *testing.T) {
	gothic := strings.Repeat("\U00010345", 50)
	tests := map[string]struct {
		data string
		want bool
	}{
		"text: one high byte":                  {data: "foo\xff", want: false},
		"binary: many high bytes":              {data: "foo" + strings.Repeat("\xff", 10), want: true},
		"text: empty":                          {data: "", want: false},
		"binary: control bytes":                {data: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09", want: true},
		"text: four-byte UTF-8 at the cutoff":  {data: gothic, want: false},
		"text: cutoff shifted by one":          {data: "a" + gothic, want: false},
		"text: cutoff shifted by two":          {data: "aa" + gothic, want: false},
		"text: cutoff shifted by three":        {data: "aaa" + gothic, want: false},
		"text: cutoff shifted by four":         {data: "aaaa" + gothic, want: false},
		"text: cutoff shifted by five":         {data: "aaaaa" + gothic, want: false},
		"binary: only continuation bytes":      {data: strings.Repeat("\x80", 150), want: true},
		"text: continuation byte at cutoff +1": {data: strings.Repeat("a", 100) + "\x80", want: false},
		"text: continuation byte at cutoff +2": {data: strings.Repeat("a", 100) + "\x80\x80", want: false},
		"text: continuation byte at cutoff +3": {data: strings.Repeat("a", 100) + "\x80\x80\x80", want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := IsMostlyBin([]byte(tt.data)); got != tt.want {
				t.Errorf("IsMostlyBin(%q) = %t, want %t", tt.data, got, tt.want)
			}
		})
	}
}

func TestIsXML(t *testing.T) {
	tests := map[string]struct {
		data string
		want bool
	}{
		"not xml: empty":         {data: "", want: false},
		"not xml: text":          {data: "foo", want: false},
		"xml: tag":               {data: "<foo", want: true},
		"xml: leading spaces":    {data: "  \n<foo", want: true},
		"xml: carriage return":   {data: "\r<foo", want: true},
		"xml: CRLF":              {data: "\r\n<foo", want: true},
		"not xml: CRLF and text": {data: "\r\nfoo", want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := IsXML([]byte(tt.data)); got != tt.want {
				t.Errorf("IsXML(%q) = %t, want %t", tt.data, got, tt.want)
			}
		})
	}
}

func TestCleanHangingNewline(t *testing.T) {
	tests := map[string]struct {
		text string
		want string
	}{
		"success: trailing newline removed": {text: "foo\n", want: "foo"},
		"success: no newline":               {text: "foo", want: "foo"},
		"success: only one newline removed": {text: "foo\n\n", want: "foo\n"},
		"success: empty":                    {text: "", want: ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := CleanHangingNewline(tt.text); got != tt.want {
				t.Errorf("CleanHangingNewline(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

// The expected lines come from upstream's hexdump on CPython 3.14.
func TestHexDump(t *testing.T) {
	got := slices.Collect(HexDump(bytes.Repeat([]byte("one\x00"), 10)))
	want := []HexDumpLine{
		{Offset: "0000000000", Hex: "6f 6e 65 00 6f 6e 65 00 6f 6e 65 00 6f 6e 65 00", Text: "one.one.one.one."},
		{Offset: "0000000010", Hex: "6f 6e 65 00 6f 6e 65 00 6f 6e 65 00 6f 6e 65 00", Text: "one.one.one.one."},
		{Offset: "0000000020", Hex: "6f 6e 65 00 6f 6e 65 00                        ", Text: "one.one."},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("HexDump mismatch (-want +got):\n%s", diff)
	}

	got = slices.Collect(HexDump([]byte("\x7f\x80\xffA\t")))
	want = []HexDumpLine{{Offset: "0000000000", Hex: "7f 80 ff 41 09" + strings.Repeat(" ", 33), Text: "...A."}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("HexDump(non-printable) mismatch (-want +got):\n%s", diff)
	}

	if lines := slices.Collect(HexDump(nil)); len(lines) != 0 {
		t.Errorf("HexDump(nil) = %v, want no lines", lines)
	}

	for range HexDump(make([]byte, 64)) {
		break // An early break must not panic.
	}
}

// escapeQuotes matches quoted strings that end at an unescaped quote. It is
// the RE2 form of upstream's "'" + SINGLELINE_CONTENT + NO_ESCAPE + "'",
// whose lookbehind Go's regexp does not support.
var escapeQuotes = regexp.MustCompile(`(?m)'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"`)

func TestSplitSpecialAreas(t *testing.T) {
	tests := map[string]struct {
		data  string
		areas *regexp.Regexp
		want  []string
	}{
		"success: no areas": {data: "foo", areas: escapeQuotes, want: []string{"foo"}},
		"success: one quoted area": {
			data: "foo 'bar' baz", areas: escapeQuotes, want: []string{"foo ", "'bar'", " baz"},
		},
		"success: escaped quote inside": {
			data: `foo 'b\'a"r' baz`, areas: escapeQuotes, want: []string{"foo ", `'b\'a"r'`, " baz"},
		},
		"success: multi-line comment": {
			data: "foo\n/*bar\nbaz*/\nqux", areas: regexp.MustCompile(`(?m)/\*[\s\S]+?\*/`),
			want: []string{"foo\n", "/*bar\nbaz*/", "\nqux"},
		},
		"success: line comment up to end of line": {
			data: "foo\n//bar\nbaz", areas: regexp.MustCompile(`(?m)//.+$`),
			want: []string{"foo\n", "//bar", "\nbaz"},
		},
		"success: area at both ends": {
			data: "'a'b'c'", areas: escapeQuotes, want: []string{"", "'a'", "b", "'c'", ""},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := SplitSpecialAreas(tt.data, tt.areas)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("SplitSpecialAreas(%q) mismatch (-want +got):\n%s", tt.data, diff)
			}
			if joined := strings.Join(got, ""); joined != tt.data {
				t.Errorf("joined parts = %q, want %q", joined, tt.data)
			}
		})
	}
}

func TestEscapeSpecialAreas(t *testing.T) {
	tests := map[string]struct {
		data string
		want string
	}{
		"success: nothing to escape": {data: `foo "bar" baz`, want: `foo "bar" baz`},
		"success: only inside areas": {data: `foo "b*r" b*z`, want: "foo \"br\" b*z"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := EscapeSpecialAreas(tt.data, escapeQuotes, "*")
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("EscapeSpecialAreas(%q) mismatch (-want +got):\n%s", tt.data, diff)
			}
			if back := UnescapeSpecialAreas(got); back != tt.data {
				t.Errorf("UnescapeSpecialAreas(%q) = %q, want %q", got, back, tt.data)
			}
		})
	}
}

func TestCutAfterNLines(t *testing.T) {
	tests := map[string]struct {
		content string
		n       int
		want    string
	}{
		"success: first line":         {content: "foo\nbar\nbaz", n: 1, want: "foo\n"},
		"success: two lines":          {content: "foo\nbar\nbaz", n: 2, want: "foo\nbar\n"},
		"success: fewer lines than n": {content: "foo\nbar", n: 100, want: "foo\nbar"},
		"success: empty first line":   {content: "\nbar", n: 1, want: "\n"},
		"success: exact line count":   {content: "foo\nbar\n", n: 2, want: "foo\nbar\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := CutAfterNLines(tt.content, tt.n); got != tt.want {
				t.Errorf("CutAfterNLines(%q, %d) = %q, want %q", tt.content, tt.n, got, tt.want)
			}
		})
	}

	defer func() {
		if recover() == nil {
			t.Error("CutAfterNLines(_, 0) did not panic")
		}
	}()
	CutAfterNLines("foo", 0)
}

func FuzzEscapedRoundTrip(f *testing.F) {
	for _, seed := range []string{"foo", "\x00\xff", `\n`, "\\\n", "'\"", "\r\n\t"} {
		f.Add([]byte(seed), false, false)
	}
	f.Fuzz(func(t *testing.T, data []byte, keepSpacing, escapeSingleQuotes bool) {
		escaped := BytesToEscapedStr(data, keepSpacing, escapeSingleQuotes)
		got, err := EscapedStrToBytes(escaped)
		if err != nil {
			t.Fatalf("EscapedStrToBytes(%q) error: %v", escaped, err)
		}
		if !bytes.Equal(data, got) {
			t.Fatalf("round trip of %q via %q gave %q", data, escaped, got)
		}
	})
}
