// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package regex

import (
	json "encoding/json/v2"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestPatternPython(t *testing.T) {
	type vector struct {
		Pattern     []byte `json:"pattern"`
		Replacement []byte `json:"replacement"`
		Subject     []byte `json:"subject"`
		Flags       Flags  `json:"flags"`
		Count       int    `json:"count"`
	}
	type result struct {
		Sub    []byte   `json:"sub"`
		Groups [][]byte `json:"groups"`
		Spans  [][2]int `json:"spans"`
		Error  bool     `json:"error"`
	}
	tests := map[string]struct {
		pattern, replacement, subject string
		flags                         Flags
		count                         int
	}{
		"success: RE2 captures":                            {pattern: `(a)(b)`, replacement: `\2\1-$`, subject: "abab"},
		"success: named captures":                          {pattern: `(?P<first>a)(b)`, replacement: `\g<2>\g<first>\g<0>`, subject: "ab"},
		"success: named numeric backreference":             {pattern: `(?P<first>a)(b)\1`, replacement: `\2\1`, subject: "aba"},
		"success: named backreference":                     {pattern: `(?P<first>a)(b)(?P=first)`, replacement: `\2\1`, subject: "aba"},
		"success: unmatched group":                         {pattern: `(a)?b`, replacement: `<\1>`, subject: "b ab"},
		"success: numeric conditional":                     {pattern: `(?P<a>a)(b)(?(1)c|d)`, replacement: `\2\1`, subject: "abc"},
		"success: named conditional":                       {pattern: `(?P<a>a)?(?(a)b|c)`, replacement: `\g<a>!`, subject: "ab c"},
		"success: forward conditional":                     {pattern: `(a)?(?(2)b|c)(d)?`, replacement: `\1\2`, subject: "acd c"},
		"success: groups retain last capture":              {pattern: `(a)+`, replacement: `\1`, subject: "aaa"},
		"success: nested groups":                           {pattern: `(?P<outer>a(b))(?=c)`, replacement: `\2\1`, subject: "abc"},
		"success: dollar preserves newline":                {pattern: `(a)$`, replacement: `[\1]`, subject: "a\n"},
		"success: standalone dollar":                       {pattern: `$`, replacement: "!", subject: "a\n"},
		"success: scoped multiline":                        {pattern: `(?m:(a)$)`, replacement: `[\1]`, subject: "a\na\n"},
		"success: absolute end":                            {pattern: `(a)\Z`, replacement: `[\1]`, subject: "a\n"},
		"success: counted replacement":                     {pattern: `a`, replacement: "x", subject: "aaa", count: 2},
		"success: negative count":                          {pattern: `a`, replacement: "x", subject: "aaa", count: -1},
		"success: empty following nonempty":                {pattern: `x*`, replacement: "-", subject: "abxd"},
		"success: nonempty after empty":                    {pattern: `|a`, replacement: "-", subject: "a"},
		"success: lazy empties":                            {pattern: `(.*?)`, replacement: `[\1]`, subject: "ab"},
		"success: counted empty alternative":               {pattern: `|a`, replacement: "-", subject: "a", count: 2},
		"success: empty input":                             {pattern: `x*`, replacement: "-", subject: ""},
		"success: consuming alternation":                   {pattern: `a|`, replacement: "-", subject: "aba"},
		"success: lookahead":                               {pattern: `(?=a)`, replacement: "-", subject: "aa"},
		"success: lookbehind captures":                     {pattern: `(?<=(a))b`, replacement: `\1`, subject: "ab ab"},
		"success: atomic group":                            {pattern: `(?>a|ab)c`, replacement: "-", subject: "abc ac"},
		"success: possessive":                              {pattern: `(a*+)a`, replacement: `\1`, subject: "aaa"},
		"success: escaped replacement":                     {pattern: `a`, replacement: `\a\b\f\n\r\t\v\\\&\101\0`, subject: "a"},
		"success: octal versus group":                      {pattern: `(a)`, replacement: `\123-\1-\077`, subject: "a"},
		"success: literal dollar":                          {pattern: `(a)`, replacement: `$1${1}$$`, subject: "a"},
		"success: newline replacement":                     {pattern: `(a)`, replacement: "\n\\1\n", subject: "a"},
		"success: Unicode byte offsets":                    {pattern: `(世)(é)`, replacement: `\2\1`, subject: "a世é", flags: Unicode},
		"success: fallback Unicode byte offsets":           {pattern: `(?<=a)(世)(é)`, replacement: `\2\1`, subject: "a世é", flags: Unicode},
		"success: Unicode empty retry":                     {pattern: `|世`, replacement: "-", subject: "世", flags: Unicode},
		"success: string ASCII mode still decodes Unicode": {pattern: `(?a)(.)`, replacement: `[\1]`, subject: "é", flags: Unicode},
		"success: inline verbose trailing comment":         {pattern: "(?x)(a) # end", replacement: `\1`, subject: "a"},
		"success: literal spaces preserved in fallback":    {pattern: `(?=a )a `, replacement: "-", subject: "a b"},
		"success: bytes invalid UTF8":                      {pattern: `(.)`, replacement: `[\1]`, subject: "\xff\xfe"},
		"success: raw nonASCII pattern bytes":              {pattern: "é", replacement: "!", subject: "é"},
		"success: bytes backreference":                     {pattern: `(.)\1`, replacement: `[\1]`, subject: "\xff\xff"},
		"success: byte escapes":                            {pattern: `\xff`, replacement: `\377`, subject: "\xff\xfe"},
		"success: bytes casefold is ASCII":                 {pattern: `\xc0`, replacement: "!", subject: "\xe0", flags: IgnoreCase},
		"success: bytes literal casefold is ASCII":         {pattern: "\xc0", replacement: "!", subject: "\xe0", flags: IgnoreCase},
		"success: bytes class casefold is ASCII":           {pattern: `[\xc0A]`, replacement: "!", subject: "\xe0a", flags: IgnoreCase},
		"error: missing group":                             {pattern: `a`, replacement: `\2`, subject: "z"},
		"error: missing group name":                        {pattern: `a`, replacement: `\g<missing>`, subject: "z"},
		"error: bad template escape":                       {pattern: `a`, replacement: `\q`, subject: "z"},
		"error: overflowing octal":                         {pattern: `a`, replacement: `\400`, subject: "z"},
		"error: incomplete template":                       {pattern: `a`, replacement: `\g<`, subject: "z"},
		"error: open group reference":                      {pattern: `(a\1)`, replacement: "!", subject: "a"},
	}
	vectors := make(map[string]vector, len(tests))
	for name, test := range tests {
		vectors[name] = vector{Pattern: []byte(test.pattern), Replacement: []byte(test.replacement), Subject: []byte(test.subject), Flags: test.flags, Count: test.count}
	}
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatal(err)
	}
	output := difftest.Python(t, `
import base64, json, re, sys
results = {}
def b64(b): return base64.b64encode(b).decode()
for name, v in json.load(sys.stdin).items():
    string = bool(v['flags'] & 8)
    decode = lambda s: base64.b64decode(s).decode() if string else base64.b64decode(s)
    pattern, replacement, subject = [decode(v[k]) for k in ('pattern','replacement','subject')]
    flags = (re.I if v['flags'] & 1 else 0) | (re.M if v['flags'] & 2 else 0) | (re.S if v['flags'] & 4 else 0)
    result = {'sub': '', 'groups': None, 'spans': None, 'error': False}
    try:
        p = re.compile(pattern, flags)
        sub = p.sub(replacement, subject, count=v['count'])
        result['sub'] = b64(sub.encode() if string else sub)
        m = p.search(subject)
        if m:
            result['groups'] = [b64((m.group(i) or '').encode() if string else (m.group(i) or b'')) for i in range(p.groups+1)]
            result['spans'] = [[len(subject[:a].encode()), len(subject[:b].encode())] if string and a >= 0 else [a,b] for a,b in [m.span(i) for i in range(p.groups+1)]]
    except (re.error, IndexError):
        result['error'] = True
    results[name] = result
json.dump(results, sys.stdout)
`, encoded)
	want := make(map[string]result)
	if err := json.Unmarshal(output, &want); err != nil {
		t.Fatal(err)
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := result{}
			p, err := CompilePattern(test.pattern, test.flags)
			if err == nil {
				got.Sub, err = p.Sub([]byte(test.replacement), []byte(test.subject), test.count)
			}
			if err != nil {
				got.Error = true
				got.Sub = []byte{}
			} else {
				m, err := p.SearchString(test.subject)
				if err != nil {
					t.Fatal(err)
				}
				if m != nil {
					got.Spans = m.Spans
					for _, g := range m.Groups {
						got.Groups = append(got.Groups, []byte(g))
					}
				}
			}
			if diff := cmp.Diff(want[name], got); diff != "" {
				t.Fatalf("Python substitution/search (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPatternBytesBackreferenceDifference(t *testing.T) {
	output := difftest.Python(t, `
import json, re, sys
json.dump(bool(re.search(rb'(?i)(.)\1', b'\xc0\xe0')), sys.stdout)
`, nil)
	var python bool
	if err := json.Unmarshal(output, &python); err != nil {
		t.Fatal(err)
	}
	if python {
		t.Fatal("Python unexpectedly folded a non-ASCII bytes backreference")
	}
	p, err := CompilePattern(`(?i)(.)\1`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !p.MatchString("\xc0\xe0") {
		t.Fatal("documented fallback backreference behaviour changed; update compat.md")
	}
}
