// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package regex

import (
	json "encoding/json/v2"
	"fmt"
	"testing"
	"unicode"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

// pythonClassesScript prints, as JSON, the code points the pinned Python
// matches with \d, \w and \s in str patterns, the code points its Unicode
// database leaves unassigned, and the bytes \d, \w and \s matches among
// 0 to 255. Ranges are [lo, hi] pairs.
const pythonClassesScript = `
import json, re, sys, unicodedata

def ranges(pred, end):
    out, lo = [], None
    for cp in range(end + 1):
        hit = cp < end and pred(cp)
        if hit and lo is None:
            lo = cp
        if not hit and lo is not None:
            out.append([lo, cp - 1])
            lo = None
    return out

def str_class(p):
    r = re.compile(p)
    return ranges(lambda cp: not 0xD800 <= cp <= 0xDFFF and r.fullmatch(chr(cp)) is not None, 0x110000)

def bytes_class(p):
    r = re.compile(p)
    return ranges(lambda b: r.fullmatch(bytes([b])) is not None, 256)

json.dump({
    "unidata": unicodedata.unidata_version,
    "unassigned": ranges(lambda cp: unicodedata.category(chr(cp)) == "Cn", 0x110000),
    "str": {c: str_class("\\" + c) for c in "dws"},
    "bytes": {c: bytes_class(("\\" + c).encode()) for c in "dws"},
}, sys.stdout)
`

type pythonClasses struct {
	Unidata    string               `json:"unidata"`
	Unassigned [][2]rune            `json:"unassigned"`
	Str        map[string][][2]rune `json:"str"`
	Bytes      map[string][][2]rune `json:"bytes"`
}

func pairsSet(pairs [][2]rune) runeSet {
	s := make(runeSet, 0, 2*len(pairs))
	for _, p := range pairs {
		s = append(s, p[0], p[1])
	}
	return s.normalize()
}

// TestClassSetsMatchPython checks the sets behind \d, \w and \s against the
// pinned Python on every code point its Unicode database assigns, for str
// patterns, and on every byte for bytes patterns, and
// checks that RE2 and regexp2 match exactly those sets through Compile,
// with and without IgnoreCase. Code points that Python's older Unicode
// database leaves unassigned may differ: they follow Go's unicode tables.
func TestClassSetsMatchPython(t *testing.T) {
	var py pythonClasses
	if err := json.Unmarshal(difftest.Python(t, pythonClassesScript, nil), &py); err != nil {
		t.Fatal(err)
	}
	t.Logf("Python Unicode %s, Go Unicode %s", py.Unidata, unicode.Version)
	unassigned := pairsSet(py.Unassigned)

	for _, mode := range []struct {
		name string
		uni  bool
		want map[string][][2]rune
		skip runeSet
	}{
		// A bytes pattern sees bytes, and no byte from 0x80 up is in these
		// classes, so neither is any rune from 0x80 up on the Go side.
		{name: "str", uni: true, want: py.Str, skip: unassigned},
		{name: "bytes", uni: false, want: py.Bytes},
	} {
		for _, c := range []byte{'d', 'w', 's'} {
			want := pairsSet(mode.want[string(c)])
			for _, neg := range []bool{false, true} {
				letter, wantSet := c, want
				if neg {
					letter, wantSet = c-'a'+'A', want.negate()
				}
				got := shorthandSet(letter, mode.uni)
				t.Run(fmt.Sprintf("%s/%c/set", mode.name, letter), func(t *testing.T) {
					checkAllRunes(t, mode.skip, wantSet, got.contains)
				})
				for _, fold := range []Flags{0, IgnoreCase} {
					flags := fold
					if mode.uni {
						flags |= Unicode
					}
					for _, prefix := range []string{"", "(?=.)"} {
						pattern := prefix + `\` + string(letter)
						m, err := Compile(pattern, flags)
						if err != nil {
							t.Fatal(err)
						}
						t.Run(fmt.Sprintf("%s/%q/fold=%v", mode.name, pattern, fold != 0), func(t *testing.T) {
							checkAllRunes(t, mode.skip, wantSet, func(r rune) bool {
								if r == '\n' && prefix != "" {
									// The lookahead does not see a newline.
									return wantSet.contains(r)
								}
								return m.MatchString(string(r))
							})
						})
					}
				}
			}
		}
	}
}

// checkAllRunes compares got with want on every rune that is not a
// surrogate and not in skip.
func checkAllRunes(t *testing.T, skip, want runeSet, got func(rune) bool) {
	t.Helper()
	var bad []string
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if 0xd800 <= r && r <= 0xdfff || skip.contains(r) {
			continue
		}
		if g, w := got(r), want.contains(r); g != w {
			bad = append(bad, fmt.Sprintf("U+%04X got %v want %v", r, g, w))
		}
	}
	if len(bad) > 0 {
		t.Errorf("%d code points differ from Python, first: %v", len(bad), bad[:min(len(bad), 10)])
	}
}
