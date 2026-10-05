// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command

import (
	"strconv"
	"testing"
)

func FuzzArgumentTypes(f *testing.F) {
	for _, seed := range []string{"", "true", "12_345", "١२３", `\N{LF}`, `\N{BELL}`, `\UFFFFFFFF`, "a,b", ":red_circle:", "1__2"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		for _, typ := range []Type{BoolType, IntType, StrType, StrSeqType, CutSpecType, MarkerType} {
			value, err := typ.Parse(t.Context(), NewManager(), text)
			if err != nil {
				continue
			}
			if typ == IntType {
				n := value.(int)
				back, err := IntType.Parse(t.Context(), NewManager(), strconv.Itoa(n))
				if err != nil || back != n {
					t.Fatalf("integer round trip %q: %v, %v", text, back, err)
				}
			}
			if typ != CutSpecType && typ != MarkerType && !typ.IsValid(t.Context(), NewManager(), value) {
				t.Fatalf("%s rejected its parsed value for %q", typ.Name(), text)
			}
		}
	})
}

func FuzzPathPattern(f *testing.F) {
	for _, seed := range []string{"", "*", "[]", "[!]", "[!]]", "[z-a-b]", "[a---c]", `\a?*`, "[é-語]"} {
		f.Add(seed, "name")
	}
	f.Fuzz(func(t *testing.T, pattern, name string) {
		re, err := pathPattern(pattern)
		if err != nil {
			if len(pattern) < 4096 {
				t.Fatalf("valid glob %q did not compile: %v", pattern, err)
			}
			return
		}
		re.MatchString(name)
	})
}
