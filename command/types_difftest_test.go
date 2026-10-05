// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package command

import (
	"bufio"
	"bytes"
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

const pythonTypesScript = `
import json, sys
from mitmproxy import types
kinds = {"str": types._StrType(), "int": types._IntType(), "bool": types._BoolType(),
         "path": types._PathType(), "strseq": types._StrSeqType(),
         "cutspec": types._CutSpecType(), "marker": types._MarkerType()}
for line in sys.stdin:
    case = json.loads(line)
    kind = kinds[case["kind"]]
    try:
        if case["complete"]:
            value = kind.completion(None, None, case["input"])
        else:
            value = kind.parse(None, None, case["input"])
        result = {"error": False, "value": value}
    except Exception:
        result = {"error": True, "value": None}
    print(json.dumps(result))
`

type typeCase struct {
	Kind     string `json:"kind"`
	Input    string `json:"input"`
	Complete bool   `json:"complete"`
}

type typeResult struct {
	Error bool `json:"error"`
	Value any  `json:"value"`
}

func TestDifferentialTypes(t *testing.T) {
	types := map[string]Type{"str": StrType, "int": IntType, "bool": BoolType, "path": PathType, "strseq": StrSeqType, "cutspec": CutSpecType, "marker": MarkerType}
	inputs := map[string][]string{
		"int":     {"", "+", "-", "0", "-1", "+1", "1_000", "_1", "1_", "1__0", "--1", "0x10", "²", " +١_२３ ", "1.0"},
		"str":     {"", "literal", `\q`, `\x1`, `\xzz`, `\x+1`, `\x-1`, `\777`, `\UFFFFFFFF`, `\U00110000`, `\N{KEYCAP DIGIT ONE}`, `\N{LF}`, `\N{latin small letter a}`, `\N{LATIN SMALL LETTER ı}`, `\N{BELL}`, `\N{CJK UNIFIED IDEOGRAPH-2EBF0}`, `\N{IDEOGRAPHIC DESCRIPTION CHARACTER SUBTRACTION}`, `\N{HANGUL SYLLABLE GAG}`, `\N{TANGUT IDEOGRAPH-17000}`, `\N{TODHRI LETTER A}`},
		"bool":    {"true", "false", "True", "1", ""},
		"strseq":  {"", "a,b", " a , b ", "a,,b", "\x1ca\x1f,b"},
		"cutspec": {"", "a,b", " a , b "},
		"marker":  {"true", "false", "X", ":red_circle:", "", ":unknown:"},
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.Is(unicode.Nd, r) || unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f {
			inputs["int"] = append(inputs["int"], string(r), string(r)+"1"+string(r))
		}
	}
	inputs["int"] = append(inputs["int"], strings.Repeat("0", 4300), strings.Repeat("0", 4301))
	for name := range runeByName() {
		inputs["str"] = append(inputs["str"], `\N{`+name+`}`)
	}
	for _, block := range algorithmicNames {
		for _, r := range []rune{block.first - 1, block.first, block.last, block.last + 1} {
			inputs["str"] = append(inputs["str"], `\N{`+block.prefix+strings.ToUpper(strconv.FormatInt(int64(r), 16))+`}`)
		}
	}
	for name := range unicodeNameAliases {
		inputs["str"] = append(inputs["str"], `\N{`+name+`}`, `\N{`+strings.ToLower(name)+`}`)
	}
	var cases []typeCase
	for kind, values := range inputs {
		for _, value := range values {
			cases = append(cases, typeCase{Kind: kind, Input: value})
		}
	}
	for _, kind := range []string{"marker", "bool"} {
		cases = append(cases, typeCase{Kind: kind, Complete: true})
	}
	runTypeDifferential(t, types, cases)
}

func TestDifferentialPathCompletion(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	for _, name := range []string{"aaa", "aab", "aac", ".hidden", "[literal", "-dash", "^caret", "z", "A", "é"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"bbb", ".private", "inner"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "entry"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var cases []typeCase
	for _, value := range []string{"", "a", "./", "./a", ".", ".h", "~", "~/", "~/a", "~missing-command-test-user/", "none", "*", "*/e", "b*/", "[!a]", "[^a]", "[a-z]", "[z-a]", "[a--z]", "[z-a-b]", "[[]", "[", "inner/../a", "././a", dir + "/", dir + "/a"} {
		cases = append(cases, typeCase{Kind: "path", Input: value}, typeCase{Kind: "path", Input: value, Complete: true})
	}
	runTypeDifferential(t, map[string]Type{"path": PathType}, cases)
}

func runTypeDifferential(t *testing.T, types map[string]Type, cases []typeCase) {
	t.Helper()
	slices.SortFunc(cases, func(a, b typeCase) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Input, b.Input)
	})
	var input bytes.Buffer
	for _, tc := range cases {
		line, err := json.Marshal(tc)
		if err != nil {
			t.Fatal(err)
		}
		input.Write(line)
		input.WriteByte('\n')
	}
	output := difftest.Python(t, pythonTypesScript, input.Bytes())
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(nil, 1<<20)
	for i, tc := range cases {
		if !scanner.Scan() {
			t.Fatalf("Python stopped at case %d: %v", i, scanner.Err())
		}
		var want, got typeResult
		if err := json.Unmarshal(scanner.Bytes(), &want); err != nil {
			t.Fatal(err)
		}
		var value any
		var err error
		if tc.Complete {
			value, err = types[tc.Kind].Completion(t.Context(), NewManager(), tc.Input)
		} else {
			value, err = types[tc.Kind].Parse(t.Context(), NewManager(), tc.Input)
		}
		if err != nil {
			value = nil
		}
		line, marshalErr := json.Marshal(typeResult{Error: err != nil, Value: value})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if err := json.Unmarshal(line, &got); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("%s %q completion=%t (-Python +Go):\n%s", tc.Kind, tc.Input, tc.Complete, diff)
		}
	}
	if scanner.Scan() || scanner.Err() != nil {
		t.Fatalf("unexpected extra output or scan error: %v", scanner.Err())
	}
}
