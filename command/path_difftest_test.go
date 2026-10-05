// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package command

import (
	json "encoding/json/v2"
	rand "math/rand/v2"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestDifferentialPathPatterns(t *testing.T) {
	var cases [][2]string
	patterns := []string{"[]", "[!]", "[]]", "[!]]", "[^a]", "[a-z]", "[z-a]", "[a--z]", "[z-a-b]", "[a-b-c-d]", "[--0]", "[a---c]", `\*`, "[é-語]", "***?"}
	for _, pattern := range patterns {
		for _, name := range []string{"", "a", "b", "c", "d", "z", "-", "!", "^", "]", "[", "é", "語", "\n", `\abc`} {
			cases = append(cases, [2]string{pattern, name})
		}
	}
	rng := rand.New(rand.NewPCG(1, 2))
	pool := []rune("abc!-^[]*?\\\né語")
	for range 5000 {
		var pair [2]string
		for i := range pair {
			runes := make([]rune, rng.IntN(12))
			for j := range runes {
				runes[j] = pool[rng.IntN(len(pool))]
			}
			pair[i] = string(runes)
		}
		cases = append(cases, pair)
	}
	input, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	output := difftest.Python(t, "import fnmatch, json, sys\nprint(json.dumps([fnmatch.fnmatchcase(s,p) for p,s in json.load(sys.stdin)]))", input)
	var want []bool
	if err := json.Unmarshal(output, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != len(cases) {
		t.Fatalf("got %d oracle results for %d cases", len(want), len(cases))
	}
	for i, pair := range cases {
		pattern, err := pathPattern(pair[0])
		if err != nil {
			t.Fatalf("pattern %q: %v", pair[0], err)
		}
		if got := pattern.MatchString(pair[1]); got != want[i] {
			t.Errorf("pattern %q name %q: %s", pair[0], pair[1], cmp.Diff(want[i], got))
		}
	}
}
