// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package filter

import (
	"bytes"
	json "encoding/json/v2"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// TestGoldenIsCurrent re-runs testdata/parse_oracle.py against the pinned
// upstream mitmproxy and checks that it reproduces the committed
// parse_golden.json byte for byte, so TestParseMatchesUpstream compares
// against what upstream really does today. After changing the corpus,
// regenerate the golden with:
//
//	uv run --python 3.13 --script filter/testdata/parse_oracle.py \
//	    filter/testdata/parse_corpus.json > filter/testdata/parse_golden.json
func TestGoldenIsCurrent(t *testing.T) {
	uv, err := exec.LookPath("uv")
	if err != nil {
		t.Skip("uv is not installed")
	}
	cmd := exec.CommandContext(t.Context(), uv, "run", "-q", "--python", "3.13", "--script",
		filepath.Join("testdata", "parse_oracle.py"), filepath.Join("testdata", "parse_corpus.json"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	got, err := cmd.Output()
	if err != nil {
		t.Fatalf("parse_oracle.py: %v\n%s", err, stderr.Bytes())
	}
	want, err := os.ReadFile(filepath.Join("testdata", "parse_golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("testdata/parse_golden.json is stale: the pinned mitmproxy produces different records (%d bytes, committed %d); regenerate it", len(got), len(want))
	}
}

// operatorExprs holds one expression per operator.
var operatorExprs = []string{
	"~a", "~e", "~http", "~marked", "~replay", "~replayq", "~replays", "~q", "~s", "~tcp", "~udp", "~dns", "~websocket", "~all",
	"~b hello", "~bq content", "~bs message", "~t json", "~tq json", "~ts html", "~d example", "~dst :443",
	"~h content-type", "~hq ^host:", "~hs ^server:", "~m post", "~src 127.0.0.1", "~u /path", "~meta key",
	"~marker :red:", "~comment ^review", "~c 200",
}

// dollarExprs holds one expression per operator whose pattern can end in
// $ outside MULTILINE, where Python's $ also matches before a final
// newline; the oracle's hand-made flows end those fields in a newline.
var dollarExprs = []string{
	`~b "two$"`, `~bq "content$"`, `~bs "two$"`, `~m "get$"`, `~d "address$"`, `~u "path$"`,
	`~t "json$"`, `~tq "json$"`, `~ts "html$"`, markerDollarExpr,
}

// markerDollarExpr also matches a flow whose marker is exactly ":red:", so
// TestMatchMatchesUpstream checks that its selection includes the flow
// marked ":red:\n" as well.
const markerDollarExpr = `~marker "red:$"`

// extraExprs take the regexp2 path, pin value formatting, or combine
// operators.
var extraExprs = []string{
	`~bs "two$\n"`, `~bs "(?:two$)+"`, `~b "hello(?!x)"`, `~h "^content-length: 7\r$"`,
	`~meta "^b: string$"`, `~meta "'key': 'value'"`, `~meta "^d: b\"by'tes\"$"`, `~meta "\[1, 2.5, None, True\]"`,
	`~comment "^needs$"`, "~d example.org", `~u "^http://example.org:8443/path$"`, `~src "^::1:443$"`,
	"~dst example.com:443", "~c 404", "~bq compressed", "~bq not.gzip", "~b dns.google", "~bs 8.8.4.4", "~u dns.google",
	"~http & !~s", "~tcp | ~udp", "!(~q | ~s ) & ~http", "~websocket & ~bs me", "~b binary ~http",
}

// classExprs use \d, \w, \s, \b and their complements on the oracle's
// flow with non-ASCII subjects, in the str patterns of ~u and ~comment and
// the bytes patterns of ~b and ~h, on RE2 and, with a lookaround, on
// regexp2. The last rows make str patterns ASCII with (?a). Inside quotes the filter grammar drops a backslash, so a class
// escape is written \\d there.
var classExprs = []string{
	`~u /\d/`, `~u "/\\d/(?!x)"`, `~u /\D/`,
	`~comment caf\w`, `~comment "\\w(?=!)"`, `~comment caf\W`, `~comment "b [\\d-]$"`, `~comment "b [^\\D-]$"`,
	`~comment "a\\sb"`, `~comment "a\\Sb"`, `~comment "a\\sb(?!x)"`,
	`~comment "\\bx"`, `~comment "fé\\b"`, `~comment "\\Bx"`,
	`~b n=\d;`, `~b "n=\\d(?=;)"`, `~b "n=\\D(?!q)"`,
	`~b "caf\\w"`, `~b "caf\\w(?!q)"`, `~b "caf\\W"`, `~b "caf\\W(?!q)"`, `~b "\\W(?=elvin)"`,
	`~b "a\\sb"`, `~b "a\\sb(?!q)"`, `~b \bx`, `~b "\\bx(?!q)"`,
	`~h "x-note: caf\\w"`, `~h "x-note: caf\\W"`, `~h "x-note: caf\\W(?!q)"`,
	`~comment "(?a)caf\\W"`, `~u "(?a)/\\d/"`, `~comment "(?a:caf\\w)"`,
}

// TestMatchMatchesUpstream evaluates matchExprs on the same flows in Go
// and in the pinned upstream mitmproxy and compares the selections. The
// flows come from testdata/match_oracle.py, which writes them to one flow
// file in the current format; Go loads that file through flow.FromState.
func TestMatchMatchesUpstream(t *testing.T) {
	uv, err := exec.LookPath("uv")
	if err != nil {
		t.Skip("uv is not installed")
	}
	t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", "")
	dir := t.TempDir()
	matchExprs := slices.Concat(operatorExprs, dollarExprs, extraExprs, classExprs)
	exprsPath := filepath.Join(dir, "exprs.json")
	data, err := json.Marshal(matchExprs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exprsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	flowsPath := filepath.Join(dir, "flows.mitm")
	cmd := exec.CommandContext(t.Context(), uv, "run", "-q", "--python", "3.13", "--script",
		filepath.Join("testdata", "match_oracle.py"), testutil.FixturePath(t, "mitmproxy"), exprsPath, flowsPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("match_oracle.py: %v\n%s", err, stderr.Bytes())
	}
	if stderr.Len() > 0 {
		t.Logf("match_oracle.py: %s", stderr.Bytes())
	}
	var want struct {
		Flows   int     `json:"flows"`
		Results [][]int `json:"results"`
	}
	if err := json.Unmarshal(out, &want); err != nil {
		t.Fatalf("decode oracle output: %v", err)
	}

	flows := loadFlows(t, flowsPath)
	if len(flows) != want.Flows {
		t.Fatalf("loaded %d flows, upstream wrote %d", len(flows), want.Flows)
	}
	for i, expr := range matchExprs {
		e, err := Parse(expr)
		if err != nil {
			t.Errorf("Parse(%q) error = %v", expr, err)
			continue
		}
		t.Logf("%q selects %d flows upstream", expr, len(want.Results[i]))
		if i < len(operatorExprs)+len(dollarExprs) && len(want.Results[i]) == 0 {
			t.Errorf("%q selects no flow upstream, so the comparison proves nothing", expr)
		}
		got := []int{}
		for j, f := range flows {
			if e.Match(f) {
				got = append(got, j)
			}
		}
		if diff := gocmp.Diff(want.Results[i], got); diff != "" {
			t.Errorf("flows matching %q differ (-upstream +go):\n%s", expr, diff)
		}
	}
	if all := want.Results[slices.Index(matchExprs, "~all")]; len(all) != len(flows) {
		t.Errorf("~all selects %d of %d flows upstream", len(all), len(flows))
	}
	newlineMarked := slices.IndexFunc(flows, func(f flow.Flow) bool {
		v, _ := f.GetState().Get("marked")
		return v == ":red:\n"
	})
	if newlineMarked < 0 {
		t.Fatal(`no flow is marked ":red:\n", so the ~marker row does not test $ before a final newline`)
	}
	if sel := want.Results[slices.Index(matchExprs, markerDollarExpr)]; !slices.Contains(sel, newlineMarked) {
		t.Errorf("%q selects %v upstream, which lacks flow %d marked \":red:\\n\"", markerDollarExpr, sel, newlineMarked)
	}
}

// loadFlows reads every flow of a flow file written by upstream.
func loadFlows(t *testing.T, path string) []flow.Flow {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var flows []flow.Flow
	for len(data) > 0 {
		v, rest, err := tnetstring.Pop(data)
		if err != nil {
			t.Fatalf("decode flow %d: %v", len(flows), err)
		}
		data = rest
		m, ok := fromTnetstring(t, v).(*state.Map)
		if !ok {
			t.Fatalf("flow %d is %T, not a dict", len(flows), v)
		}
		f, err := flow.FromState(m)
		if err != nil {
			t.Fatalf("flow %d: FromState: %v", len(flows), err)
		}
		flows = append(flows, f)
	}
	return flows
}

// fromTnetstring converts a decoded tnetstring value to a state value.
func fromTnetstring(t *testing.T, v any) any {
	t.Helper()
	switch x := v.(type) {
	case *tnetstring.Dict:
		m := state.NewMap(x.Len())
		for k, e := range x.All() {
			m.Set(k, fromTnetstring(t, e))
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = fromTnetstring(t, e)
		}
		return out
	case *big.Int:
		t.Fatalf("integer %v does not fit int64", x)
	}
	return v
}
