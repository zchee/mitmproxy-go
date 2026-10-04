// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package filter

import (
	"errors"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/filter/regex"
)

// TestParse ports the structural assertions of upstream's TestParsing
// (test_simple, test_non_ascii, test_naked_url, test_quoting, test_nesting,
// test_not, test_binaryops, test_wideops, test_pyparsing_bug), expressed as
// the expected tree of upstream class names and arguments.
func TestParse(t *testing.T) {
	tests := map[string]struct {
		expr string
		want any
	}{
		"success: request":                  {expr: "~q", want: []any{"FReq"}},
		"success: response code":            {expr: "~c 10", want: []any{"FCode", "10"}},
		"success: method":                   {expr: "~m foobar", want: []any{"FMethod", "foobar"}},
		"success: url":                      {expr: "~u foobar", want: []any{"FUrl", "foobar"}},
		"success: implicit and of two":      {expr: "~q ~c 10", want: []any{"FAnd", []any{"FReq"}, []any{"FCode", "10"}}},
		"success: replay":                   {expr: "~replay", want: []any{"FReplay"}},
		"success: replayq":                  {expr: "~replayq", want: []any{"FReplayClient"}},
		"success: replays":                  {expr: "~replays", want: []any{"FReplayServer"}},
		"success: comment":                  {expr: "~comment .", want: []any{"FComment", "."}},
		"success: non-ascii argument":       {expr: "~s шгн", want: []any{"FAnd", []any{"FResp"}, []any{"FUrl", "шгн"}}},
		"success: naked url before header":  {expr: "foobar ~h rex", want: []any{"FAnd", []any{"FUrl", "foobar"}, []any{"FHead", "rex"}}},
		"success: single-quoted with ~":     {expr: "~u 'foo ~u bar' ~u voing", want: []any{"FAnd", []any{"FUrl", "foo ~u bar"}, []any{"FUrl", "voing"}}},
		"success: escaped quotes":           {expr: `~u 'foobar\"\''`, want: []any{"FUrl", `foobar"'`}},
		"success: escaped single in double": {expr: `~u "foo \'bar"`, want: []any{"FUrl", "foo 'bar"}},
		"success: nesting":                  {expr: "(~u foobar & ~h voing)", want: []any{"FAnd", []any{"FUrl", "foobar"}, []any{"FHead", "voing"}}},
		"success: not":                      {expr: "!~h test", want: []any{"FNot", []any{"FHead", "test"}}},
		"success: not of a group":           {expr: "!(~u test & ~h bar)", want: []any{"FNot", []any{"FAnd", []any{"FUrl", "test"}, []any{"FHead", "bar"}}}},
		"success: or":                       {expr: "~u foobar | ~h voing", want: []any{"FOr", []any{"FUrl", "foobar"}, []any{"FHead", "voing"}}},
		"success: and":                      {expr: "~u foobar & ~h voing", want: []any{"FAnd", []any{"FUrl", "foobar"}, []any{"FHead", "voing"}}},
		"success: wide operator":            {expr: "~hq 'header: qvalue'", want: []any{"FHeadRequest", "header: qvalue"}},
		"success: bare word":                {expr: "test", want: []any{"FUrl", "test"}},
		"success: not binds tighter than and": {
			expr: "!~q & ~s",
			want: []any{"FAnd", []any{"FNot", []any{"FReq"}}, []any{"FResp"}},
		},
		"success: and binds tighter than or": {
			expr: "~q | ~s & ~e",
			want: []any{"FOr", []any{"FReq"}, []any{"FAnd", []any{"FResp"}, []any{"FErr"}}},
		},
		"success: chained and is flat": {
			expr: "~q & ~s & ~e",
			want: []any{"FAnd", []any{"FReq"}, []any{"FResp"}, []any{"FErr"}},
		},
		"success: a parenthesized operand joins the chain": {
			expr: "~q & (~s ) & ~e",
			want: []any{"FAnd", []any{"FReq"}, []any{"FResp"}, []any{"FErr"}},
		},
		"success: a parenthesized chain stays nested": {
			expr: "~q & (~s & ~e )",
			want: []any{"FAnd", []any{"FReq"}, []any{"FAnd", []any{"FResp"}, []any{"FErr"}}},
		},
		"success: implicit and is loosest": {
			expr: "~q | ~s ~e",
			want: []any{"FAnd", []any{"FOr", []any{"FReq"}, []any{"FResp"}}, []any{"FErr"}},
		},
		"success: ampersand inside a bare word":  {expr: "a&b", want: []any{"FUrl", "a&b"}},
		"success: lone ampersand is a bare word": {expr: "&", want: []any{"FUrl", "&"}},
		"success: integer stops at a non-digit":  {expr: "~c 10x", want: []any{"FAnd", []any{"FCode", "10"}, []any{"FUrl", "x"}}},
		"success: leading zeros are dropped":     {expr: "~c 007", want: []any{"FCode", "7"}},
		"success: integer beyond int64":          {expr: "~c 99999999999999999999", want: []any{"FCode", "99999999999999999999"}},
		"success: operator before non-ascii":     {expr: "~qш", want: []any{"FAnd", []any{"FReq"}, []any{"FUrl", "ш"}}},
		"success: tab inside quotes becomes spaces": {
			expr: "~u 'a\tb'",
			want: []any{"FUrl", "a" + strings.Repeat(" ", 3) + "b"},
		},
		"success: escapes as pyparsing reverses them": {
			expr: `~u "\d\x41\xA2\t\0"`,
			want: []any{"FUrl", "dx41¢\t\x00"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e, err := Parse(tt.expr)
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", tt.expr, err)
			}
			if diff := gocmp.Diff(tt.want, tree(e)); diff != "" {
				t.Errorf("Parse(%q) tree mismatch (-want +got):\n%s", tt.expr, diff)
			}
		})
	}
}

// TestParseConcreteTypes checks the Go types behind the trees, which
// callers type-switch on.
func TestParseConcreteTypes(t *testing.T) {
	e, err := Parse("~hq 'header: qvalue'")
	if err != nil {
		t.Fatal(err)
	}
	rex, ok := e.(*Rex)
	if !ok {
		t.Fatalf("Parse() = %T, want *Rex", e)
	}
	if rex.Token != TokenHeaderRequest {
		t.Errorf("Token = %v, want %v", rex.Token, TokenHeaderRequest)
	}
	if rex.Regexp() == nil {
		t.Fatal("Regexp() = nil")
	}
	if !rex.Regexp().MatchString("Accept: */*\r\nHeader: QValue\r\n") {
		t.Error("Regexp() does not match a header block containing the pattern")
	}

	e, err = Parse("!(~c 200 | ~marked )")
	if err != nil {
		t.Fatal(err)
	}
	want := &Not{Expr: &Or{Exprs: []Expr{&Int{Token: TokenCode, Value: "200"}, &Unary{Token: TokenMarked}}}}
	if diff := gocmp.Diff(want, e); diff != "" {
		t.Errorf("Parse() mismatch (-want +got):\n%s", diff)
	}
}

// TestDescribe ports upstream's test_str_implementations.
func TestDescribe(t *testing.T) {
	tests := map[string]struct {
		expr string
		want string
	}{
		"success: ~a":         {expr: "~a", want: "is asset"},
		"success: ~marked":    {expr: "~marked", want: "is marked"},
		"success: ~http":      {expr: "~http", want: "is an HTTP Flow"},
		"success: ~websocket": {expr: "~websocket", want: "is a Websocket Flow"},
		"success: ~tcp":       {expr: "~tcp", want: "is a TCP Flow"},
		"success: ~udp":       {expr: "~udp", want: "is a UDP Flow"},
		"success: ~dns":       {expr: "~dns", want: "is a DNS Flow"},
		"success: ~all":       {expr: "~all", want: "all flows"},
		"success: ~q":         {expr: "~q", want: "has no response"},
		"success: ~s":         {expr: "~s", want: "has response"},
		"success: ~e":         {expr: "~e", want: "has error"},
		"success: ~t":         {expr: "~t content", want: "content type matches /content/i"},
		"success: ~tq":        {expr: "~tq content", want: "req. content type matches /content/i"},
		"success: ~ts":        {expr: "~ts content", want: "resp. content type matches /content/i"},
		"success: ~h rex":     {expr: "~h rex", want: "header matches /rex/im"},
		"success: ~hq rex":    {expr: "~hq rex", want: "req. header matches /rex/im"},
		"success: ~hs rex":    {expr: "~hs rex", want: "resp. header matches /rex/im"},
		"success: ~h header":  {expr: "~h header", want: "header matches /header/im"},
		"success: ~hq header": {expr: "~hq header", want: "req. header matches /header/im"},
		"success: ~hs header": {expr: "~hs header", want: "resp. header matches /header/im"},
		"success: ~b rex":     {expr: "~b rex", want: "body matches /rex/is"},
		"success: ~bq rex":    {expr: "~bq rex", want: "body request matches /rex/is"},
		"success: ~bs rex":    {expr: "~bs rex", want: "body response matches /rex/is"},
		"success: ~b content": {expr: "~b content", want: "body matches /content/is"},
		"success: ~bq content": {
			expr: "~bq content", want: "body request matches /content/is",
		},
		"success: ~bs content": {
			expr: "~bs content", want: "body response matches /content/is",
		},
		"success: ~m":       {expr: "~m get", want: "method matches /get/i"},
		"success: ~d":       {expr: "~d example.com", want: "domain matches /example.com/i"},
		"success: ~u":       {expr: "~u foo", want: "url matches /foo/i"},
		"success: ~src":     {expr: "~src 127.0.0.1", want: "source address matches /127.0.0.1/i"},
		"success: ~dst":     {expr: "~dst example.com:443", want: "destination address matches /example.com:443/i"},
		"success: ~replay":  {expr: "~replay", want: "flow has been replayed"},
		"success: ~replayq": {expr: "~replayq", want: "request has been replayed"},
		"success: ~replays": {expr: "~replays", want: "response has been replayed"},
		"success: ~meta":    {expr: "~meta foo", want: "flow metadata matches /foo/im"},
		"success: ~marker":  {expr: "~marker red", want: "marker matches /red/i"},
		"success: ~comment": {expr: "~comment note", want: "comment matches /note/im"},
		"success: ~c":       {expr: "~c 404", want: "response code is 404"},
		"success: group": {
			expr: "(~u foobar & ~h voing)", want: "url matches /foobar/i and header matches /voing/im",
		},
		"success: not":              {expr: "!~h test", want: "not header matches /test/im"},
		"success: and":              {expr: "~u foo & ~c 200", want: "url matches /foo/i and response code is 200"},
		"success: or":               {expr: "~u foo | ~c 200", want: "url matches /foo/i or response code is 200"},
		"success: not of a group":   {expr: "!(~u foo | ~c 200)", want: "not (url matches /foo/i or response code is 200)"},
		"success: inline dotall":    {expr: `~u "(?s)a"`, want: "url matches /(?s)a/is"},
		"success: nested and group": {expr: "(~q & ~s ) & ~e", want: "(has no response and has response) and has error"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", "")
			e, err := Parse(tt.expr)
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", tt.expr, err)
			}
			if got := e.Describe(); got != tt.want {
				t.Errorf("Describe() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseError ports upstream's test_parse_err and test_match error case
// and pins the offset each rejection names.
func TestParseError(t *testing.T) {
	tests := map[string]struct {
		expr       string
		wantOffset int
		wantMsg    string
	}{
		"error: empty":                   {expr: "", wantOffset: 0, wantMsg: "empty filter expression"},
		"error: whitespace only":         {expr: "  ", wantOffset: 2, wantMsg: "expected a filter expression"},
		"error: missing regex":           {expr: "~b", wantOffset: 2, wantMsg: "~b requires a regex argument"},
		"error: bad regex":               {expr: "~h [", wantOffset: 3, wantMsg: "cannot compile expression"},
		"error: bad bare regex":          {expr: "[foobar", wantOffset: 0, wantMsg: "cannot compile expression"},
		"error: mid-pattern flags":       {expr: `~u "a(?i)"`, wantOffset: 3, wantMsg: "global flags (?i) not at the start"},
		"error: missing integer":         {expr: "~c", wantOffset: 2, wantMsg: "~c requires an integer argument"},
		"error: negative integer":        {expr: "~c -1", wantOffset: 3, wantMsg: "~c requires an integer argument"},
		"error: too many digits":         {expr: "~c " + strings.Repeat("1", 4301), wantOffset: 3, wantMsg: "exceeds 4300 digits"},
		"error: unknown operator":        {expr: "~zz", wantOffset: 0, wantMsg: `unknown operator "~zz"`},
		"error: operator glued to &":     {expr: "~q&~s", wantOffset: 0, wantMsg: `unknown operator "~q&~s"`},
		"error: operator glued to paren": {expr: "(~q)", wantOffset: 1, wantMsg: `unknown operator "~q)"`},
		"error: dangling or":             {expr: "a |", wantOffset: 3, wantMsg: "unexpected end of expression"},
		"error: lone not":                {expr: "!", wantOffset: 1, wantMsg: "unexpected end of expression"},
		"error: juxtaposition in parens": {expr: "(a b)", wantOffset: 3, wantMsg: "expected '&', '|' or ')' inside parentheses opened at offset 0"},
		"error: unclosed paren":          {expr: "a & (b", wantOffset: 6, wantMsg: "missing ')' for '(' at offset 4"},
		"error: stray close paren":       {expr: "a)", wantOffset: 1, wantMsg: "unexpected ')'"},
		"error: empty parens":            {expr: "()", wantOffset: 1, wantMsg: "unexpected ')'"},
		"error: unterminated quote":      {expr: `~u "abc`, wantOffset: 3, wantMsg: "unterminated quoted string"},
		"error: line break in quote":     {expr: "\"a\nb\"", wantOffset: 2, wantMsg: "line break inside quoted string"},
		"error: offset before a tab":     {expr: "\t~zz", wantOffset: 1, wantMsg: `unknown operator "~zz"`},
		"error: offset after a tab":      {expr: "~u\t\"a", wantOffset: 3, wantMsg: "unterminated quoted string"},
		"error: invalid utf-8":           {expr: "ab\xff", wantOffset: 2, wantMsg: "invalid UTF-8"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e, err := Parse(tt.expr)
			if err == nil {
				t.Fatalf("Parse(%q) = %v, want error", tt.expr, e)
			}
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("Parse(%q) error = %T, want *ParseError", tt.expr, err)
			}
			if pe.Offset != tt.wantOffset {
				t.Errorf("Offset = %d, want %d (error: %v)", pe.Offset, tt.wantOffset, err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Error() = %q, want it to contain %q", err, tt.wantMsg)
			}
			if tt.expr != "" && !strings.Contains(err.Error(), "at offset") {
				t.Errorf("Error() = %q does not name the offset", err)
			}
		})
	}
}

// TestCaseSensitiveEnv ports upstream's test_case_sensitive for the parse
// side: the variable decides whether patterns ignore case.
func TestCaseSensitiveEnv(t *testing.T) {
	tests := map[string]struct {
		env          string
		wantDescribe string
		wantGET      bool
	}{
		"success: unset ignores case":   {env: "", wantDescribe: "method matches /get/i", wantGET: true},
		"success: 0 ignores case":       {env: "0", wantDescribe: "method matches /get/i", wantGET: true},
		"success: 1 is case-sensitive":  {env: "1", wantDescribe: "method matches /get/", wantGET: false},
		"success: true is not 1":        {env: "true", wantDescribe: "method matches /get/i", wantGET: true},
		"success: inline flag still on": {env: "1", wantDescribe: "method matches /(?i)get/i", wantGET: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", tt.env)
			expr := "~m get"
			if strings.Contains(tt.wantDescribe, "(?i)") {
				expr = `~m "(?i)get"`
			}
			e, err := Parse(expr)
			if err != nil {
				t.Fatal(err)
			}
			if got := e.Describe(); got != tt.wantDescribe {
				t.Errorf("Describe() = %q, want %q", got, tt.wantDescribe)
			}
			if got := e.(*Rex).Regexp().MatchString("GET"); got != tt.wantGET {
				t.Errorf("pattern matches GET = %v, want %v", got, tt.wantGET)
			}
		})
	}
}

func TestRegexFlagsPerToken(t *testing.T) {
	want := map[Token]regex.Flags{
		TokenHeader: regex.Multiline, TokenHeaderRequest: regex.Multiline, TokenHeaderResponse: regex.Multiline,
		TokenMeta: regex.Multiline | regex.Unicode, TokenComment: regex.Multiline | regex.Unicode,
		TokenDomain: regex.Unicode, TokenDst: regex.Unicode, TokenSrc: regex.Unicode, TokenURL: regex.Unicode, TokenMarker: regex.Unicode,
		TokenBody: regex.DotAll, TokenBodyRequest: regex.DotAll, TokenBodyResponse: regex.DotAll,
	}
	for _, tok := range Tokens() {
		if got := tok.RegexFlags(); got != want[tok] {
			t.Errorf("%v.RegexFlags() = %q, want %q", tok, got, want[tok])
		}
	}
}

func TestTokens(t *testing.T) {
	var codes []string
	arity := map[Arity]int{}
	for _, tok := range Tokens() {
		codes = append(codes, tok.String())
		arity[tok.Arity()]++
	}
	want := []string{
		"~a", "~e", "~http", "~marked", "~replay", "~replayq", "~replays", "~q", "~s", "~tcp", "~udp", "~dns", "~websocket", "~all",
		"~b", "~bq", "~bs", "~t", "~tq", "~ts", "~d", "~dst", "~h", "~hq", "~hs", "~m", "~src", "~u", "~meta", "~marker", "~comment",
		"~c",
	}
	if diff := gocmp.Diff(want, codes); diff != "" {
		t.Errorf("Tokens() mismatch (-want +got):\n%s", diff)
	}
	if diff := gocmp.Diff(map[Arity]int{ArityNone: 14, ArityRegex: 17, ArityInt: 1}, arity); diff != "" {
		t.Errorf("arity counts mismatch (-want +got):\n%s", diff)
	}
}

func TestDump(t *testing.T) {
	e, err := Parse("~q ~c 10 | !foo")
	if err != nil {
		t.Fatal(err)
	}
	want := "FAnd\n\tFReq\n\tFOr\n\t\tFCode\n\t\tFNot\n\t\t\tFUrlfoo\n"
	if got := dumpString(t, e); got != want {
		t.Errorf("Dump() = %q, want %q", got, want)
	}
}

func TestString(t *testing.T) {
	tests := map[string]struct {
		expr string
		want string
	}{
		"success: bare word gains ~u":       {expr: "foo", want: "~u foo"},
		"success: quotes only when needed":  {expr: `~h "a b"`, want: `~h "a b"`},
		"success: quoted word unquoted":     {expr: `~h "ab"`, want: "~h ab"},
		"success: escapes in quoted form":   {expr: `~u 'a"b\\.c'`, want: `~u "a\"b\\.c"`},
		"success: control characters":       {expr: `~u "\n\r\t"`, want: `~u "\n\r\t"`},
		"success: empty pattern":            {expr: `~u ''`, want: `~u ""`},
		"success: implicit and made":        {expr: "~q ~s", want: "~q & ~s"},
		"success: nested groups kept":       {expr: "(~q & ~s ) & ~e", want: "(~q & ~s ) & ~e"},
		"success: not of group":             {expr: "!(~q |~s )", want: "!(~q | ~s )"},
		"success: canonical integer":        {expr: "~c 0404", want: "~c 404"},
		"success: special word characters":  {expr: "a&b|c!", want: "~u a&b|c!"},
		"success: implicit and of or group": {expr: "~q | ~s ~e", want: "(~q | ~s ) & ~e"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e, err := Parse(tt.expr)
			if err != nil {
				t.Fatal(err)
			}
			if got := e.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	for _, expr := range loadCorpus(f) {
		if len(expr) < 512 {
			f.Add(expr)
		}
	}
	f.Fuzz(func(t *testing.T, expr string) {
		e, err := Parse(expr)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("Parse(%q) error = %T, want *ParseError", expr, err)
			}
			if pe.Offset < 0 || pe.Offset > len(expr) {
				t.Fatalf("Parse(%q) offset %d outside the input", expr, pe.Offset)
			}
			if err.Error() == "" {
				t.Fatalf("Parse(%q) returned an empty error message", expr)
			}
			return
		}
		if e.Describe() == "" {
			t.Errorf("Parse(%q).Describe() is empty", expr)
		}
		s := e.String()
		again, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q).String() = %q does not parse: %v", expr, s, err)
		}
		if diff := gocmp.Diff(tree(e), tree(again)); diff != "" {
			t.Fatalf("Parse(%q).String() = %q parses to a different tree (-first +second):\n%s", expr, s, diff)
		}
		if s2 := again.String(); s2 != s {
			t.Fatalf("String() is not a fixed point for %q: %q then %q", expr, s, s2)
		}
	})
}

func BenchmarkParse(b *testing.B) {
	benchmarks := map[string]string{
		"operator":  "~q",
		"bare word": "example.com",
		"header":    `~h "^content-type: application/json"`,
		"combined":  "~d example.com & ~m POST & !(~c 200 | ~c 204) & ~bs error",
		"lookahead": `~u "/api/(?=v2)"`,
	}
	for name, expr := range benchmarks {
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				if _, err := Parse(expr); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
