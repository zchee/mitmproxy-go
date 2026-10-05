// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tnetstring

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	rand "math/rand/v2"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/omap"
)

// entry is an exported mirror of a dictionary entry, so go-cmp can diff
// decoded trees and show key order.
type entry struct {
	Key      string
	BytesKey bool
	Value    any
}

// plain converts a decoded value into a tree go-cmp can diff field by field.
// Dictionaries become ordered entry slices, so the comparison is
// order-sensitive; big integers become their decimal text.
func plain(v any) any {
	switch v := v.(type) {
	case *omap.Map[any]:
		out := []entry{}
		for k, val := range v.All() {
			out = append(out, entry{Key: k, BytesKey: v.IsBytesKey(k), Value: plain(val)})
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = plain(v[i])
		}
		return out
	case *big.Int:
		return "big:" + v.String()
	}
	return v
}

// treeDiff returns "" when want and got are the same tree, dictionary order
// included, and a go-cmp diff otherwise. Equality is decided by comparing
// encodings, which preserve order and type: go-cmp's slice diff takes time
// exponential in the nesting depth, so it only renders a failure.
func treeDiff(want, got any) string {
	we, werr := Dumps(want)
	ge, gerr := Dumps(got)
	if werr == nil && gerr == nil && bytes.Equal(we, ge) {
		return ""
	}
	if d := gocmp.Diff(plain(want), plain(got)); d != "" {
		return d
	}
	return fmt.Sprintf("encodings differ: want %q (%v), got %q (%v)", we, werr, ge, gerr)
}

// dict builds a dictionary from alternating keys and values. A string key is
// a text key and a []byte key a byte-string key.
func dict(kv ...any) *omap.Map[any] {
	d := omap.NewWithCapacity[any](len(kv) / 2)
	for i := 0; i < len(kv); i += 2 {
		switch k := kv[i].(type) {
		case string:
			d.Set(k, kv[i+1])
		case []byte:
			d.SetBytesKey(string(k), kv[i+1])
		}
	}
	return d
}

func nan() float64 { return math.NaN() }

func inf(sign int) float64 { return math.Inf(sign) }

func nest(depth int, leaf any) any {
	v := leaf
	for range depth {
		v = []any{v}
	}
	return v
}

// formatExamples are the FORMAT_EXAMPLES of mitmproxy's
// test/mitmproxy/io/test_tnetstring.py, followed by the examples in the
// tnetstring module docstring. canonical marks the encodings Dumps
// reproduces byte for byte.
var formatExamples = map[string]struct {
	data      string
	want      any
	canonical bool
}{
	"empty dict":  {data: "0:}", want: dict(), canonical: true},
	"empty list":  {data: "0:]", want: []any{}, canonical: true},
	"nested dict": {data: "51:5:hello,39:11:12345678901#4:this,4:true!0:~4:\x00\x00\x00\x00,]}", want: dict([]byte("hello"), []any{int64(12345678901), []byte("this"), true, nil, []byte("\x00\x00\x00\x00")}), canonical: true},
	"int":         {data: "5:12345#", want: int64(12345), canonical: true},
	"bytes":       {data: "12:this is cool,", want: []byte("this is cool"), canonical: true},
	"unicode":     {data: "19:this is unicode \xe2\x98\x85;", want: "this is unicode ★", canonical: true},
	"empty bytes": {data: "0:,", want: []byte{}, canonical: true},
	"empty str":   {data: "0:;", want: "", canonical: true},
	"null":        {data: "0:~", want: nil, canonical: true},
	"true":        {data: "4:true!", want: true, canonical: true},
	"false":       {data: "5:false!", want: false, canonical: true},
	"zero bytes":  {data: "10:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,", want: bytes.Repeat([]byte{0}, 10), canonical: true},
	"mixed list":  {data: "24:5:12345#5:67890#5:xxxxx,]", want: []any{int64(12345), int64(67890), []byte("xxxxx")}, canonical: true},
	"float list":  {data: "18:3:0.1^3:0.2^3:0.3^]", want: []any{0.1, 0.2, 0.3}, canonical: true},
	"deep nest": {
		data:      "243:238:233:228:223:218:213:208:203:198:193:188:183:178:173:168:163:158:153:148:143:138:133:128:123:118:113:108:103:99:95:91:87:83:79:75:71:67:63:59:55:51:47:43:39:35:31:27:23:19:15:11:hello-there,]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
		want:      nest(51, []byte("hello-there")),
		canonical: true,
	},
	"docstring bytes": {data: "11:hello world,", want: []byte("hello world"), canonical: true},
	"docstring int":   {data: "5:12345#", want: int64(12345), canonical: true},
	"docstring list":  {data: "19:5:12345#4:true!1:0#]", want: []any{int64(12345), true, int64(0)}, canonical: true},
}

func TestFormatExamples(t *testing.T) {
	for name, tt := range formatExamples {
		t.Run(name, func(t *testing.T) {
			got, err := Loads([]byte(tt.data))
			if err != nil {
				t.Fatalf("Loads(%q) error: %v", tt.data, err)
			}
			if diff := treeDiff(tt.want, got); diff != "" {
				t.Errorf("Loads(%q) mismatch (-want +got):\n%s", tt.data, diff)
			}

			v, rest, err := Pop([]byte(tt.data))
			if err != nil {
				t.Fatalf("Pop(%q) error: %v", tt.data, err)
			}
			if len(rest) != 0 || !Equal(tt.want, v) {
				t.Errorf("Pop(%q) = (%v, %q), want (%v, \"\")", tt.data, plain(v), rest, plain(tt.want))
			}

			enc, err := Dumps(tt.want)
			if err != nil {
				t.Fatalf("Dumps(%v) error: %v", plain(tt.want), err)
			}
			if tt.canonical && string(enc) != tt.data {
				t.Errorf("Dumps(%v) = %q, want %q", plain(tt.want), enc, tt.data)
			}
			back, err := Loads(enc)
			if err != nil {
				t.Fatalf("Loads(Dumps(%v)) error: %v", plain(tt.want), err)
			}
			if !Equal(tt.want, back) {
				t.Errorf("Loads(Dumps(v)) = %v, want %v", plain(back), plain(tt.want))
			}
		})
	}
}

// TestFileExamples ports Test_FileLoading.test_roundtrip_file_examples: Load
// must stop exactly at the end of the value and leave the rest unread.
func TestFileExamples(t *testing.T) {
	readers := map[string]func([]byte) io.Reader{
		"bufio": func(b []byte) io.Reader { return bufio.NewReader(bytes.NewReader(b)) },
		"bytes": func(b []byte) io.Reader { return bytes.NewReader(b) },
		"one byte at a time": func(b []byte) io.Reader {
			return iotest.OneByteReader(bytes.NewReader(b))
		},
	}
	for name, tt := range formatExamples {
		for rname, mk := range readers {
			t.Run(name+"/"+rname, func(t *testing.T) {
				enc, err := Dumps(tt.want)
				if err != nil {
					t.Fatal(err)
				}
				for _, data := range []string{tt.data, string(enc)} {
					r := mk([]byte(data + "OK"))
					got, err := Load(r)
					if err != nil {
						t.Fatalf("Load(%q) error: %v", data, err)
					}
					if !Equal(tt.want, got) {
						t.Errorf("Load(%q) = %v, want %v", data, plain(got), plain(tt.want))
					}
					rest, err := io.ReadAll(r)
					if err != nil {
						t.Fatal(err)
					}
					if string(rest) != "OK" {
						t.Errorf("after Load(%q) the reader holds %q, want \"OK\"", data, rest)
					}
				}
			})
		}
	}
}

func TestDumpWritesToWriter(t *testing.T) {
	var buf bytes.Buffer
	if err := Dump(&buf, []any{int64(12345), true, int64(0)}); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "19:5:12345#4:true!1:0#]"; got != want {
		t.Errorf("Dump wrote %q, want %q", got, want)
	}
}

// TestDictOrder checks that the writer emits entries in reverse insertion
// order, as mitmproxy does, and that the reader keeps file order.
func TestDictOrder(t *testing.T) {
	enc, err := Dumps(dict("a", int64(1), "b", int64(2)))
	if err != nil {
		t.Fatal(err)
	}
	// Recorded from tnetstring.dumps({"a": 1, "b": 2}) of mitmproxy 3368a0a.
	if got, want := string(enc), "16:1:b;1:2#1:a;1:1#}"; got != want {
		t.Fatalf("Dumps({a: 1, b: 2}) = %q, want %q", got, want)
	}
	if strings.Index(string(enc), "1:b;") > strings.Index(string(enc), "1:a;") {
		t.Errorf("b is written after a in %q", enc)
	}

	got, err := Loads(enc)
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]string{"b", "a"}, got.(*omap.Map[any]).Keys()); diff != "" {
		t.Errorf("decoded key order mismatch (-want +got):\n%s", diff)
	}
}

// TestFlowFiles reads the flow files written by mitmproxy. In
// corrupted_gzip_body.mitm the top-level keys run from websocket to version,
// the reverse of get_state's order; the other files hold other orders.
// Decoding keeps file order and encoding reverses every dictionary, so two
// round trips must reproduce mitmproxy's bytes exactly, floats included.
//
// Every .mitm file in the fixture directory is checked, so a fixture added
// later is covered without editing this test.
func TestFlowFiles(t *testing.T) {
	const dir = "mitmproxy/flows"
	files, err := filepath.Glob(filepath.Join(testutil.FixturePath(t, dir), "*.mitm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no .mitm fixtures in testdata/%s", dir)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			b := testutil.Fixture(t, dir+"/"+filepath.Base(file))
			var out []byte
			flows := 0
			for rest := b; len(rest) > 0; flows++ {
				v, r, err := Pop(rest)
				if err != nil {
					t.Fatalf("flow %d: %v", flows, err)
				}
				rest = r
				keys := v.(*omap.Map[any]).Keys()
				if filepath.Base(file) == "corrupted_gzip_body.mitm" && (keys[0] != "websocket" || keys[len(keys)-1] != "version") {
					t.Errorf("flow %d: keys = %v, want websocket first and version last", flows, keys)
				}
				reversed, err := Dumps(v)
				if err != nil {
					t.Fatalf("flow %d: %v", flows, err)
				}
				back, err := Loads(reversed)
				if err != nil {
					t.Fatalf("flow %d: %v", flows, err)
				}
				again, err := Dumps(back)
				if err != nil {
					t.Fatalf("flow %d: %v", flows, err)
				}
				out = append(out, again...)
			}
			if !bytes.Equal(out, b) {
				t.Errorf("two round trips changed the %d flows in the file", flows)
			}
		})
	}
}

func TestDictSemantics(t *testing.T) {
	tests := map[string]struct {
		data     string
		wantKeys []string
		want     *omap.Map[any]
	}{
		"success: byte-string keys stay byte strings": {
			data:     "16:1:a,1:1#1:b;1:2#}",
			wantKeys: []string{"a", "b"},
			want:     dict([]byte("a"), int64(1), "b", int64(2)),
		},
		"success: byte-string key that is not UTF-8": {
			data:     "8:1:\xff,1:1#}",
			wantKeys: []string{"\xff"},
			want:     dict([]byte("\xff"), int64(1)),
		},
		"success: duplicate byte-string key keeps its kind": {
			data:     "16:1:a,1:1#1:a,1:2#}",
			wantKeys: []string{"a"},
			want:     dict([]byte("a"), int64(2)),
		},
		"success: duplicate key keeps first position and last value": {
			data:     "24:1:a;1:1#1:b;1:2#1:a;1:3#}",
			wantKeys: []string{"a", "b"},
			want:     dict("a", int64(3), "b", int64(2)),
		},
		"success: many keys use the index": {
			data:     manyKeys(20),
			wantKeys: manyKeyNames(20),
			want:     manyKeyDict(20),
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Loads([]byte(tt.data))
			if err != nil {
				t.Fatalf("Loads(%q) error: %v", tt.data, err)
			}
			d := got.(*omap.Map[any])
			if diff := gocmp.Diff(tt.wantKeys, d.Keys()); diff != "" {
				t.Errorf("keys mismatch (-want +got):\n%s", diff)
			}
			if diff := treeDiff(tt.want, d); diff != "" {
				t.Errorf("value mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func manyKeyNames(n int) []string {
	keys := make([]string, n)
	for i := range n {
		keys[i] = fmt.Sprintf("k%02d", i)
	}
	return keys
}

func manyKeyDict(n int) *omap.Map[any] {
	d := omap.New[any]()
	for i, k := range manyKeyNames(n) {
		d.Set(k, int64(i))
	}
	return d
}

func manyKeys(n int) string {
	var payload strings.Builder
	for i, k := range manyKeyNames(n) {
		v := fmt.Sprint(i)
		fmt.Fprintf(&payload, "%d:%s;%d:%s#", len(k), k, len(v), v)
	}
	return fmt.Sprintf("%d:%s}", payload.Len(), payload.String())
}

// TestDictEncoding checks how the writer treats a dictionary's nil value
// and key kinds; the map's own semantics are tested in package omap.
func TestDictEncoding(t *testing.T) {
	var nilDict *omap.Map[any]
	if enc, err := Dumps(nilDict); err != nil || string(enc) != "0:}" {
		t.Errorf("Dumps(nil map) = %q, %v; want \"0:}\"", enc, err)
	}

	k := omap.NewWithCapacity[any](2)
	k.Set("t", int64(1))
	k.SetBytesKey("b", int64(2))
	k.Set("b", int64(3))
	k.SetBytesKey("t", int64(4))
	if enc, err := Dumps(k); err != nil || string(enc) != "16:1:b,1:3#1:t,1:4#}" {
		t.Errorf("Dumps = %q, %v; want byte-string keys written with ,", enc, err)
	}
}

func TestEqual(t *testing.T) {
	big1 := new(big.Int).Lsh(big.NewInt(1), 70)
	tests := map[string]struct {
		a, b any
		want bool
	}{
		"success: dict order is ignored":    {a: dict("a", int64(1), "b", int64(2)), b: dict("b", int64(2), "a", int64(1)), want: true},
		"success: int64 equals small big":   {a: int64(7), b: big.NewInt(7), want: true},
		"success: big equals big":           {a: big1, b: new(big.Int).Set(big1), want: true},
		"success: nil bytes equals empty":   {a: []byte(nil), b: []byte{}, want: true},
		"failure: NaN is unequal":           {a: nan(), b: nan(), want: false},
		"failure: string is not bytes":      {a: "a", b: []byte("a"), want: false},
		"failure: dict value differs":       {a: dict("a", int64(1)), b: dict("a", int64(2)), want: false},
		"failure: dict key differs":         {a: dict("a", int64(1)), b: dict("b", int64(1)), want: false},
		"failure: dict key kind differs":    {a: dict("a", int64(1)), b: dict([]byte("a"), int64(1)), want: false},
		"success: byte-string keys equal":   {a: dict([]byte("a"), int64(1)), b: dict([]byte("a"), int64(1)), want: true},
		"failure: list length differs":      {a: []any{nil}, b: []any{}, want: false},
		"failure: int is not float":         {a: int64(1), b: 1.0, want: false},
		"failure: big is not int64 range":   {a: big1, b: int64(0), want: false},
		"failure: unknown types":            {a: struct{}{}, b: struct{}{}, want: false},
		"failure: nil is not empty list":    {a: nil, b: []any{}, want: false},
		"failure: true is not false":        {a: true, b: false, want: false},
		"failure: dict is not list":         {a: dict(), b: []any{}, want: false},
		"failure: int64 is not big of 2^70": {a: int64(0), b: big1, want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Equal(tt.a, tt.b); got != tt.want {
				t.Errorf("Equal(%v, %v) = %v, want %v", plain(tt.a), plain(tt.b), got, tt.want)
			}
		})
	}
}

func TestDumpsTypes(t *testing.T) {
	tests := map[string]struct {
		in   any
		want string
	}{
		"int":          {in: 42, want: "2:42#"},
		"int32":        {in: int32(-7), want: "2:-7#"},
		"int16":        {in: int16(300), want: "3:300#"},
		"int8":         {in: int8(-128), want: "4:-128#"},
		"uint":         {in: uint(5), want: "1:5#"},
		"uint64 max":   {in: uint64(1<<64 - 1), want: "20:18446744073709551615#"},
		"uint32":       {in: uint32(1), want: "1:1#"},
		"uint16":       {in: uint16(2), want: "1:2#"},
		"uint8":        {in: uint8(3), want: "1:3#"},
		"float32":      {in: float32(0.5), want: "3:0.5^"},
		"nil bytes":    {in: []byte(nil), want: "0:,"},
		"big negative": {in: big.NewInt(-12), want: "3:-12#"},
		"nested dict":  {in: dict("x", dict("y", []any{"z"})), want: "19:1:x;11:1:y;4:1:z;]}}"},
		"timestamp":    {in: 1759600000.123456, want: "17:1759600000.123456^"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Dumps(tt.in)
			if err != nil {
				t.Fatalf("Dumps(%v) error: %v", tt.in, err)
			}
			if string(got) != tt.want {
				t.Errorf("Dumps(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDumpsErrors(t *testing.T) {
	selfRef := []any{nil}
	selfRef[0] = selfRef
	tests := map[string]struct {
		in      any
		wantErr string
		is      error
	}{
		"error: unsupported type":  {in: map[string]any{}, wantErr: "unserializable value", is: ErrUnsupportedType},
		"error: nil big.Int":       {in: (*big.Int)(nil), wantErr: "nil *big.Int", is: ErrUnsupportedType},
		"error: invalid UTF-8":     {in: "\xff", wantErr: "not valid UTF-8"},
		"error: invalid UTF-8 key": {in: dict("\xff", nil), wantErr: "not valid UTF-8"},
		"error: bad value in list": {in: []any{struct{}{}}, wantErr: "unserializable value", is: ErrUnsupportedType},
		"error: bad value in dict": {in: dict("a", struct{}{}), wantErr: "unserializable value", is: ErrUnsupportedType},
		"error: self reference":    {in: selfRef, wantErr: "deeper than 1000"},
		"error: deep dict":         {in: deepDict(maxDepth + 1), wantErr: "deeper than 1000"},
		"error: huge integer":      {in: new(big.Int).Exp(big.NewInt(10), big.NewInt(maxIntDigits), nil), wantErr: "4301 digits"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Dumps(tt.in)
			if err == nil {
				t.Fatalf("Dumps succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Dumps error = %q, want it to contain %q", err, tt.wantErr)
			}
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("errors.Is(%v, %v) = false", err, tt.is)
			}
			if err := Dump(io.Discard, tt.in); err == nil {
				t.Error("Dump succeeded where Dumps failed")
			}
		})
	}
}

func deepDict(depth int) any {
	var v any = int64(1)
	for range depth {
		v = dict("k", v)
	}
	return v
}

func TestMaxDepthBoundary(t *testing.T) {
	enc, err := Dumps(nest(maxDepth, nil))
	if err != nil {
		t.Fatalf("Dumps at the depth limit: %v", err)
	}
	if _, err := Loads(enc); err != nil {
		t.Fatalf("Loads at the depth limit: %v", err)
	}
	deeper := fmt.Appendf(nil, "%d:%s]", len(enc), enc)
	var se *SyntaxError
	if _, err := Loads(deeper); !errors.As(err, &se) || !strings.Contains(err.Error(), "deeper than 1000") {
		t.Errorf("Loads past the depth limit: error = %v, want a depth SyntaxError", err)
	}
	dictDeeper := fmt.Appendf(nil, "%d:1:k;%d:%s]}", len(enc)+4+len(fmt.Sprint(len(enc)))+2, len(enc), enc)
	if _, err := Loads(dictDeeper); err == nil || !strings.Contains(err.Error(), "deeper than 1000") {
		t.Errorf("Loads of a dict past the depth limit: error = %v", err)
	}
}

func TestLoadsErrors(t *testing.T) {
	tests := map[string]struct {
		data    string
		wantErr string
	}{
		"error: empty input":        {data: "", wantErr: "not a tnetstring: missing or invalid length prefix: \"\""},
		"error: no colon":           {data: "5", wantErr: "invalid length prefix: \"5\""},
		"error: no digits":          {data: ":~", wantErr: "missing or invalid length prefix"},
		"error: non-digit prefix":   {data: "x:~", wantErr: "missing or invalid length prefix"},
		"error: length past end":    {data: "5:abc,", wantErr: "invalid length prefix: 5"},
		"error: missing tag":        {data: "3:abc", wantErr: "invalid length prefix: 3"},
		"error: huge length":        {data: "99999999999999999999999:x,", wantErr: "invalid length prefix"},
		"error: trailing data":      {data: "0:~OK", wantErr: "2 bytes of trailing data"},
		"error: unknown tag":        {data: "0:x", wantErr: "unknown type tag: 120"},
		"error: bad bool":           {data: "4:True!", wantErr: "invalid boolean literal"},
		"error: bad null":           {data: "1:0~", wantErr: "invalid null literal"},
		"error: bad int":            {data: "3:1.5#", wantErr: "invalid integer literal"},
		"error: empty int":          {data: "0:#", wantErr: "invalid integer literal"},
		"error: bad float":          {data: "3:abc^", wantErr: "invalid float literal"},
		"error: hex float":          {data: "5:0x1p0^", wantErr: "invalid float literal"},
		"error: invalid UTF-8":      {data: "1:\xff;", wantErr: "invalid UTF-8"},
		"error: non-string key":     {data: "7:1:1#0:~}", wantErr: "dictionary key is int64"},
		"error: key without value":  {data: "4:1:a;}", wantErr: "has no value"},
		"error: bytes and text key": {data: "16:1:a,1:1#1:a;1:2#}", wantErr: `dictionary has both a byte-string and a text key "a"`},
		"error: text and bytes key": {data: "16:1:a;1:1#1:a,1:2#}", wantErr: `dictionary has both a byte-string and a text key "a"`},
		"error: bad item in list":   {data: "3:0:x]", wantErr: "unknown type tag"},
		"error: bad key in dict":    {data: "3:0:x}", wantErr: "unknown type tag"},
		"error: bad value in dict":  {data: "7:1:a;0:x}", wantErr: "unknown type tag"},
		"error: integer too long":   {data: fmt.Sprintf("%d:%s#", maxIntDigits+1, strings.Repeat("9", maxIntDigits+1)), wantErr: "4301 digits"},
		"error: long prefix quoted": {data: strings.Repeat("a", 40), wantErr: "aaaa\"..."},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			v, err := Loads([]byte(tt.data))
			if err == nil {
				t.Fatalf("Loads(%q) = %v, want error containing %q", tt.data, plain(v), tt.wantErr)
			}
			if _, ok := errors.AsType[*SyntaxError](err); !ok {
				t.Errorf("Loads(%q) error %T is not a *SyntaxError", tt.data, err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Loads(%q) error = %q, want it to contain %q", tt.data, err, tt.wantErr)
			}
		})
	}
}

func TestLoadsScalars(t *testing.T) {
	huge, _ := new(big.Int).SetString("123456789012345678901234567890", 10)
	tests := map[string]struct {
		data string
		want any
	}{
		"success: negative int":     {data: "2:-5#", want: int64(-5)},
		"success: plus sign":        {data: "2:+5#", want: int64(5)},
		"success: leading zeros":    {data: "3:007#", want: int64(7)},
		"success: int64 max":        {data: "19:9223372036854775807#", want: int64(1<<63 - 1)},
		"success: int64 overflow":   {data: "30:123456789012345678901234567890#", want: huge},
		"success: negative big":     {data: "20:-9223372036854775809#", want: new(big.Int).Sub(big.NewInt(-1<<63), big.NewInt(1))},
		"success: inf":              {data: "3:inf^", want: inf(1)},
		"success: -inf":             {data: "4:-inf^", want: inf(-1)},
		"success: infinity":         {data: "8:Infinity^", want: inf(1)},
		"success: overflow to inf":  {data: "5:1e400^", want: inf(1)},
		"success: underflow to 0":   {data: "6:1e-400^", want: 0.0},
		"success: exponent form":    {data: "5:1e+16^", want: 1e16},
		"success: length prefix 00": {data: "00:~", want: nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Loads([]byte(tt.data))
			if err != nil {
				t.Fatalf("Loads(%q) error: %v", tt.data, err)
			}
			if diff := treeDiff(tt.want, got); diff != "" {
				t.Errorf("Loads(%q) mismatch (-want +got):\n%s", tt.data, diff)
			}
		})
	}

	got, err := Loads([]byte("3:nan^"))
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := got.(float64); !ok || f == f {
		t.Errorf("Loads(nan) = %v, want NaN", got)
	}
}

// TestLoadErrors ports test_error_on_absurd_lengths and covers truncation.
func TestLoadErrors(t *testing.T) {
	t.Run("error: absurd length leaves the colon unread", func(t *testing.T) {
		r := bytes.NewReader([]byte("1000000000000:pwned!,"))
		_, err := Load(r)
		if err == nil || !strings.Contains(err.Error(), "absurdly large length prefix") {
			t.Fatalf("Load error = %v, want absurdly large length prefix", err)
		}
		if c, _ := r.ReadByte(); c != ':' {
			t.Errorf("next byte = %q, want ':'", c)
		}
	})

	t.Run("success: empty reader is io.EOF", func(t *testing.T) {
		if _, err := Load(bytes.NewReader(nil)); err != io.EOF {
			t.Errorf("Load(empty) error = %v, want io.EOF", err)
		}
	})

	tests := map[string]struct {
		data       string
		wantErr    string
		unexpected bool
	}{
		"error: cut in prefix":   {data: "12", wantErr: "truncated", unexpected: true},
		"error: cut in payload":  {data: "5:ab", wantErr: "truncated", unexpected: true},
		"error: cut before tag":  {data: "2:ab", wantErr: "truncated", unexpected: true},
		"error: cut in big body": {data: "2000000:abc", wantErr: "truncated", unexpected: true},
		"error: missing colon":   {data: "5x", wantErr: "missing or invalid length prefix"},
		"error: no digits":       {data: ":", wantErr: "missing or invalid length prefix"},
		"error: bad payload":     {data: "1:x#", wantErr: "invalid integer literal"},
		"error: wrong tag":       {data: "0:?", wantErr: "unknown type tag"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for _, r := range []io.Reader{bytes.NewReader([]byte(tt.data)), iotest.OneByteReader(strings.NewReader(tt.data))} {
				_, err := Load(r)
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Load(%q) error = %v, want it to contain %q", tt.data, err, tt.wantErr)
				}
				if got := errors.Is(err, io.ErrUnexpectedEOF); got != tt.unexpected {
					t.Errorf("errors.Is(%v, io.ErrUnexpectedEOF) = %v, want %v", err, got, tt.unexpected)
				}
			}
		})
	}

	t.Run("error: reader failure is passed through", func(t *testing.T) {
		boom := errors.New("boom")
		if _, err := Load(iotest.ErrReader(boom)); !errors.Is(err, boom) {
			t.Errorf("Load error = %v, want %v", err, boom)
		}
		r := io.MultiReader(strings.NewReader("2000000:"), iotest.ErrReader(boom))
		if _, err := Load(r); !errors.Is(err, boom) {
			t.Errorf("Load error = %v, want %v", err, boom)
		}
	})

	t.Run("success: large body read incrementally", func(t *testing.T) {
		body := bytes.Repeat([]byte("x"), 2<<20)
		enc, err := Dumps(body)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Load(iotest.HalfReader(bytes.NewReader(enc)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.([]byte), body) {
			t.Error("large body did not round-trip through Load")
		}
	})
}

// TestPopDoesNotAlias checks that decoded byte strings own their memory.
func TestPopDoesNotAlias(t *testing.T) {
	in := []byte("3:abc,rest")
	v, rest, err := Pop(in)
	if err != nil {
		t.Fatal(err)
	}
	copy(in, "XXXXXX")
	if got := string(v.([]byte)); got != "abc" {
		t.Errorf("decoded bytes changed with the input: %q", got)
	}
	if string(rest) != "rest" {
		t.Errorf("rest = %q, want \"rest\"", rest)
	}
}

// randomObject ports get_random_object from mitmproxy's test suite: scalars
// become likelier as depth grows, so generation terminates.
func randomObject(r *rand.Rand, depth int) any {
	const maxInt = 1<<31 - 1
	if depth+r.IntN(11-min(depth, 10)) <= 4 {
		n := r.IntN(11)
		if r.IntN(2) == 0 {
			list := make([]any, 0, n)
			for range n {
				list = append(list, randomObject(r, depth+1))
			}
			return list
		}
		d := omap.New[any]()
		for range n {
			k := make([]string, r.IntN(101))
			for i := range k {
				k[i] = fmt.Sprint(32 + r.IntN(95))
			}
			d.Set("["+strings.Join(k, ", ")+"]", randomObject(r, depth+1))
		}
		return d
	}
	switch r.IntN(5) {
	case 0:
		return nil
	case 1:
		return true
	case 2:
		return false
	case 3:
		n := int64(r.IntN(maxInt + 1))
		if r.IntN(2) == 1 {
			n = -n
		}
		return n
	}
	b := make([]byte, r.IntN(101))
	for i := range b {
		b[i] = byte(32 + r.IntN(95))
	}
	return b
}

func TestRoundTripRandom(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 200 {
		v := randomObject(r, 0)
		enc, err := Dumps(v)
		if err != nil {
			t.Fatalf("object %d: Dumps error: %v", i, err)
		}
		got, err := Loads(enc)
		if err != nil {
			t.Fatalf("object %d: Loads(%q) error: %v", i, enc, err)
		}
		if !Equal(v, got) {
			t.Fatalf("object %d: round trip changed the value:\nwant %v\ngot  %v", i, plain(v), plain(got))
		}
		popped, rest, err := Pop(enc)
		if err != nil || len(rest) != 0 || !Equal(v, popped) {
			t.Fatalf("object %d: Pop = (%v, %q, %v)", i, plain(popped), rest, err)
		}
		loaded, err := Load(bytes.NewReader(append(enc, "OK"...)))
		if err != nil || !Equal(v, loaded) {
			t.Fatalf("object %d: Load = (%v, %v)", i, plain(loaded), err)
		}
	}
}

// TestRoundTripBigInteger ports test_roundtrip_big_integer: 1557! has 4,300
// digits, the most Python converts by default.
func TestRoundTripBigInteger(t *testing.T) {
	f := new(big.Int).MulRange(1, 1557)
	enc, err := Dumps(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Loads(enc)
	if err != nil {
		t.Fatal(err)
	}
	if b, ok := got.(*big.Int); !ok || b.Cmp(f) != 0 {
		t.Errorf("1557! did not round-trip: got %T", got)
	}
	neg := new(big.Int).Neg(f)
	enc, err = Dumps(neg)
	if err != nil {
		t.Fatalf("Dumps(-1557!) error: %v", err)
	}
	if got, err := Loads(enc); err != nil || !Equal(neg, got) {
		t.Errorf("-1557! did not round-trip: %v", err)
	}
}
