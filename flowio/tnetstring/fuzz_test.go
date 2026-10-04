// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tnetstring

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzLoads feeds arbitrary bytes to the reader. Whatever decodes must encode
// again, byte-string dictionary keys that are not UTF-8 included, and the
// encoding must be stable: decoding reverses no order and encoding reverses every
// dictionary, so encoding twice through a decode is the identity.
func FuzzLoads(f *testing.F) {
	for _, tt := range formatExamples {
		f.Add([]byte(tt.data))
	}
	for _, seed := range []string{
		"", "0:", ":", "00:~", "1:\xff;", "2:\xff\xfe,", "4:1:\xff,}", "3:inf^", "3:nan^", "5:1e400^",
		"30:123456789012345678901234567890#", "1000000000000:pwned!,", "7:1:1#0:~}", "0:~OK",
		"16:1:a,1:1#1:a,1:2#}", "16:1:a,1:1#1:a;1:2#}", "8:1:\xff,1:1#}",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, rest, popErr := Pop(data)
		loaded, loadErr := Load(bytes.NewReader(data))
		if popErr == nil && loadErr == nil && !sameEncoding(v, loaded) {
			t.Fatalf("Pop and Load disagree on %q", data)
		}
		whole, err := Loads(data)
		if (err == nil) != (popErr == nil && len(rest) == 0) {
			t.Fatalf("Loads error %v disagrees with Pop (%v, %d trailing bytes)", err, popErr, len(rest))
		}
		if popErr != nil {
			if _, ok := errors.AsType[*SyntaxError](popErr); !ok {
				t.Fatalf("Pop error %T is not a *SyntaxError: %v", popErr, popErr)
			}
			return
		}
		if err == nil && !sameEncoding(v, whole) {
			t.Fatalf("Loads and Pop disagree on %q", data)
		}

		first, err := Dumps(v)
		if err != nil {
			t.Fatalf("Dumps of a decoded value failed: %v", err)
		}
		reversed, err := Loads(first)
		if err != nil {
			t.Fatalf("Loads(Dumps(v)) failed: %v\nencoding %q", err, first)
		}
		if !bytes.Contains(first, []byte("nan^")) && !Equal(v, reversed) {
			t.Fatalf("round trip changed the value of %q", data)
		}
		second, err := Dumps(reversed)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Loads(second)
		if err != nil {
			t.Fatal(err)
		}
		if third, err := Dumps(back); err != nil || !bytes.Equal(first, third) {
			t.Fatalf("encoding is not stable: %q then %q (%v)", first, third, err)
		}
	})
}

func sameEncoding(a, b any) bool {
	ae, aerr := Dumps(a)
	be, berr := Dumps(b)
	if aerr != nil || berr != nil {
		return (aerr == nil) == (berr == nil)
	}
	return bytes.Equal(ae, be)
}

// FuzzRoundTrip builds values from fuzzed scalars, nests them, and checks that
// every value the writer accepts reads back equal through Loads, Pop and Load.
func FuzzRoundTrip(f *testing.F) {
	f.Add("hello", []byte("hello"), int64(12345), 0.1, true, uint8(0))
	f.Add("this is unicode ★", []byte{0, 0, 0, 0}, int64(12345678901), 1759600000.123456, false, uint8(3))
	f.Add("", []byte{}, int64(-1<<63), math.Inf(-1), true, uint8(51))
	f.Add("version", []byte(nil), int64(1<<63-1), 1e16, false, uint8(200))
	f.Add("k", []byte("hello-there"), int64(0), 5e-324, true, uint8(7))
	f.Fuzz(func(t *testing.T, s string, b []byte, i int64, x float64, flag bool, depth uint8) {
		s = strings.ToValidUTF8(s, "�")
		var v any = []any{s, b, i, x, flag, nil, dict(s, b, "k", i, "x", x)}
		for level := range int(depth) % 64 {
			if level%2 == 0 {
				v = dict(s, v, "flag", flag)
			} else {
				v = []any{v, i}
			}
		}
		enc, err := Dumps(v)
		if err != nil {
			t.Fatalf("Dumps failed: %v", err)
		}
		got, err := Loads(enc)
		if err != nil {
			t.Fatalf("Loads(%q) failed: %v", enc, err)
		}
		if !math.IsNaN(x) && !Equal(v, got) {
			t.Fatalf("round trip changed the value:\nwant %v\ngot  %v", plain(v), plain(got))
		}
		popped, rest, err := Pop(append(enc, "OK"...))
		if err != nil || string(rest) != "OK" || !sameEncoding(got, popped) {
			t.Fatalf("Pop = (%v, %q, %v)", plain(popped), rest, err)
		}
		loaded, err := Load(bytes.NewReader(enc))
		if err != nil || !sameEncoding(got, loaded) {
			t.Fatalf("Load = (%v, %v)", plain(loaded), err)
		}
		if !utf8.Valid(enc) && utf8.ValidString(s) && utf8.Valid(b) {
			t.Fatalf("encoding of valid UTF-8 input is not UTF-8: %q", enc)
		}
	})
}
