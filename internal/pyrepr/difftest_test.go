// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package pyrepr

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

// pythonSamplesScript prints one line per generated sample, "str" or
// "bytes", the hex of the sample's bytes and Python's repr of it, separated
// by tabs; a repr never holds a tab or a newline. A str sample is its bytes
// decoded with errors="surrogateescape", so random bytes exercise the
// undecodable-byte path. Samples holding a code point Python's Unicode
// database leaves unassigned are dropped: Go's tables are newer, and those
// code points are the known skew TestUnicodeVersionSkew covers.
const pythonSamplesScript = `
import random, sys, unicodedata

rng = random.Random(20261005)
pool = (
    list("abcxyz019 ~") * 6
    + list("'\"\\") * 6
    + ["\t", "\n", "\r", "\x00", "\x01", "\x1f", "\x7f"] * 3
    + [chr(c) for c in range(0x80, 0x100)]
    + [chr(c) for c in (0x200B, 0x2028, 0x3000, 0xFEFF, 0xFFFD, 0xE000, 0x65E5, 0x0301)]
    + ["\U0001F600", "\U000E0001", "\U0010FFFF", "\U00020000"]
)

def emit(kind, raw, obj):
    sys.stdout.write("%s\t%s\t%s\n" % (kind, raw.hex(), repr(obj)))

def assigned(s):
    return all(unicodedata.category(c) != "Cn" or 0xDC80 <= ord(c) <= 0xDCFF for c in s)

n = 0
while n < 300:
    s = "".join(rng.choice(pool) for _ in range(rng.randrange(0, 12)))
    raw = s.encode("utf8")
    if n % 3 == 2:
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 12)))
        s = raw.decode("utf8", "surrogateescape")
    if not assigned(s):
        continue
    emit("str", raw, s)
    emit("bytes", raw, raw)
    n += 1
`

func TestDifferentialRepr(t *testing.T) {
	out := difftest.Python(t, pythonSamplesScript, nil)
	sc := bufio.NewScanner(bytes.NewReader(out))
	var str, byt int
	for sc.Scan() {
		kind, rest, ok1 := strings.Cut(sc.Text(), "\t")
		hexRaw, want, ok2 := strings.Cut(rest, "\t")
		if !ok1 || !ok2 {
			t.Fatalf("malformed line %q", sc.Text())
		}
		raw, err := hex.DecodeString(hexRaw)
		if err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		var got string
		switch kind {
		case "str":
			got = Str(string(raw))
			str++
		case "bytes":
			got = Bytes(raw)
			byt++
		default:
			t.Fatalf("line %q: unknown kind %q", sc.Text(), kind)
		}
		if got != want {
			t.Errorf("%s %q: got %s, want %s", kind, raw, got, want)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if str < 300 || byt < 300 {
		t.Fatalf("compared %d str and %d bytes samples, want at least 300 of each", str, byt)
	}
	t.Logf("compared %d str and %d bytes samples", str, byt)
}
