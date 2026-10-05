// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package http1

import (
	"bufio"
	"bytes"
	json "encoding/json/v2"
	"fmt"
	rand "math/rand/v2"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestRequestHeadsAgainstPython(t *testing.T) {
	const seed = uint64(0x4854545031)
	t.Logf("request-head seed=%d", seed)
	rng := rand.New(rand.NewPCG(seed, seed+1))
	targets := []string{"/", "*", "http://example.test/a?x=1", "HTTP://example.test:80", "https://example.test/", "example.test:443", "/raw\xff", "ws://example.test/"}
	methods := []string{"GET", "POST", "OPTIONS", "CONNECT", "get"}
	versions := []string{"HTTP/1.0", "HTTP/1.1", "HTTP/9.9", "HTTP/10.1", "WTF/1.1"}
	separators := []string{": ", ":\t", " :", ":"}
	values := []string{"", "value", " x \t", "\xff", "one\r\n\ttwo", "one\r\n two\r\n\tthree"}
	inputs := make([][]byte, 500)
	for i := range inputs {
		line := fmt.Sprintf("%s %s %s\r\n", methods[rng.IntN(len(methods))], targets[rng.IntN(len(targets))], versions[rng.IntN(len(versions))])
		for range rng.IntN(5) {
			line += "X-Test" + separators[rng.IntN(len(separators))] + values[rng.IntN(len(values))] + "\r\n"
		}
		inputs[i] = []byte(line + "\r\n")
	}
	type result struct {
		OK      bool        `json:"ok"`
		Method  []byte      `json:"method,omitzero"`
		Target  []byte      `json:"target,omitzero"`
		Version []byte      `json:"version,omitzero"`
		Headers [][2][]byte `json:"headers,omitzero"`
	}
	data, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	const script = `import base64, json, sys
from mitmproxy.net.http.http1 import read

def enc(b):
    return base64.b64encode(b).decode()

out = []
for encoded in json.load(sys.stdin):
    raw = base64.b64decode(encoded)
    lines = [line.removesuffix(b"\r") for line in raw.split(b"\n")[:-2]]
    try:
        req = read.read_request_head(lines)
        out.append(dict(ok=True, method=enc(req.data.method), target=enc(lines[0].split()[1]), version=enc(req.data.http_version), headers=[[enc(k), enc(v)] for k,v in req.headers.fields]))
    except (ValueError, IndexError):
        out.append(dict(ok=False))
json.dump(out, sys.stdout)
`
	var want []result
	if err := json.Unmarshal(difftest.Python(t, script, data), &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != len(inputs) {
		t.Fatalf("oracle returned %d results for %d inputs", len(want), len(inputs))
	}
	for i, input := range inputs {
		head, err := ReadRequestHead(bufio.NewReader(bytes.NewReader(input)))
		got := result{OK: err == nil}
		if err == nil {
			got.Method, got.Target, got.Version = []byte(head.Request.Method), head.Target, []byte(head.Request.HTTPVersion)
			got.Headers = make([][2][]byte, len(head.Request.Headers))
			for j, field := range head.Request.Headers {
				got.Headers[j] = [2][]byte{field.Name, field.Value}
			}
		}
		if diff := gocmp.Diff(want[i], got); diff != "" {
			t.Fatalf("seed=%d row=%d input=%q error=%v (-Python +Go):\n%s", seed, i, input, err, diff)
		}
	}
}
