// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package socks5

import (
	"bytes"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func FuzzSOCKS5Handshake(f *testing.F) {
	for _, seed := range []struct {
		data string
		auth bool
	}{
		{"\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00\x01\x12\x34applicationdata", false},
		{"\x05\x01\x00\x05\x01\x00\x04" + string(make([]byte, 15)) + "\x01\x12\x34", false},
		{"\x05\x01\x00\x05\x01\x00\x03\x0bexample.com\x12\x34", false},
		{"GET / HTTP/1.1", false},
		{"abcd", false},
		{"\x05\x01\x00\x05\x02\x00\x01\x7f\x00\x00\x01\x12\x34", false},
		{"\x05\x01\x00\x05\x01\x00\xff\x00\x00", false},
		{"\x05\x01\x02\x01\x04user\x08password\x05\x01\x00\x01\x7f\x00\x00\x01\x12\x34", true},
		{"\x05\x02\x01\x02\x01\x04user\x08password", true},
		{"\x05\x01\x00", true},
		{"\x05\x02\x00\x02\x01\x04user\x07errcode", true},
		{"\x05", false},
		{"\x05\x01\x02\xff\x00\x00", true},
	} {
		f.Add([]byte(seed.data), seed.auth)
	}
	f.Fuzz(func(t *testing.T, input []byte, auth bool) {
		reader := bytes.NewReader(input)
		p := parser{need: 2, auth: auth}
		controlBytes := 0
		for range 3 {
			if err := p.next(reader); err != nil {
				return
			}
			if p.n > len(p.frame) || p.need > len(p.frame) || p.n != p.need {
				t.Fatalf("unbounded parser state: n=%d need=%d stage=%v", p.n, p.need, p.stage)
			}
			controlBytes += p.n
			switch p.stage {
			case methods:
				if auth {
					p.reset(credentials, 3)
				} else {
					p.reset(request, 5)
				}
			case password:
				user, password := p.credentials()
				if len(user) > 4*255 || len(password) > 4*255 {
					t.Fatal("credential decoding exceeded bounded expansion")
				}
				p.reset(request, 5)
			case handover:
				destination := p.destination()
				if destination.Port < 0 || destination.Port > 65535 {
					t.Fatalf("invalid port: %d", destination.Port)
				}
				consumed := len(input) - reader.Len()
				if consumed > 257+513+262 {
					t.Fatalf("consumed unbounded control bytes: %d", consumed)
				}
				remaining, err := io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(input[controlBytes:], remaining); diff != "" {
					t.Fatal(diff)
				}
				return
			case greeting, credentials, username, request, address:
				t.Fatalf("incomplete frame returned success: %v", p.stage)
			}
		}
		t.Fatal("parser did not finish within its three bounded frames")
	})
}

func TestParserDecoding(t *testing.T) {
	tests := map[string]struct {
		input []byte
		want  string
	}{
		"valid UTF8":   {[]byte("日�"), "日�"},
		"invalid UTF8": {[]byte{0xc3, 0x28, 0xe2, 0x82, 0xff}, `\xc3(\xe2\x82\xff`},
		"empty":        {nil, ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, decodeCredentials(tt.input)); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
