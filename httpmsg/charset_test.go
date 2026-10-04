// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestLegacyCharsets(t *testing.T) {
	t.Parallel()

	// The expected bytes come from CPython 3.14: text.encode(codec).hex().
	tests := map[string]struct {
		label string
		text  string
		hex   string
	}{
		"success: gb18030":                   {label: "gb18030", text: "中文测试€", hex: "d6d0cec4b2e2cad4a2e3"},
		"success: iso-8859-2":                {label: "iso-8859-2", text: "Zażółć gęślą", hex: "5a61bff3b3e62067eab66cb1"},
		"success: shift_jis":                 {label: "shift_jis", text: "日本語テキスト", hex: "93fa967b8cea8365834c83588367"},
		"success: euc-kr":                    {label: "euc-kr", text: "한국어", hex: "c7d1b1b9beee"},
		"success: windows-1252":              {label: "windows-1252", text: "café – “quoted” €", hex: "636166e92096209371756f746564942080"},
		"success: python cp1252 spelling":    {label: "cp1252", text: "naïve €", hex: "6e61ef76652080"},
		"success: windows-1251":              {label: "windows-1251", text: "Привет", hex: "cff0e8e2e5f2"},
		"success: koi8-r":                    {label: "KOI8-R", text: "Привет", hex: "f0d2c9d7c5d4"},
		"success: big5":                      {label: "big5", text: "繁體中文", hex: "c163c5e9a4a4a4e5"},
		"success: euc-jp":                    {label: "euc-jp", text: "日本語", hex: "c6fccbdcb8ec"},
		"success: iso-8859-15":               {label: "iso-8859-15", text: "€uro œ", hex: "a475726f20bd"},
		"success: latin2 alias":              {label: "latin2", text: "Łódź", hex: "a3f364bc"},
		"success: windows-1250":              {label: "windows-1250", text: "Čeština", hex: "c8659a74696e61"},
		"success: iso-2022-jp":               {label: "iso-2022-jp", text: "日本語", hex: "1b2442467c4b5c386c1b2842"},
		"success: python iso8859_7 spelling": {label: "iso8859_7", text: "Ελληνικά", hex: "c5ebebe7ede9eadc"},
		"success: python euc_kr spelling":    {label: "euc_kr", text: "한국어", hex: "c7d1b1b9beee"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			want, err := hex.DecodeString(tt.hex)
			if err != nil {
				t.Fatal(err)
			}
			got, err := encodeText(tt.text, tt.label)
			if err != nil {
				t.Fatalf("encodeText(%q, %q): %v", tt.text, tt.label, err)
			}
			if hex.EncodeToString(got) != tt.hex {
				t.Errorf("encodeText(%q, %q) = %x, want %s", tt.text, tt.label, got, tt.hex)
			}
			text, err := decodeText(want, tt.label)
			if err != nil {
				t.Fatalf("decodeText(%s, %q): %v", tt.hex, tt.label, err)
			}
			if text != tt.text {
				t.Errorf("decodeText(%s, %q) = %q, want %q", tt.hex, tt.label, text, tt.text)
			}
		})
	}
}

func TestLegacyCharsetErrors(t *testing.T) {
	t.Parallel()

	decodes := map[string]struct {
		label   string
		data    string
		wantErr string
	}{
		// CPython raises UnicodeDecodeError for both inputs.
		"error: truncated shift_jis":   {label: "shift_jis", data: "\x82", wantErr: "cannot decode"},
		"error: invalid euc-kr":        {label: "euc-kr", data: "\xff\xff", wantErr: "cannot decode"},
		"error: unknown label":         {label: "wtf", data: "foo", wantErr: `unsupported character set "wtf"`},
		"error: known but unsupported": {label: "utf-7", data: "foo", wantErr: "unsupported character set"},
	}
	for name, tt := range decodes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeText([]byte(tt.data), tt.label); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("decodeText(%q, %q) error = %v, want %q", tt.data, tt.label, err, tt.wantErr)
			}
		})
	}

	encodes := map[string]struct {
		label string
		text  string
	}{
		"error: character outside the set": {label: "iso-8859-2", text: "日本"},
		"error: unknown label":             {label: "wtf", text: "foo"},
		"error: raw byte in text":          {label: "gb18030", text: "a\xffb"},
		"error: raw byte with utf-8":       {label: "utf-8", text: "a\xffb"},
	}
	for name, tt := range encodes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if b, err := encodeText(tt.text, tt.label); err == nil {
				t.Errorf("encodeText(%q, %q) = %x, want an error", tt.text, tt.label, b)
			}
		})
	}
}

func TestMessageTextLegacyCharset(t *testing.T) {
	t.Parallel()

	// Ports test_http.py::TestMessageText::test_guess_meta_charset: a
	// gb2312 meta charset is read as gb18030.
	r := tResp()
	r.Headers.Set("content-type", "text/html")
	r.RawContent = []byte(`<meta http-equiv="content-type" content="text/html;charset=gb2312">` + "\xe6\x98\x8e\xe4\xbc\xaf")
	text, err := r.Text()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "鏄庝集") {
		t.Errorf("Text() = %q, want it to contain 鏄庝集", text)
	}

	// Ports test_guess_css_charset for the text/css case.
	css := tResp()
	css.Headers.Set("content-type", "text/css")
	css.RawContent = []byte(`@charset "gb2312";#foo::before {content: "` + "\xe6\x98\x8e\xe4\xbc\xaf" + `"}`)
	if text, err := css.Text(); err != nil || !strings.Contains(text, "鏄庝集") {
		t.Errorf("css Text() = (%q, %v)", text, err)
	}

	// SetText in a legacy charset, and the UTF-8 fallback for text the
	// charset cannot hold.
	s := tResp()
	s.Headers.Set("content-type", "text/plain; charset=shift_jis")
	s.SetText("日本語")
	if hex.EncodeToString(s.RawContent) != "93fa967b8cea" || s.Headers.Get("content-type") != "text/plain; charset=shift_jis" {
		t.Errorf("SetText in shift_jis: raw=%x type=%q", s.RawContent, s.Headers.Get("content-type"))
	}
	s.SetText("☃")
	if string(s.RawContent) != "☃" || s.Headers.Get("content-type") != "text/plain; charset=utf-8" {
		t.Errorf("SetText fallback: raw=%q type=%q", s.RawContent, s.Headers.Get("content-type"))
	}

	// Upstream encodes undecodable text strictly even for UTF-8, so text
	// with a raw byte takes the fallback and gets an explicit charset.
	u := tResp()
	u.Headers.Set("content-type", "text/html; charset=utf8")
	u.SetText("\xff")
	if string(u.RawContent) != "\xff" || u.Headers.Get("content-type") != "text/html; charset=utf-8" {
		t.Errorf("SetText with a raw byte: raw=%q type=%q", u.RawContent, u.Headers.Get("content-type"))
	}
}
