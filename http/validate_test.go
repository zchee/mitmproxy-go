// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http

import (
	"strings"
	"testing"
)

func TestParseContentLength(t *testing.T) {
	t.Parallel()

	// Ports test/mitmproxy/net/http/test_validate.py.
	tests := map[string]struct {
		in      string
		want    int64
		wantErr bool
	}{
		"success: zero":           {in: "0", want: 0},
		"success: number":         {in: "42", want: 42},
		"error: nan":              {in: "NaN", wantErr: true},
		"error: empty":            {in: "", wantErr: true},
		"error: space":            {in: " ", wantErr: true},
		"error: negative":         {in: "-1", wantErr: true},
		"error: plus sign":        {in: "+1", wantErr: true},
		"error: hex":              {in: "0x42", wantErr: true},
		"error: leading zero":     {in: "010", wantErr: true},
		"error: word":             {in: "foo", wantErr: true},
		"error: list":             {in: "1, 1", wantErr: true},
		"error: trailing newline": {in: "42\n", wantErr: true},
		"error: overflows int64":  {in: "99999999999999999999", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseContentLength(tt.in)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "invalid content-length") {
					t.Errorf("ParseContentLength(%q) error = %v, want invalid content-length", tt.in, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("ParseContentLength(%q) = (%d, %v), want %d", tt.in, got, err, tt.want)
			}
		})
	}
}

func TestParseTransferEncoding(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in      string
		want    TransferEncoding
		wantErr bool
	}{
		"success: chunked":            {in: "chunked", want: TEChunked},
		"success: gzip then chunked":  {in: "gzip,chunked", want: TEGzipChunked},
		"success: spaces normalised":  {in: "gzip, chunked", want: TEGzipChunked},
		"success: tabs and case":      {in: "GZIP\t,\tChunked", want: TEGzipChunked},
		"error: unknown":              {in: "unknown", wantErr: true},
		"error: chunked twice":        {in: "chunked,chunked", wantErr: true},
		"error: chunked not final":    {in: "chunked,gzip", wantErr: true},
		"error: empty":                {in: "", wantErr: true},
		"error: kelvin sign":          {in: "chunKed", wantErr: true},
		"error: space inside a token": {in: "chun ked", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseTransferEncoding(tt.in)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "transfer-encoding") {
					t.Errorf("ParseTransferEncoding(%q) error = %v", tt.in, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("ParseTransferEncoding(%q) = (%q, %v), want %q", tt.in, got, err, tt.want)
			}
		})
	}
}

func TestValidateHeaders(t *testing.T) {
	t.Parallel()

	resp := func(h Headers) *Response {
		r := tResp()
		r.Headers = h
		return r
	}
	req := func(h Headers) *Request {
		r := tReq()
		r.Method = "POST"
		r.Headers = h
		return r
	}
	tests := map[string]struct {
		validate func() error
		wantErr  string
	}{
		"success: response with content-length": {validate: resp(hdrs("content-length", "42")).ValidateHeaders},
		"success: chunked request":              {validate: req(hdrs("transfer-encoding", "chunked")).ValidateHeaders},
		"success: gzip response":                {validate: resp(hdrs("transfer-encoding", "gzip")).ValidateHeaders},
		"success: no framing headers":           {validate: resp(Headers{}).ValidateHeaders},
		"error: both framing headers": {
			validate: resp(hdrs("transfer-encoding", "chunked", "content-length", "42")).ValidateHeaders,
			wantErr:  "both transfer-encoding and content-length",
		},
		"error: whitespace in name": {
			validate: resp(hdrs("content-length ", "42")).ValidateHeaders,
			wantErr:  "invalid header name",
		},
		"error: whitespace in value": {
			validate: resp(hdrs("content-length", "42 ")).ValidateHeaders,
			wantErr:  "invalid content-length",
		},
		"error: negative content-length": {
			validate: resp(hdrs("content-length", "-42")).ValidateHeaders,
			wantErr:  "invalid content-length",
		},
		"error: unknown transfer-encoding": {
			validate: resp(hdrs("transfer-encoding", "unknown")).ValidateHeaders,
			wantErr:  "unknown transfer-encoding",
		},
		"error: repeated content-length": {
			validate: resp(hdrs("content-length", "42", "content-length", "43")).ValidateHeaders,
			wantErr:  "multiple content-length",
		},
		"error: repeated transfer-encoding": {
			validate: resp(hdrs("transfer-encoding", "", "transfer-encoding", "chunked")).ValidateHeaders,
			wantErr:  "multiple transfer-encoding",
		},
		"error: transfer-encoding on HTTP/1.0": {
			validate: func() error {
				r := resp(hdrs("transfer-encoding", "chunked"))
				r.HTTPVersion = "HTTP/1.0"
				return r.ValidateHeaders()
			},
			wantErr: "for HTTP/1.0",
		},
		"error: transfer-encoding on 204": {
			validate: func() error {
				r := resp(hdrs("transfer-encoding", "chunked"))
				r.StatusCode = 204
				return r.ValidateHeaders()
			},
			wantErr: "status code 204",
		},
		"error: transfer-encoding on 1xx": {
			validate: func() error {
				r := resp(hdrs("transfer-encoding", "chunked"))
				r.StatusCode = 101
				return r.ValidateHeaders()
			},
			wantErr: "status code 101",
		},
		"error: identity request": {
			validate: req(hdrs("transfer-encoding", "identity")).ValidateHeaders,
			wantErr:  `"identity" for request`,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := tt.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("ValidateHeaders() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ValidateHeaders() = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
	if !TEGzipChunked.Chunked() || TEGzip.Chunked() || !TEChunked.Chunked() {
		t.Error("Chunked() misclassified an encoding")
	}
}
