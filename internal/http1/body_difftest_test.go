// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package http1

import (
	"bufio"
	"bytes"
	json "encoding/json/v2"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestBodyCornersAgainstPython(t *testing.T) {
	type input struct {
		Request  []byte `json:"request"`
		Response []byte `json:"response"`
		Body     []byte `json:"body"`
	}
	tests := map[string]input{
		"conflicting duplicate length": {Request: []byte("POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n")},
		"chunk extensions":             {Request: []byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), Body: []byte("3;foo=bar\r\nabc\r\n0\r\nX: y\r\n\r\nNEXT")},
		"HTTP 1.0 keepalive":           {Request: []byte("POST / HTTP/1.0\r\nConnection: keep-alive\r\nContent-Length: 3\r\n\r\n"), Body: []byte("abcNEXT")},
		"204 extra body":               {Request: []byte("GET / HTTP/1.1\r\n\r\n"), Response: []byte("HTTP/1.1 204 No Content\r\nContent-Length: 4\r\n\r\n"), Body: []byte("bodyNEXT")},
		"folded Set-Cookie":            {Request: []byte("GET / HTTP/1.1\r\nSet-Cookie: a=b;\r\n\tSecure\r\nSet-Cookie: c=d\r\n\r\n"), Body: []byte("NEXT")},
		"until close":                  {Request: []byte("GET / HTTP/1.0\r\n\r\n"), Response: []byte("HTTP/1.0 200 OK\r\n\r\n"), Body: []byte("abc")},
		"folded trailer":               {Request: []byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), Body: []byte("0\r\nSet-Cookie: a=b; \r\n\t Secure\r\n\r\nNEXT")},
		"trailer framing":              {Request: []byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), Body: []byte("0\r\nContent-Length: 01, 01\r\nContent-Length: 01\r\nTransfer-Encoding: CHUNKED\r\n\r\n")},
		"invalid trailer":              {Request: []byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), Body: []byte("0\r\nX : y\r\n\r\n")},
		"empty trailer length member":  {Request: []byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), Body: []byte("0\r\nContent-Length: ,1\r\n\r\n")},
	}
	type result struct {
		OK        bool        `json:"ok"`
		Mode      BodyMode    `json:"mode,omitzero"`
		Close     bool        `json:"close,omitzero"`
		Body      []byte      `json:"body,omitzero"`
		Remaining []byte      `json:"remaining,omitzero"`
		Headers   [][2][]byte `json:"headers,omitzero"`
		Trailers  [][2][]byte `json:"trailers,omitzero"`
	}
	data, err := json.Marshal(tests)
	if err != nil {
		t.Fatal(err)
	}
	const script = `import base64, json, sys
import h11
from h11._readers import ContentLengthReader, ChunkedReader, Http10Reader
from h11._receivebuffer import ReceiveBuffer
from mitmproxy.net.http.http1 import read

def dec(value):
    return base64.b64decode(value)
def enc(value):
    return base64.b64encode(value).decode()
def lines(value):
    return [line.removesuffix(b"\r") for line in dec(value).split(b"\n")[:-2]]
def fields(value):
    return [[enc(k), enc(v)] for k,v in value]

out = {}
for name, row in json.load(sys.stdin).items():
    try:
        req = read.read_request_head(lines(row["request"]))
        resp = read.read_response_head(lines(row["response"])) if row["response"] else None
        size = read.expected_http_body_size(req, resp)
        mode = 2 if size is None else 3 if size == -1 else 0 if size == 0 else 1
        body, trailers = bytearray(), []
        buf = ReceiveBuffer()
        buf += dec(row["body"])
        if mode:
            reader = ChunkedReader() if mode == 2 else Http10Reader() if mode == 3 else ContentLengthReader(size)
            while True:
                event = reader(buf)
                if event is None:
                    event = reader.read_eof()
                if isinstance(event, h11.EndOfMessage):
                    trailers = event.headers.raw_items()
                    break
                body += event.data
        msg = resp or req
        result = dict(ok=True, mode=mode, close=read.connection_close(msg.http_version, msg.headers))
        if body: result["body"] = enc(body)
        if buf._data: result["remaining"] = enc(buf._data)
        if req.headers.fields: result["headers"] = fields(req.headers.fields)
        if trailers: result["trailers"] = fields(trailers)
        out[name] = result
    except (ValueError, h11.ProtocolError):
        out[name] = dict(ok=False)
json.dump(out, sys.stdout)
`
	var want map[string]result
	if err := json.Unmarshal(difftest.Python(t, script, data), &want); err != nil {
		t.Fatal(err)
	}
	for name, row := range tests {
		t.Run(name, func(t *testing.T) {
			got := result{}
			req, err := ReadRequestHead(bufio.NewReader(bytes.NewReader(row.Request)))
			if err != nil {
				t.Fatal(err)
			}
			var resp *httpmsg.Response
			if len(row.Response) != 0 {
				head, err := ReadResponseHead(bufio.NewReader(bytes.NewReader(row.Response)))
				if err != nil {
					t.Fatal(err)
				}
				resp = head.Response
			}
			size, err := ExpectedBodySize(req.Request, resp)
			if err == nil {
				reader := bufio.NewReader(bytes.NewReader(row.Body))
				body, err := NewBodyReader(reader, size)
				if err != nil {
					t.Fatal(err)
				}
				content, err := io.ReadAll(body)
				if err == nil {
					got.OK, got.Mode = true, size.Mode
					if len(content) != 0 {
						got.Body = content
					}
					left, err := io.ReadAll(reader)
					if err != nil {
						t.Fatal(err)
					}
					if len(left) != 0 {
						got.Remaining = left
					}
					msg := &req.Request.Message
					if resp != nil {
						msg = &resp.Message
					}
					got.Close = ConnectionClose(msg.HTTPVersion, msg.Headers)
					for _, field := range req.Request.Headers {
						got.Headers = append(got.Headers, [2][]byte{field.Name, field.Value})
					}
					for _, field := range body.Trailers() {
						got.Trailers = append(got.Trailers, [2][]byte{field.Name, field.Value})
					}
				}
			}
			if diff := gocmp.Diff(want[name], got); diff != "" {
				t.Fatalf("(-Python +Go):\n%s", diff)
			}
		})
	}
}
