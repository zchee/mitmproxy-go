// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http1

import (
	"strings"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

// ExpectedBodySize selects framing using mitmproxy's precedence. Pass nil for
// response to select the request body. HEAD responses, informational responses,
// 204, 304 and successful CONNECT responses have no body regardless of headers.
// Chunked overrides Content-Length; non-chunked response transfer encodings end
// at EOF. Invalid nonempty framing values return httpmsg's validation errors.
// Empty values act as absent. Header validation is a separate caller policy.
func ExpectedBodySize(request *httpmsg.Request, response *httpmsg.Response) (BodySize, error) {
	headers := request.Headers
	if response != nil {
		headers = response.Headers
		status := response.StatusCode
		method := strings.ToUpper(request.Method)
		if method == "HEAD" || status >= 100 && status <= 199 || status == 204 || status == 304 || method == "CONNECT" && status >= 200 && status <= 299 {
			return BodySize{Mode: BodyNone}, nil
		}
	}
	if value := headers.Get("transfer-encoding"); value != "" {
		encoding, err := httpmsg.ParseTransferEncoding(value)
		if err != nil {
			return BodySize{}, err
		}
		if encoding.Chunked() {
			return BodySize{Mode: BodyChunked}, nil
		}
		if response != nil || encoding != httpmsg.TEIdentity && !headers.Has("content-length") {
			return BodySize{Mode: BodyUntilClose}, nil
		}
	}
	if value := headers.Get("content-length"); value != "" {
		length, err := httpmsg.ParseContentLength(value)
		if err != nil {
			return BodySize{}, err
		}
		return BodySize{Mode: BodyLength, Length: length}, nil
	}
	if response != nil {
		return BodySize{Mode: BodyUntilClose}, nil
	}
	return BodySize{Mode: BodyNone}, nil
}

// ConnectionClose reports whether the peer requested connection closure.
// Tokens are case-sensitive as in upstream: close wins over keep-alive, and an
// unrecognized or absent value closes versions other than HTTP/1.1 and HTTP/2.0.
func ConnectionClose(version string, headers httpmsg.Headers) bool {
	keepAlive := false
	for token := range strings.SplitSeq(headers.Get("connection"), ",") {
		switch strings.TrimSpace(token) {
		case "close":
			return true
		case "keep-alive":
			keepAlive = true
		}
	}
	return !keepAlive && version != "HTTP/1.1" && version != "HTTP/2.0"
}
