// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The patterns below are anchored at both ends. Python's "$" also matches
// before a trailing newline, so upstream accepts "42\n"; these do not,
// which is the stricter choice for a guard against request smuggling.
var (
	// validHeaderName matches an RFC 7230 token.
	validHeaderName = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9a-zA-Z]+$")
	// validContentLength matches a decimal without sign or leading zeros.
	validContentLength = regexp.MustCompile(`^(?:0|[1-9][0-9]*)$`)
	// transferEncodingSep matches a comma with optional spaces and tabs.
	transferEncodingSep = regexp.MustCompile(`[\t ]*,[\t ]*`)
)

// TransferEncoding is a Transfer-Encoding value upstream accepts, in
// normalised form.
type TransferEncoding string

// Transfer encodings upstream accepts. RFC 9112 allows more, but upstream
// only accepts this known subset.
const (
	TEChunked         TransferEncoding = "chunked"
	TECompressChunked TransferEncoding = "compress,chunked"
	TEDeflateChunked  TransferEncoding = "deflate,chunked"
	TEGzipChunked     TransferEncoding = "gzip,chunked"
	TECompress        TransferEncoding = "compress"
	TEDeflate         TransferEncoding = "deflate"
	TEGzip            TransferEncoding = "gzip"
	TEIdentity        TransferEncoding = "identity"
)

// Chunked reports whether chunked is the final transfer coding.
func (t TransferEncoding) Chunked() bool {
	return t == TEChunked || strings.HasSuffix(string(t), ",chunked")
}

// ParseContentLength parses a Content-Length value: a decimal number
// without sign, spaces or leading zeros.
func ParseContentLength(value string) (int64, error) {
	if !validContentLength.MatchString(value) {
		return 0, fmt.Errorf("invalid content-length header: %q", value)
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid content-length header: %q", value)
	}
	return n, nil
}

// ParseTransferEncoding parses a Transfer-Encoding value into one of the
// accepted encodings. Case and whitespace around commas are normalised;
// any other value is an error.
func ParseTransferEncoding(value string) (TransferEncoding, error) {
	// Non-ASCII input is rejected before lower-casing, which could map a
	// character such as U+212A KELVIN SIGN onto an ASCII letter.
	if !isASCII(value) {
		return "", fmt.Errorf("invalid transfer-encoding header: %q", value)
	}
	te := TransferEncoding(transferEncodingSep.ReplaceAllString(strings.ToLower(value), ","))
	switch te {
	case TEChunked, TECompressChunked, TEDeflateChunked, TEGzipChunked, TECompress, TEDeflate, TEGzip, TEIdentity:
		return te, nil
	}
	return "", fmt.Errorf("unknown transfer-encoding header: %q", value)
}

// ValidateHeaders rejects ambiguous framing, as
// upstream's validate_headers does to prevent request smuggling: header
// names that are not tokens, both Transfer-Encoding and Content-Length,
// repeated framing headers, Transfer-Encoding outside HTTP/1.1, and
// malformed or unknown values.
// A request must also end its transfer codings with chunked.
func (r *Request) ValidateHeaders() error {
	return validateHeaders(&r.Message, true, 0)
}

// ValidateHeaders rejects ambiguous framing, as
// upstream's validate_headers does to prevent request smuggling: header
// names that are not tokens, both Transfer-Encoding and Content-Length,
// repeated framing headers, Transfer-Encoding outside HTTP/1.1, and
// malformed or unknown values.
// A 1xx or 204 response must also not carry Transfer-Encoding.
func (r *Response) ValidateHeaders() error {
	return validateHeaders(&r.Message, false, r.StatusCode)
}

// validateHeaders implements both ValidateHeaders methods; status is the
// response status code and is ignored for requests.
func validateHeaders(m *Message, isRequest bool, status int) error {
	var te, cl []string
	for _, f := range m.Headers {
		if !validHeaderName.Match(f.Name) {
			return fmt.Errorf("invalid header name: %q", f.Name)
		}
		switch strings.ToLower(string(f.Name)) {
		case "transfer-encoding":
			te = append(te, string(f.Value))
		case "content-length":
			cl = append(cl, string(f.Value))
		}
	}
	switch {
	case len(te) > 0 && len(cl) > 0:
		return fmt.Errorf("message with both transfer-encoding and content-length headers")
	case len(te) > 0:
		if len(te) > 1 {
			return fmt.Errorf("multiple transfer-encoding headers: %q", te)
		}
		if !m.IsHTTP11() {
			return fmt.Errorf("unexpected HTTP transfer-encoding %q for %s", te[0], m.HTTPVersion)
		}
		if !isRequest && (100 <= status && status <= 199 || status == 204) {
			return fmt.Errorf("unexpected HTTP transfer-encoding %q for response with status code %d", te[0], status)
		}
		parsed, err := ParseTransferEncoding(te[0])
		if err != nil {
			return err
		}
		if isRequest && !parsed.Chunked() {
			return fmt.Errorf("unexpected HTTP transfer-encoding %q for request", parsed)
		}
	case len(cl) > 0:
		// Upstream is stricter than RFC 9112 here and rejects repeated
		// headers even when the values agree.
		if len(cl) > 1 {
			return fmt.Errorf("multiple content-length headers: %q", cl)
		}
		if _, err := ParseContentLength(cl[0]); err != nil {
			return err
		}
	}
	return nil
}
