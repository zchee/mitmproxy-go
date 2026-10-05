// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http1

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

const asciiWhitespace = " \t\n\r\v\f"

var statusInteger = regexp.MustCompile(`^[+-]?[0-9]+(?:_[0-9]+)*$`)

// ReadRequestHead reads a complete request head, retaining its raw wire bytes.
// It skips leading empty lines under MaxHeadBytes and accepts LF or CRLF as
// upstream does. A clean EOF returns io.EOF; a partial head returns
// io.ErrUnexpectedEOF. Syntax errors wrap ErrInvalidHead; resource limits wrap
// their distinct ErrHeadTooLarge, ErrLineTooLong or ErrTooManyHeaders sentinels.
// It does not read a body, validate framing headers, or count normalizations.
func ReadRequestHead(r *bufio.Reader) (RequestHead, error) {
	raw, lines, start, err := readHead(r, true)
	if err != nil {
		return RequestHead{}, err
	}
	req, target, err := readRequestLine(lines[0])
	if err != nil {
		return RequestHead{}, err
	}
	req.Headers, err = ReadHeaders(lines[1:])
	if err != nil {
		return RequestHead{}, err
	}
	req.TimestampStart = float64(time.Now().UnixNano()) / 1e9
	words := []byte(req.Method + " " + string(target) + " " + req.HTTPVersion)
	return RequestHead{Request: req, Raw: raw, Consumed: len(raw), Target: target, wire: snapshotHead(raw, start, req.Headers, requestLine(req), words)}, nil
}

// ReadResponseHead reads a complete status line and header block. EOF, malformed
// input and limits follow ReadRequestHead, but leading empty lines are rejected.
// Status integers may have Python's sign and digit separators but must fit Go's
// int. The response body and pipelined bytes remain in r.
func ReadResponseHead(r *bufio.Reader) (ResponseHead, error) {
	raw, lines, start, err := readHead(r, false)
	if err != nil {
		return ResponseHead{}, err
	}
	resp, err := readResponseLine(lines[0])
	if err != nil {
		return ResponseHead{}, err
	}
	resp.Headers, err = ReadHeaders(lines[1:])
	if err != nil {
		return ResponseHead{}, err
	}
	resp.TimestampStart = float64(time.Now().UnixNano()) / 1e9
	canonical := responseLine(resp)
	words := bytes.TrimSuffix(canonical, []byte("\r\n"))
	return ResponseHead{Response: resp, Raw: raw, Consumed: len(raw), wire: snapshotHead(raw, start, resp.Headers, canonical, words)}, nil
}

func readHead(r *bufio.Reader, skipEmpty bool) ([]byte, [][]byte, int, error) {
	var raw []byte
	var lines [][]byte
	start, count := 0, 0
	for {
		line, err := readLine(r, MaxLineBytes, MaxHeadBytes-len(raw), ErrLineTooLong)
		if err != nil {
			if errors.Is(err, io.EOF) && len(raw) != 0 {
				err = io.ErrUnexpectedEOF
			}
			return nil, nil, 0, err
		}
		raw = append(raw, line...)
		clean := bytes.TrimSuffix(bytes.TrimSuffix(line, []byte{'\n'}), []byte{'\r'})
		if len(lines) == 0 {
			if len(clean) == 0 && skipEmpty {
				start = len(raw)
				continue
			}
			lines = append(lines, clean)
			continue
		}
		if len(clean) == 0 {
			return raw, lines, start, nil
		}
		if clean[0] != ' ' && clean[0] != '\t' {
			count++
			if count > MaxHeaderFields {
				return nil, nil, 0, fmt.Errorf("%w: maximum %d", ErrTooManyHeaders, MaxHeaderFields)
			}
		}
		lines = append(lines, clean)
	}
}

// readLine retains at most the smaller remaining budget, independently of the
// caller's bufio buffer size. A delimiter is included in the limit.
func readLine(r *bufio.Reader, limit, budget int, lineError error) ([]byte, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(part) > min(limit, budget)-len(line) {
			if budget < limit {
				return nil, fmt.Errorf("%w: maximum %d", ErrHeadTooLarge, MaxHeadBytes)
			}
			return nil, fmt.Errorf("%w: maximum %d", lineError, limit)
		}
		line = append(line, part...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(line) != 0 {
			return nil, io.ErrUnexpectedEOF
		}
		return line, err
	}
}

// ReadHeaders parses physical header lines with or without their line endings.
// It preserves name case and order, strips ASCII whitespace from values, and
// joins continuation lines with CRLF plus one space. Missing colons, empty
// names and a continuation without a preceding field wrap ErrInvalidHead.
// Size, line and field limits match ReadRequestHead. The result owns its bytes.
func ReadHeaders(lines [][]byte) (httpmsg.Headers, error) {
	headers := make(httpmsg.Headers, 0, min(len(lines), MaxHeaderFields))
	total := 0
	for _, line := range lines {
		if len(line) > MaxLineBytes {
			return nil, fmt.Errorf("%w: maximum %d", ErrLineTooLong, MaxLineBytes)
		}
		if len(line) > MaxHeadBytes-total {
			return nil, fmt.Errorf("%w: maximum %d", ErrHeadTooLarge, MaxHeadBytes)
		}
		total += len(line)
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if len(headers) == 0 {
				return nil, fmt.Errorf("%w: Invalid headers", ErrInvalidHead)
			}
			last := &headers[len(headers)-1]
			last.Value = append(last.Value, '\r', '\n', ' ')
			last.Value = append(last.Value, bytes.Trim(line, asciiWhitespace)...)
			continue
		}
		name, value, ok := bytes.Cut(line, []byte{':'})
		if !ok || len(name) == 0 {
			return nil, fmt.Errorf("%w: Invalid header line: %s", ErrInvalidHead, pyrepr.Bytes(line))
		}
		if len(headers) == MaxHeaderFields {
			return nil, fmt.Errorf("%w: maximum %d", ErrTooManyHeaders, MaxHeaderFields)
		}
		value = bytes.Trim(value, asciiWhitespace)
		owned := make([]byte, len(value))
		copy(owned, value)
		headers = append(headers, httpmsg.Field{Name: bytes.Clone(name), Value: owned})
	}
	return headers, nil
}

func validVersion(v string) bool {
	return len(v) == 8 && v[:5] == "HTTP/" && v[5] >= '0' && v[5] <= '9' && v[6] == '.' && v[7] >= '0' && v[7] <= '9'
}

func readRequestLine(line []byte) (*httpmsg.Request, []byte, error) {
	bad := func() (*httpmsg.Request, []byte, error) {
		return nil, nil, fmt.Errorf("%w: Bad HTTP request line: %s", ErrInvalidHead, pyrepr.Bytes(line))
	}
	parts := bytes.FieldsFunc(line, func(r rune) bool { return strings.ContainsRune(asciiWhitespace, r) })
	if len(parts) != 3 || !validVersion(string(parts[2])) {
		return bad()
	}
	req := &httpmsg.Request{Method: string(parts[0]), HTTPVersion: string(parts[2])}
	target := string(parts[1])
	switch {
	case target == "*" || strings.HasPrefix(target, "/"):
		req.Path = target
	case req.Method == "CONNECT":
		req.Authority = target
		host, port, err := httpmsg.ParseAuthorityBytes(parts[1], true)
		if err != nil || port <= 0 {
			return bad()
		}
		req.Host, req.Port = host, port
	default:
		scheme, rest, ok := strings.Cut(target, "://")
		if !ok {
			return bad()
		}
		authority, path, _ := strings.Cut(rest, "/")
		req.Scheme = strings.ToLower(scheme)
		req.Authority, req.Path = authority, "/"+path
		host, port, err := httpmsg.ParseAuthorityBytes([]byte(authority), true)
		if err != nil {
			return bad()
		}
		if port <= 0 {
			switch req.Scheme {
			case "http":
				port = 80
			case "https":
				port = 443
			default:
				return bad()
			}
		}
		if _, _, _, _, err = httpmsg.ParseURLBytes(parts[1]); err != nil {
			return bad()
		}
		req.Host, req.Port = host, port
	}
	return req, bytes.Clone(parts[1]), nil
}

func readResponseLine(line []byte) (*httpmsg.Response, error) {
	bad := func() (*httpmsg.Response, error) {
		return nil, fmt.Errorf("%w: Bad HTTP response line: %s", ErrInvalidHead, pyrepr.Bytes(line))
	}
	remaining := strings.TrimLeft(string(line), asciiWhitespace)
	var parts [2]string
	for i := range parts {
		at := strings.IndexAny(remaining, asciiWhitespace)
		if at < 0 {
			parts[i], remaining = remaining, ""
		} else {
			parts[i], remaining = remaining[:at], strings.TrimLeft(remaining[at:], asciiWhitespace)
		}
	}
	if !validVersion(parts[0]) || !statusInteger.MatchString(parts[1]) {
		return bad()
	}
	digits := strings.ReplaceAll(parts[1], "_", "")
	if len(strings.TrimLeft(digits, "+-")) > 4300 {
		return bad()
	}
	code, err := strconv.Atoi(digits)
	if err != nil {
		return bad()
	}
	return &httpmsg.Response{HTTPVersion: parts[0], StatusCode: code, Reason: remaining}, nil
}

// snapshotHead records which wire bytes assembly may reuse. Bytes are reused
// only where every recipient reads them as the proxy did: a start line whose
// SP/HTAB-separated words equal the parsed words, and a field whose value is
// the parsed value apart from surrounding SP/HTAB. Other whitespace the parser
// accepted, such as VT, FF or a bare CR, is a spelling that stricter parsers
// read differently, so such lines are re-emitted from the parsed values that
// framed the message, as upstream always does.
func snapshotHead(raw []byte, start int, headers httpmsg.Headers, canonical, words []byte) wireHead {
	lineEnd := bytes.IndexByte(raw[start:], '\n') + start + 1
	wire := wireHead{line: raw[:lineEnd], canonicalLine: canonical}
	if !sameWords(trimLineEnd(raw[start:lineEnd]), words) {
		wire.canonicalLine = nil
	}
	for rest := raw[lineEnd:]; len(rest) > 0; {
		n := bytes.IndexByte(rest, '\n') + 1
		line := rest[:n]
		rest = rest[n:]
		if bytes.Equal(line, []byte{'\n'}) || bytes.Equal(line, []byte{'\r', '\n'}) {
			wire.end = line
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			last := &wire.fields[len(wire.fields)-1]
			if last.normalized == nil {
				last.normalized = bytes.Clone(last.raw)
			}
			joined := append([]byte{' '}, bytes.Trim(line, asciiWhitespace)...)
			joined = append(joined, '\r', '\n')
			if !bytes.Equal(line, joined) {
				last.rewrites++
			}
			last.normalized = append(last.normalized, joined...)
			last.raw = raw[len(raw)-len(rest)-len(line)-len(last.raw) : len(raw)-len(rest)]
		} else {
			field := headers[len(wire.fields)]
			wire.fields = append(wire.fields, wireField{field: httpmsg.Field{Name: bytes.Clone(field.Name), Value: bytes.Clone(field.Value)}, raw: line})
		}
	}
	// Folded fields are already re-emitted. The parsed value of a field is
	// complete only after its continuation lines, hence the separate pass.
	for i := range wire.fields {
		field := &wire.fields[i]
		if field.normalized != nil {
			continue
		}
		_, value, _ := bytes.Cut(trimLineEnd(field.raw), []byte{':'})
		if !bytes.Equal(bytes.Trim(value, " \t"), field.field.Value) {
			field.normalized = appendField(nil, field.field)
			field.rewrites = 1
		}
	}
	return wire
}

// trimLineEnd removes the LF and at most one CR before it, as readHead does.
func trimLineEnd(line []byte) []byte {
	return bytes.TrimSuffix(bytes.TrimSuffix(line, []byte{'\n'}), []byte{'\r'})
}

// sameWords reports whether a and b hold the same words separated by runs of
// SP or HTAB, the separators every HTTP/1 parser accepts.
func sameWords(a, b []byte) bool {
	isBlank := func(r rune) bool { return r == ' ' || r == '\t' }
	return slices.EqualFunc(slices.Collect(bytes.FieldsFuncSeq(a, isBlank)), slices.Collect(bytes.FieldsFuncSeq(b, isBlank)), bytes.Equal)
}
