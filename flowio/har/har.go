// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package har imports HTTP Archive entries as mitmproxy HTTP flows.
package har

import (
	"bytes"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

// MaxEntries bounds the number of entries materialized from one HAR document.
const MaxEntries = 100_000

const (
	maxDocumentSize = 256 << 20
	maxDepth        = 1000
)

// HeaderError identifies a malformed HAR header, like upstream's OptionsError.
type HeaderError struct{ Err error }

// Error returns the malformed-header reason.
func (e *HeaderError) Error() string { return e.Err.Error() }

// Unwrap returns the underlying header decoding error.
func (e *HeaderError) Unwrap() error { return e.Err }

// FixHeaders converts HAR name/value objects or Slack-style pairs to headers.
// Duplicate fields retain their order and casing. Malformed fields return a
// *HeaderError; extra elements of pairs are ignored, as upstream ignores them.
func FixHeaders(headers jsontext.Value) (httpmsg.Headers, error) {
	var fields []jsontext.Value
	if len(headers) == 0 || headers.Kind() != '[' {
		return nil, &HeaderError{errors.New("HAR headers must be an array")}
	}
	if err := json.Unmarshal(headers, &fields, jsontext.AllowDuplicateNames(true)); err != nil {
		return nil, &HeaderError{err}
	}
	result := make(httpmsg.Headers, 0, len(fields))
	for _, raw := range fields {
		var name, value *string
		switch raw.Kind() {
		case '{':
			var h struct {
				Name  *string `json:"name"`
				Value *string `json:"value"`
			}
			if err := json.Unmarshal(raw, &h, jsontext.AllowDuplicateNames(true)); err != nil {
				return nil, &HeaderError{err}
			}
			name, value = h.Name, h.Value
		case '[':
			var pair []jsontext.Value
			if err := json.Unmarshal(raw, &pair); err != nil {
				return nil, &HeaderError{err}
			}
			if len(pair) < 2 {
				return nil, &HeaderError{errors.New("list index out of range")}
			}
			if err := json.Unmarshal(pair[0], &name); err != nil {
				return nil, &HeaderError{err}
			}
			if err := json.Unmarshal(pair[1], &value); err != nil {
				return nil, &HeaderError{err}
			}
		default:
			return nil, &HeaderError{errors.New("HAR header must be an object or pair")}
		}
		if name == nil || value == nil {
			return nil, &HeaderError{errors.New("HAR header is missing name or value")}
		}
		result.Add(*name, *value)
	}
	return result, nil
}

// ReadEntries reads one complete HAR document, limited to 256 MiB, 1000
// nested objects or arrays, and [MaxEntries] entries. Memory grows with bytes
// actually read, never with a declared length. It requires log.entries to be
// an array and rejects trailing JSON values. Duplicate log and entries keys
// keep the last value, as Python's json.loads does; only the final array is
// materialized and subject to the entry bound. Entry validation occurs in
// RequestToFlow.
func ReadEntries(r io.Reader) ([]jsontext.Value, error) {
	return readEntries(r, maxDocumentSize)
}

func readEntries(r io.Reader, limit int64) ([]jsontext.Value, error) {
	limited := &io.LimitedReader{R: r, N: limit + 1}
	d := jsontext.NewDecoder(limited, jsontext.AllowDuplicateNames(true))
	var b bytes.Buffer
	e := jsontext.NewEncoder(&b, jsontext.AllowDuplicateNames(true))
	for {
		token, err := d.ReadToken()
		if limited.N == 0 {
			return nil, errors.New("HAR document exceeds 256 MiB")
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if d.StackDepth() > maxDepth {
			return nil, errors.New("HAR nesting exceeds 1000 levels")
		}
		if e.OutputOffset() != 0 && e.StackDepth() == 0 {
			return nil, errors.New("HAR document has trailing JSON")
		}
		if err := e.WriteToken(token); err != nil {
			return nil, err
		}
	}
	// Keep repeated log objects as raw values so an earlier object cannot
	// merge fields into the final object selected by Python's last-key rule.
	var document struct {
		Log jsontext.Value `json:"log"`
	}
	if err := json.Unmarshal(b.Bytes(), &document, jsontext.AllowDuplicateNames(true)); err != nil {
		return nil, err
	}
	var log struct {
		Entries jsontext.Value `json:"entries"`
	}
	if len(document.Log) == 0 || document.Log.Kind() == 'n' {
		return nil, errors.New("HAR document is missing log.entries")
	}
	if err := json.Unmarshal(document.Log, &log, jsontext.AllowDuplicateNames(true)); err != nil {
		return nil, err
	}
	if len(log.Entries) == 0 || log.Entries.Kind() == 'n' {
		return nil, errors.New("HAR document is missing log.entries")
	}
	if log.Entries.Kind() != '[' {
		return nil, errors.New("HAR entries must be an array")
	}
	d.Reset(bytes.NewReader(log.Entries), jsontext.AllowDuplicateNames(true))
	if _, err := d.ReadToken(); err != nil {
		return nil, err
	}
	entries := []jsontext.Value{}
	for d.PeekKind() != ']' {
		if len(entries) == MaxEntries {
			return nil, errors.New("HAR exceeds entry-count limit")
		}
		value, err := d.ReadValue()
		if err != nil {
			return nil, err
		}
		entries = append(entries, slices.Clone(value))
	}
	if _, err := d.ReadToken(); err != nil {
		return nil, err
	}
	return entries, nil
}

type entry struct {
	StartedDateTime *string  `json:"startedDateTime"`
	Time            *float64 `json:"time"`
	ServerIPAddress *string  `json:"serverIPAddress"`
	Request         *struct {
		Method      *string        `json:"method"`
		URL         *string        `json:"url"`
		HTTPVersion *string        `json:"httpVersion"`
		Headers     jsontext.Value `json:"headers"`
		PostData    *struct {
			Text *string `json:"text"`
		} `json:"postData"`
	} `json:"request"`
	Response *struct {
		Status      *int           `json:"status"`
		HTTPVersion *string        `json:"httpVersion"`
		Headers     jsontext.Value `json:"headers"`
		Content     *struct {
			Text     string `json:"text"`
			Encoding string `json:"encoding"`
		} `json:"content"`
	} `json:"response"`
}

// RequestToFlow builds a flow from one HAR entry, following request_to_flow.
// It restores timestamps and protocol versions, removes content compression,
// and preserves the HAR headers. Invalid or incomplete entries return errors.
func RequestToFlow(raw jsontext.Value) (*flow.HTTPFlow, error) {
	var item entry
	if err := json.Unmarshal(raw, &item, jsontext.AllowDuplicateNames(true)); err != nil {
		return nil, err
	}
	if item.StartedDateTime == nil || item.Time == nil || item.Request == nil || item.Response == nil {
		return nil, errors.New("HAR entry is missing timing, request or response")
	}
	req, resp := item.Request, item.Response
	if req.Method == nil || req.URL == nil || req.HTTPVersion == nil || resp.Status == nil || resp.HTTPVersion == nil || resp.Content == nil {
		return nil, errors.New("HAR entry is missing request or response fields")
	}
	stamp := *item.StartedDateTime
	if len(stamp) > 10 && stamp[10] == ' ' {
		stamp = stamp[:10] + "T" + stamp[11:]
	}
	started, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		started, err = time.ParseInLocation("2006-01-02T15:04:05", stamp, time.Local)
	}
	if err != nil {
		return nil, err
	}
	// Python datetime retains microseconds, truncating longer fractions.
	start := float64(started.Unix()) + float64(started.Nanosecond()/1000)/1e6
	end := start + *item.Time/1000
	requestHeaders, err := FixHeaders(req.Headers)
	if err != nil {
		return nil, err
	}
	responseHeaders, err := FixHeaders(resp.Headers)
	if err != nil {
		return nil, err
	}
	requestContent := []byte{}
	if req.PostData != nil {
		if req.PostData.Text == nil {
			return nil, errors.New("HAR postData is missing text")
		}
		requestContent = []byte(*req.PostData.Text)
	}
	request, err := httpmsg.MakeRequest(*req.Method, *req.URL, requestContent, requestHeaders)
	if err != nil {
		return nil, err
	}
	var content []byte
	if resp.Content.Encoding == "base64" {
		content, err = base64.StdEncoding.DecodeString(resp.Content.Text)
		if err != nil {
			return nil, err
		}
	} else {
		// SetText uses the same Content-Type inference and UTF-8 fallback as
		// upstream. Work on private headers so only Decode changes the originals.
		textMessage := httpmsg.Message{Headers: responseHeaders.Clone()}
		textMessage.Headers.Del("Content-Encoding")
		if resp.Content.Encoding != "" {
			textMessage.Headers.Set("Content-Type", "text/plain; charset="+resp.Content.Encoding)
		}
		textMessage.SetText(resp.Content.Text)
		content = textMessage.RawContent
	}
	response := &httpmsg.Response{HTTPVersion: "HTTP/1.1", Headers: responseHeaders, RawContent: content, TimestampStart: start, TimestampEnd: &end, StatusCode: *resp.Status, Reason: httpmsg.StatusText(*resp.Status)}
	if encoding, ok := response.Headers.Lookup("Content-Encoding"); ok {
		if err := response.Encode(encoding); err != nil {
			return nil, err
		}
	}
	request.TimestampStart, request.TimestampEnd = start, &end
	request.HTTPVersion = httpVersion(*req.HTTPVersion)
	response.HTTPVersion = httpVersion(*resp.HTTPVersion)
	if err := request.Decode(true); err != nil {
		return nil, err
	}
	if err := response.Decode(true); err != nil {
		return nil, err
	}
	client := connection.NewClient(connection.Address{Host: "127.0.0.1"}, connection.Address{Host: "127.0.0.1"}, start)
	client.TimestampEnd = &end
	var address *connection.Address
	if item.ServerIPAddress != nil && *item.ServerIPAddress != "" {
		port := 443
		if strings.HasPrefix(*req.URL, "http://") {
			port = 80
		}
		address = &connection.Address{Host: *item.ServerIPAddress, Port: port}
	}
	f := flow.NewHTTPFlow(client, connection.NewServer(address), false)
	f.Request, f.Response = request, response
	return f, nil
}

func httpVersion(s string) string {
	switch s {
	case "http/2.0", "HTTP/2":
		return "HTTP/2"
	case "HTTP/3":
		return "HTTP/3"
	default:
		return "HTTP/1.1"
	}
}
