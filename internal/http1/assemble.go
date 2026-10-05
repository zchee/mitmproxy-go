// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http1

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

// AssembleRequestHead emits only a request line and headers, never its body.
// With an original head, unchanged start lines and header fields retain their
// exact wire bytes except that obs-fold is joined as in upstream, and a line
// spelled with whitespace other than SP and HTAB, which the parser accepted,
// is re-emitted from its parsed values. Without one,
// fields use upstream's canonical CRLF and colon-space spelling. The caller
// must set addonChanged if any addon changed this message; that excludes the
// entire emission from fidelity accounting. Calls themselves are emissions:
// do not pass a counter when assembling merely to inspect the result.
func AssembleRequestHead(request *httpmsg.Request, original *RequestHead, addonChanged bool, fidelity *FidelityCounter) []byte {
	var wire *wireHead
	if original != nil {
		wire = &original.wire
	}
	return assembleHead(requestLine(request), request.Headers, wire, addonChanged, fidelity)
}

// AssembleResponseHead is AssembleRequestHead for a status line and headers.
// An empty reason phrase still emits the space after the status code, as
// upstream does, unless an unchanged original status line is being preserved.
func AssembleResponseHead(response *httpmsg.Response, original *ResponseHead, addonChanged bool, fidelity *FidelityCounter) []byte {
	var wire *wireHead
	if original != nil {
		wire = &original.wire
	}
	return assembleHead(responseLine(response), response.Headers, wire, addonChanged, fidelity)
}

func requestLine(r *httpmsg.Request) []byte {
	target := r.Path
	if strings.ToUpper(r.Method) == "CONNECT" {
		target = r.Authority
	} else if r.Authority != "" {
		target = r.Scheme + "://" + r.Authority + r.Path
	}
	return []byte(r.Method + " " + target + " " + r.HTTPVersion + "\r\n")
}

func responseLine(r *httpmsg.Response) []byte {
	return []byte(r.HTTPVersion + " " + strconv.Itoa(r.StatusCode) + " " + r.Reason + "\r\n")
}

func appendField(out []byte, field httpmsg.Field) []byte {
	out = append(out, field.Name...)
	out = append(out, ':', ' ')
	out = append(out, field.Value...)
	return append(out, '\r', '\n')
}

// Separate framing families so one rewrite is not counted again as a generic
// header-block normalization. Multiple folded lines each count once.
func fidelityRegion(name []byte) int {
	switch strings.ToLower(string(name)) {
	case "content-length":
		return 1
	case "transfer-encoding":
		return 2
	default:
		return 0
	}
}

func assembleHead(line []byte, headers httpmsg.Headers, wire *wireHead, addonChanged bool, counter *FidelityCounter) []byte {
	if wire == nil {
		for _, field := range headers {
			line = appendField(line, field)
		}
		return append(line, '\r', '\n')
	}
	var count uint64
	out := line
	if bytes.Equal(line, wire.canonicalLine) {
		out = bytes.Clone(wire.line)
	} else if !bytes.Equal(line, wire.line) {
		count++
	}
	var before, after [3][]byte
	originals := make(map[[2]string][]wireField, len(wire.fields))
	for _, field := range wire.fields {
		key := [2]string{string(field.field.Name), string(field.field.Value)}
		originals[key] = append(originals[key], field)
		region := fidelityRegion(field.field.Name)
		if field.normalized != nil {
			before[region] = append(before[region], field.normalized...)
		} else {
			before[region] = append(before[region], field.raw...)
		}
	}
	for _, field := range headers {
		var emitted []byte
		key := [2]string{string(field.Name), string(field.Value)}
		if matches := originals[key]; len(matches) != 0 {
			old := matches[0]
			originals[key] = matches[1:]
			if old.normalized != nil {
				emitted = appendField(nil, field)
				count += old.rewrites
			} else {
				emitted = old.raw
			}
		} else {
			emitted = appendField(nil, field)
		}
		out = append(out, emitted...)
		region := fidelityRegion(field.Name)
		after[region] = append(after[region], emitted...)
	}
	out = append(out, wire.end...)
	for i := range before {
		if !bytes.Equal(before[i], after[i]) {
			count++
		}
	}
	if !addonChanged {
		counter.Add(count)
	}
	return out
}
