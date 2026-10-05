// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"errors"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/strutil"
)

// Multipart displays a multipart/form-data body as an ordered YAML mapping.
type Multipart struct{}

// Name returns the registered view name.
func (Multipart) Name() string { return "Multipart Form" }

// SyntaxHighlight returns the view's highlighting language.
func (Multipart) SyntaxHighlight() string { return "yaml" }

// RenderPriority prefers nonempty multipart/form-data bodies.
func (Multipart) RenderPriority(data []byte, metadata Metadata) float64 {
	if len(data) != 0 && metadata.ContentType == "multipart/form-data" {
		return 1
	}
	return 0
}

// Prettify decodes the parts named by the message's Content-Type boundary,
// escapes their bytes, and merges repeated names. It returns an error when
// metadata has no HTTP message, that message has no Content-Type header, or
// a part has no end of headers.
func (Multipart) Prettify(data []byte, metadata Metadata) (string, error) {
	if metadata.HTTPMessage == nil {
		return "", errors.New("Not an HTTP message") //nolint:staticcheck // Match the upstream view's displayed error.
	}
	contentType, ok := metadata.HTTPMessage.Headers.Lookup("content-type")
	if !ok {
		// Upstream's header lookup raises KeyError here.
		return "", errors.New("content-type header is missing")
	}
	parts, err := httpmsg.DecodeMultipart(contentType, data)
	if err != nil {
		return "", err
	}
	pairs := make([][2]string, len(parts))
	for i, part := range parts {
		pairs[i][0] = strutil.BytesToEscapedStr(part[0], false, false)
		pairs[i][1] = strutil.BytesToEscapedStr(part[1], false, false)
	}
	return yamlPairs(pairs)
}
