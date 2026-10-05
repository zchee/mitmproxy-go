// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/strutil"
)

// URLEncoded displays form fields as an ordered YAML mapping.
type URLEncoded struct{}

// Name returns the registered view name.
func (URLEncoded) Name() string { return "URL-encoded" }

// SyntaxHighlight returns the view's highlighting language.
func (URLEncoded) SyntaxHighlight() string { return "yaml" }

// RenderPriority prefers nonempty URL-encoded form bodies.
func (URLEncoded) RenderPriority(data []byte, metadata Metadata) float64 {
	if len(data) != 0 && metadata.ContentType == "application/x-www-form-urlencoded" {
		return 1
	}
	return 0
}

// Prettify decodes form fields, escapes their bytes, and merges repeated keys.
// It returns an error if the YAML encoder cannot represent the result.
func (URLEncoded) Prettify(data []byte, _ Metadata) (string, error) {
	pairs := httpmsg.DecodeQuery(string(data))
	for i := range pairs {
		pairs[i][0] = strutil.BytesToEscapedStr([]byte(pairs[i][0]), false, false)
		pairs[i][1] = strutil.BytesToEscapedStr([]byte(pairs[i][1]), false, false)
	}
	return yamlPairs(pairs)
}
