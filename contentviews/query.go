// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import "errors"

// Query displays an HTTP request's query parameters as an ordered YAML mapping.
type Query struct{}

// Name returns the registered view name.
func (Query) Name() string { return "Query" }

// SyntaxHighlight returns the view's highlighting language.
func (Query) SyntaxHighlight() string { return "yaml" }

// RenderPriority prefers request query parameters when the body is empty.
func (Query) RenderPriority(data []byte, metadata Metadata) float64 {
	if len(data) == 0 && metadata.HTTPRequest != nil && len(metadata.HTTPRequest.Query()) != 0 {
		return 0.3
	}
	return 0
}

// Prettify renders query parameters, preserving key order and repeated values.
// It returns an error when metadata has no HTTP request or YAML encoding fails.
func (Query) Prettify(_ []byte, metadata Metadata) (string, error) {
	if metadata.HTTPRequest == nil {
		return "", errors.New("Not an HTTP request.") //nolint:staticcheck // Match the upstream view's displayed error.
	}
	return yamlPairs(metadata.HTTPRequest.Query())
}
