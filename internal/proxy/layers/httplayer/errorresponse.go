// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"fmt"
	"strings"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/h2"
	"github.com/zchee/mitmproxy-go/internal/version"
)

// htmlEscaper escapes the five characters Python's html.escape replaces,
// using Python's replacement text so error bodies match upstream byte for
// byte: Go's html.EscapeString writes an apostrophe as &#39; instead.
var htmlEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&#x27;",
)

// formatError renders the HTML error body mitmproxy shows for a failed
// stream. message is escaped; the reason phrase for an unknown status code
// is "Unknown". Typed connection failures use a fixed client-facing 502 body.
func formatError(statusCode int, message string, cause error) []byte {
	if statusCode == 502 && h2.IsConnectionClosed(cause) {
		message = "upstream closed the HTTP/2 connection"
	}
	reason := httpmsg.StatusText(statusCode)
	if reason == "" {
		reason = "Unknown"
	}
	return fmt.Appendf(nil,
		"<html>\n<head>\n    <title>%[1]d %[2]s</title>\n</head>\n<body>\n    <h1>%[1]d %[2]s</h1>\n    <p>%[3]s</p>\n</body>\n</html>",
		statusCode, reason, htmlEscaper.Replace(message))
}

// makeErrorResponse builds the HTTP response for a failed stream: the
// formatError body with Connection: close and a text/html content type,
// as upstream's make_error_response, with this proxy's Server value.
func makeErrorResponse(statusCode int, message string, cause error) (*httpmsg.Response, error) {
	return httpmsg.MakeResponse(statusCode, formatError(statusCode, message, cause), httpmsg.Headers{
		{Name: []byte("Server"), Value: []byte(version.String())},
		{Name: []byte("Connection"), Value: []byte("close")},
		{Name: []byte("Content-Type"), Value: []byte("text/html")},
	})
}
