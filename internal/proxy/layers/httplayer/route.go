// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"fmt"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

// httpMode is how the HTTP layer interprets request targets, as upstream's
// HTTPMode: regular proxying with absolute-form targets, transparent
// interception that learns the target from the connection, and upstream
// proxying that forwards absolute-form requests to another proxy. A reverse
// proxy runs as transparent with the listener's fixed destination.
type httpMode uint8

const (
	modeRegular httpMode = iota
	modeTransparent
	modeUpstream
)

// routeConfig is the request-shaping policy of one HTTP layer: the mode,
// whether the client connected to a reverse-proxy listener, and the options
// read at layer construction.
type routeConfig struct {
	mode    httpMode
	reverse bool
	// keepHostHeader leaves the client's Host header alone in reverse mode.
	keepHostHeader bool
	// validateInboundHeaders refuses ambiguous framing before any hook runs.
	validateInboundHeaders bool
}

// validateRequest returns the refusal text for a request the proxy will not
// process, or "": an unsupported scheme, a CONNECT outside regular or
// upstream mode, and header blocks that would smuggle a second request.
func validateRequest(mode httpMode, request *httpmsg.Request, validateInboundHeaders bool) string {
	switch request.Scheme {
	case "http", "https", "":
	default:
		return "Invalid request scheme: " + request.Scheme
	}
	if mode == modeTransparent && request.Method == "CONNECT" {
		return "mitmproxy received an HTTP CONNECT request even though it is not running in " +
			"regular/upstream mode. This usually indicates a misconfiguration, " +
			"please see the mitmproxy mode documentation for details."
	}
	if validateInboundHeaders {
		if err := request.ValidateHeaders(); err != nil {
			return fmt.Sprintf("Received %v from client, refusing to prevent request smuggling attacks. "+
				"Disable the validate_inbound_headers option to skip this security check.", err)
		}
	}
	return ""
}

// normalizeRequest fills the request's target from the connection the client
// used and shapes the head for forwarding, as upstream's
// state_wait_for_request_headers does before the requestheaders hook:
// transparent targets come from the server metadata, a missing target comes
// from the Host header, regular mode downgrades absolute-form targets to
// origin-form for HTTP/1 origins, and reverse mode rewrites the Host header
// to the configured destination unless keep_host_header is set. It returns
// the refusal text for a request whose destination cannot be determined.
func normalizeRequest(route routeConfig, clientTLS bool, server *connection.Server, request *httpmsg.Request) string {
	if route.mode == modeTransparent {
		request.Host = server.Address.Host
		request.Port = server.Address.Port
		if server.TLS {
			request.Scheme = "https"
		} else {
			request.Scheme = "http"
		}
	} else if request.Host == "" {
		// The destination must come from the Host header.
		header, _ := request.HostHeader()
		host, port, err := httpmsg.ParseAuthority(header, true)
		if err != nil {
			return "HTTP request has no host header, destination unknown."
		}
		if port < 0 {
			if clientTLS {
				port = 443
			} else {
				port = 80
			}
		}
		request.Host = host
		request.Port = port
		if clientTLS {
			request.Scheme = "https"
		} else {
			request.Scheme = "http"
		}
	}

	if route.mode == modeRegular && !request.IsHTTP2() && !request.IsHTTP3() {
		// Downgrade to origin-form: some HTTP/1 origins refuse the
		// absolute-form target a proxy client sends.
		request.Authority = ""
	}

	if route.reverse && !route.keepHostHeader {
		scheme := "http"
		if server.TLS {
			scheme = "https"
		}
		request.SetHostHeader(httpmsg.HostPort(scheme, server.Address.Host, server.Address.Port))
	}
	return ""
}
