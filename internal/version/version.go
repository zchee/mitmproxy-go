// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package version holds mitmproxy-go's release version, as upstream's
// mitmproxy/version.py holds mitmproxy's.
package version

// Version is the mitmproxy-go release.
const Version = "0.1.0-dev"

// String returns the program name and version, "mitmproxy-go <Version>",
// in the place where mitmproxy writes "mitmproxy <VERSION>".
func String() string {
	return "mitmproxy-go " + Version
}
