// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowio

// Version is the mitmproxy-go release that flow version errors name, as
// mitmproxy names "mitmproxy <VERSION>" in its own.
const Version = "0.1.0-dev"

// versionName is the program name and version that begins a version error.
const versionName = "mitmproxy-go " + Version
