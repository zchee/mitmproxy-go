// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modes

import "github.com/zchee/mitmproxy-go/internal/proxy/modespec"

func init() {
	reverseSchemes["quic"] = reverseScheme{transport: modespec.UDP, setSNI: true, application: "quic"}
}
