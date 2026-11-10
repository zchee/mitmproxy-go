// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyauth

import "encoding/base64"

// MakeAuth returns upstream's base64 basic-auth value, including its trailing LF.
// The caller supplies the scheme, conventionally "basic".
func MakeAuth(username, password, scheme string) string {
	return scheme + " " + base64.StdEncoding.EncodeToString([]byte(username+":"+password)) + "\n"
}
