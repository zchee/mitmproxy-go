// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

// NewWindowsRedirector creates a native Windows packet controller.
// Construction is inert. A deliberate Launch acquires the pinned executable
// and requests native runas elevation; the IPC connection timeout does not
// cancel an OS approval dialog. Packet messages use named-pipe message boundaries.
func NewWindowsRedirector(confdir, overridePath string) Redirector {
	return newWindowsRedirector(confdir, overridePath)
}
