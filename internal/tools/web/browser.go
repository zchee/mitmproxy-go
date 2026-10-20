// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// openBrowser tries only fixed GUI-capable launchers. The URL is always one
// argument, never interpreted by a shell or a BROWSER environment template.
func openBrowser(ctx context.Context, address string) bool {
	var commands [][]string
	switch runtime.GOOS {
	case "darwin":
		commands = [][]string{{"open"}}
	case "windows":
		commands = [][]string{{"rundll32.exe", "url.dll,FileProtocolHandler"}}
	default:
		commands = [][]string{{"wslview"}}
		if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
			commands = append(commands, []string{"gio", "open"}, []string{"x-www-browser"}, []string{"gnome-open"}, []string{"xdg-open"}, []string{"google-chrome"}, []string{"chrome"}, []string{"chromium"}, []string{"chromium-browser"}, []string{"firefox"}, []string{"opera"}, []string{"safari"})
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, command := range commands {
		if ctx.Err() != nil {
			return false
		}
		path, err := exec.LookPath(command[0])
		if err != nil {
			continue
		}
		args := append(command[1:], address)
		cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // Fixed GUI launcher names resolve through PATH; the URL is one argument, never shell text.
		cmd.WaitDelay = time.Second
		if cmd.Run() == nil {
			return true
		}
	}
	return false
}
