// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build darwin || freebsd

package platform

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

const pfCommandTimeout = 5 * time.Second

func readPFState(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, pfCommandTimeout)
	defer cancel()
	out := &boundedPFOutput{cancel: cancel}
	cmd := exec.CommandContext(ctx, "sudo", "-n", "/sbin/pfctl", "-s", "state")
	cmd.WaitDelay = time.Second
	cmd.Stdout, cmd.Stderr = out, out
	err := cmd.Run()
	if out.full {
		return nil, ErrPFOutput
	}
	if bytes.Contains(out.Bytes(), []byte("sudo: a password is required")) {
		return nil, ErrPrivileges
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("Error getting pfctl state: %w", err)
	}
	return out.Bytes(), nil
}
