// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !proxybench

// Package bench exercises proxy throughput with owned client and origin endpoints.
package bench

import (
	"bufio"
	"bytes"
	"context"
	json "encoding/json/v2"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestProxyBenchSmoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the tagged harness source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../../.."))
	cmd := exec.CommandContext(ctx, "go", "test", "-race", "-tags", "proxybench", "-count=1", "-cpu=1", "-timeout=2m", "-json", "-run", "^TestProxyBenchHarness$/^smoke$", "./internal/proxy/bench")
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	exit := -1
	if cmd.ProcessState != nil {
		exit = cmd.ProcessState.ExitCode()
	}
	t.Logf("child argv=%q directory=%q exit=%d\nstdout:\n%s\nstderr:\n%s", cmd.Args, cmd.Dir, exit, stdout.Bytes(), stderr.Bytes())
	if err != nil {
		t.Fatalf("tagged harness child: %v", err)
	}
	runs, passes, packages := 0, 0, 0
	scanner := bufio.NewScanner(&stdout)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var event struct {
			Action string
			Test   string
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("malformed child JSON: %v", err)
		}
		if event.Action == "fail" || event.Action == "skip" {
			t.Fatalf("child %s: %s", event.Action, event.Test)
		}
		if event.Test == "TestProxyBenchHarness/smoke" {
			switch event.Action {
			case "run":
				runs++
			case "pass":
				passes++
			}
		}
		if event.Action == "pass" && event.Test == "" {
			packages++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || passes != 1 || packages != 1 {
		t.Fatalf("child smoke run=%d pass=%d package pass=%d, want exactly one each", runs, passes, packages)
	}
}
