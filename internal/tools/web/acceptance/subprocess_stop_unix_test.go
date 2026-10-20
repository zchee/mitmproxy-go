// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest && unix

package acceptance_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/difftest"
)

func TestMitmwebProcessStop(t *testing.T) {
	tests := map[string]struct{}{"direct child releases descendant": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			uv, err := exec.LookPath("uv")
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			ready, stopped := filepath.Join(root, "ready"), filepath.Join(root, "stopped")
			const script = `import os
import pathlib
import signal
import subprocess
import sys

child = subprocess.Popen(
    [sys.executable, "-I", "-c",
     "import sys; sys.stdout.write('ready\\n'); sys.stdout.flush(); sys.stdin.buffer.read(1)"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
)
if child.stdout.readline() != b"ready\n":
    raise RuntimeError("descendant failed readiness")
received = 0
read_fd, write_fd = os.pipe()

def stop(_signum: int, _frame: object) -> None:
    global received
    received += 1
    os.write(write_fd, b"!")

signal.signal(signal.SIGTERM, stop)
pathlib.Path(sys.argv[1]).write_text("ready\n")
os.read(read_fd, 1)
child.stdin.close()
status = child.wait()
pathlib.Path(sys.argv[2]).write_text(f"{received} {status}\n")
if received != 1 or status != 0:
    raise RuntimeError("normal stop signalled the descendant or delivered twice")
`
			process := startWebProcess(t, uv, []string{"run", "--quiet", "--no-project", "--python", difftest.PythonVersion, "--with", difftest.Requirement, "python", "-I", "-c", script, ready, stopped}, "signal-forwarding")
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			for {
				if _, err := os.Stat(ready); err == nil {
					break
				} else if !os.IsNotExist(err) {
					t.Fatal(err)
				}
				select {
				case <-process.done:
					t.Fatalf("real uv/Python process exited before signal readiness: %v", process.waitErr)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-ticker.C:
				}
			}
			process.stop(t)
			raw, err := os.ReadFile(stopped)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff("1 0\n", string(raw)); diff != "" {
				t.Errorf("SIGTERM delivery count and real descendant exit differ (-want +got):\n%s", diff)
			}
		})
	}
}
