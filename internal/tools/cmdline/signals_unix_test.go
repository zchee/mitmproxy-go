// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build unix

package cmdline

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestSignals(t *testing.T) {
	if os.Getenv("MITMPROXY_GO_SIGNAL_TEST_CHILD") == "1" {
		fired := make(chan struct{})
		stop := Signals(sync.OnceFunc(func() { close(fired) }))
		defer stop()
		if !signal.Ignored(syscall.SIGPIPE) {
			t.Fatal("SIGPIPE must be ignored after installing handlers")
		}
		fmt.Println("ready")
		if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		fmt.Println("pong")
		<-fired
		stop()
		return
	}
	tests := map[string]struct{ signal os.Signal }{
		"success: interrupt": {os.Interrupt},
		"success: terminate": {syscall.SIGTERM},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestSignals$")
			cmd.Env = append(os.Environ(), "MITMPROXY_GO_SIGNAL_TEST_CHILD=1")
			// SIGQUIT makes the Go child print its goroutines if the wait hangs.
			cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGQUIT) }
			cmd.WaitDelay = 10 * time.Second
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
				if t.Failed() {
					t.Logf("child diagnostics:\n%s", stderr.String())
				}
			}()
			reader := bufio.NewReader(stdout)
			if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
				t.Fatalf("ready = %q, %v", line, err)
			}
			if err := cmd.Process.Signal(syscall.SIGPIPE); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintln(stdin, "ping"); err != nil {
				t.Fatal(err)
			}
			if line, err := reader.ReadString('\n'); err != nil || line != "pong\n" {
				t.Fatalf("SIGPIPE killed child: %q, %v", line, err)
			}
			if err := cmd.Process.Signal(tt.signal); err != nil {
				t.Fatal(err)
			}
			if err := stdin.Close(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			waited = true
			if err != nil {
				t.Fatalf("shutdown failed: %v\n%s", err, stderr.String())
			}
		})
	}
}
