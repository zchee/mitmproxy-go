// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build unix

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
	"github.com/zchee/mitmproxy-go/internal/tools/cmdline"
	"github.com/zchee/mitmproxy-go/internal/tools/dump"
	"github.com/zchee/mitmproxy-go/options"
)

type lifecycleRecorder struct {
	running chan struct{}
	done    atomic.Bool
}

func (r *lifecycleRecorder) Running(context.Context) error {
	close(r.running)
	return nil
}

func (r *lifecycleRecorder) Done(context.Context) error {
	r.done.Store(true)
	return nil
}

// TestSignalShutdown observes the done hook after a real SIGTERM.
func TestSignalShutdown(t *testing.T) {
	opts := options.New()
	var out, errOut strings.Builder
	m, err := dump.New(t.Context(), dump.Config{Options: opts, Stdout: &out, Stderr: &errOut, WithTermlog: true, WithDumper: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close(context.WithoutCancel(t.Context())) }()
	rec := &lifecycleRecorder{running: make(chan struct{})}
	if err := m.Addons.Add(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	err = m.Do(t.Context(), func(ctx context.Context) error {
		return opts.Update(ctx, map[string]any{"server": false, "confdir": t.TempDir()})
	})
	if err != nil {
		t.Fatal(err)
	}
	stop := cmdline.Signals(m.Shutdown)
	defer stop()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- m.Run(ctx) }()
	select {
	case <-rec.running:
	case err := <-result:
		t.Fatalf("master stopped before running: %v", err)
	case <-ctx.Done():
		stack := make([]byte, 1<<20)
		t.Fatalf("master startup hung:\n%s", stack[:runtime.Stack(stack, true)])
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-ctx.Done():
		stack := make([]byte, 1<<20)
		t.Fatalf("master shutdown hung:\n%s", stack[:runtime.Stack(stack, true)])
	}
	if !rec.done.Load() {
		t.Fatal("the done hook did not fire")
	}
}

// listeningAddr matches the address in a modeserver startup line.
var listeningAddr = regexp.MustCompile(`listening at (127\.0\.0\.1:\d+)`)

// TestProxyTCPBinary sends real TCP traffic through a serving mitmdump
// process in reverse mode: the echo origin's reply comes back through the
// proxy, the dumper prints the flow, and SIGTERM ends the process with
// status 0.
func TestProxyTCPBinary(t *testing.T) {
	origin := proxytest.StartEchoOrigin(t)
	cmd := child(t, "--listen-host", "127.0.0.1", "--mode", "reverse:tcp://"+origin.Addr+"@0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	ready := make(chan string, 1)
	output := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		var seen strings.Builder
		listening := false
		for scanner.Scan() {
			seen.WriteString(scanner.Text())
			seen.WriteByte('\n')
			if !listening {
				if match := listeningAddr.FindStringSubmatch(scanner.Text()); match != nil {
					listening = true
					ready <- match[1]
				}
			}
		}
		if !listening {
			close(ready)
		}
		if err := scanner.Err(); err != nil {
			seen.WriteString(err.Error())
		}
		output <- seen.String()
	}()
	addr, ok := <-ready
	if !ok {
		t.Fatalf("child ended before listening:\n%s", <-output)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	const probe = "through the mitmdump binary"
	if _, err := conn.Write([]byte(probe)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(probe))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != probe {
		t.Fatalf("echoed %q, want %q", buf, probe)
	}
	_ = conn.Close()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	seen := <-output
	if err := cmd.Wait(); err != nil {
		t.Fatalf("the child did not exit with status 0: %v\n%s", err, seen)
	}
	if !strings.Contains(seen, origin.Addr) {
		t.Fatalf("the dumper did not print the flow to %s:\n%s", origin.Addr, seen)
	}
}

// TestSignalBinary requires a listening subprocess to exit cleanly on SIGTERM.
func TestSignalBinary(t *testing.T) {
	cmd := child(t, "--listen-host", "127.0.0.1", "-p", "0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	ready := make(chan error, 1)
	scanned := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		var seen strings.Builder
		listening := false
		for scanner.Scan() {
			seen.WriteString(scanner.Text())
			seen.WriteByte('\n')
			if !listening && strings.Contains(scanner.Text(), "listening at") {
				listening = true
				ready <- nil
			}
		}
		if !listening {
			ready <- fmt.Errorf("child ended before listening: %s (read error: %v)", seen.String(), scanner.Err())
		}
		scanned <- scanner.Err()
	}()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := <-scanned; err != nil {
		t.Fatalf("read child output: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("the child did not exit with status 0: %v", err)
	}
}
