// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build integration && transparentprivileged && linux

package modeserver_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type redirectProcess struct {
	command *exec.Cmd
	done    chan struct{}
	scanned chan struct{}
	ready   chan string
	err     error
	scanErr error
	once    sync.Once
	output  *os.File
	stderr  *os.File
	prefix  string
}

func startRedirectProcess(t *testing.T, ctx context.Context, directory, label string, ready *regexp.Regexp, environment []string, executable string, arguments ...string) *redirectProcess {
	t.Helper()
	prefix := filepath.Join(directory, label)
	stdout, err := os.OpenFile(prefix+".stdout", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.OpenFile(prefix+".stderr", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		_ = stdout.Close()
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = environment
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGINT)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 30 * time.Second
	if err := os.WriteFile(prefix+".command", []byte(command.String()+"\n"), 0o644); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	command.Stdout = io.MultiWriter(stdout, writer)
	command.Stderr = stderr
	process := &redirectProcess{command: command, output: stdout, stderr: stderr, prefix: prefix, done: make(chan struct{}), scanned: make(chan struct{}), ready: make(chan string, 1)}
	go func() {
		defer close(process.scanned)
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			if match := ready.FindStringSubmatch(scanner.Text()); len(match) == 2 {
				select {
				case process.ready <- match[1]:
				default:
				}
			}
		}
		process.scanErr = scanner.Err()
		_ = reader.Close()
	}()
	if err := command.Start(); err != nil {
		_ = writer.Close()
		<-process.scanned
		_ = stdout.Close()
		_ = stderr.Close()
		t.Fatalf("start %s: %v", label, err)
	}
	go func() {
		process.err = command.Wait()
		_ = writer.Close()
		close(process.done)
	}()
	t.Cleanup(func() { process.stop(t) })
	return process
}

func (p *redirectProcess) awaitReady(t *testing.T, ctx context.Context) string {
	t.Helper()
	select {
	case ready := <-p.ready:
		return ready
	case <-p.done:
		t.Fatalf("process exited before readiness: %s: %v", p.prefix, p.err)
	case <-ctx.Done():
		t.Fatalf("process readiness canceled: %s: %v", p.prefix, ctx.Err())
	case <-time.After(30 * time.Second):
		t.Fatalf("process readiness hang detector: %s", p.prefix)
	}
	return ""
}

func (p *redirectProcess) stop(t *testing.T) {
	t.Helper()
	p.once.Do(func() {
		select {
		case <-p.done:
		default:
			if err := syscall.Kill(-p.command.Process.Pid, syscall.SIGINT); err != nil && !errors.Is(err, syscall.ESRCH) {
				t.Errorf("interrupt %s: %v", p.prefix, err)
			}
			select {
			case <-p.done:
			case <-time.After(30 * time.Second):
				_ = syscall.Kill(-p.command.Process.Pid, syscall.SIGKILL)
				<-p.done
				t.Errorf("process shutdown hang detector: %s", p.prefix)
			}
		}
		<-p.scanned
		_ = p.output.Close()
		_ = p.stderr.Close()
		if p.scanErr != nil {
			t.Errorf("read process output %s: %v", p.prefix, p.scanErr)
		}
		status := p.command.ProcessState.ExitCode()
		if err := os.WriteFile(p.prefix+".exit", fmt.Appendf(nil, "exit=%d\nerror=%v\n", status, p.err), 0o644); err != nil {
			t.Error(err)
		}
		if p.err != nil {
			t.Errorf("process %s: %v", p.prefix, p.err)
		}
	})
}

func runRedirectCommand(t *testing.T, ctx context.Context, directory, label, executable string, arguments ...string) []byte {
	t.Helper()
	stdout, err := redirectCommand(ctx, directory, label, executable, arguments...)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return stdout
}

func redirectCommand(ctx context.Context, directory, label, executable string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	runErr := command.Run()
	status := -1
	if command.ProcessState != nil {
		status = command.ProcessState.ExitCode()
	}
	prefix := filepath.Join(directory, label)
	writeErr := errors.Join(
		os.WriteFile(prefix+".command", []byte(command.String()+"\n"), 0o644),
		os.WriteFile(prefix+".stdout", stdout.Bytes(), 0o644),
		os.WriteFile(prefix+".stderr", stderr.Bytes(), 0o644),
		os.WriteFile(prefix+".exit", fmt.Appendf(nil, "exit=%d\nerror=%v\n", status, runErr), 0o644),
	)
	return stdout.Bytes(), errors.Join(runErr, writeErr)
}

func requireRedirectTool(t *testing.T, name string, candidates ...string) string {
	t.Helper()
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	t.Fatalf("required native tool %s is unavailable; tried %s", name, strings.Join(candidates, ", "))
	return ""
}
