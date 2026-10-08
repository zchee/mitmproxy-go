// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build packetmodes

package packetmodetest

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sourceRoot(t *testing.T) string {
	t.Helper()
	if root := os.Getenv("PACKET_GATE_ROOT"); root != "" {
		if !filepath.IsAbs(root) {
			t.Fatal("PACKET_GATE_ROOT must be absolute")
		}
		return root
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate packet acceptance fixtures")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

func privateDirectory(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	// CA storage rejects group-writable directories even under a permissive umask.
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func logPath(t *testing.T, name string) string {
	t.Helper()
	dir := os.Getenv("PACKET_GATE_OUTPUT")
	if dir == "" {
		dir = t.TempDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, name)
}

type process struct {
	command *exec.Cmd
	done    chan struct{}
	err     error
	log     string
}

func startProcess(t *testing.T, binary string, args, env []string, name string) *process {
	t.Helper()
	path := logPath(t, name)
	output, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, args...)
	command.Dir = sourceRoot(t)
	command.Env = append(os.Environ(), env...)
	command.Stdout, command.Stderr = output, output
	p := &process{command: command, done: make(chan struct{}), log: path}
	if err := command.Start(); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	go func() {
		p.err = command.Wait()
		_ = output.Close()
		close(p.done)
	}()
	t.Cleanup(func() { p.stop(t) })
	return p
}

func (p *process) stop(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
	default:
		if err := p.command.Process.Signal(os.Interrupt); err != nil {
			t.Errorf("interrupt proxy: %v", err)
		}
		select {
		case <-p.done:
		case <-time.After(30 * time.Second):
			_ = p.command.Process.Kill()
			<-p.done
			hang(t, "proxy shutdown", p.log)
		}
	}
	if p.err != nil {
		content, _ := os.ReadFile(p.log)
		t.Errorf("proxy exit: %v\n%s", p.err, content)
	}
}

func (p *process) ready(t *testing.T, pattern string) string {
	t.Helper()
	re := regexp.MustCompile(pattern)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		content, err := os.ReadFile(p.log)
		if err != nil {
			t.Fatal(err)
		}
		if matches := re.FindStringSubmatch(string(content)); len(matches) == 2 {
			return matches[1]
		}
		select {
		case <-p.done:
			t.Fatalf("proxy exited before readiness: %v\n%s", p.err, content)
		case <-deadline.C:
			hang(t, "proxy readiness", p.log)
		case <-ticker.C:
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
}

func hang(t *testing.T, reason, path string) {
	t.Helper()
	var stacks strings.Builder
	_ = pprof.Lookup("goroutine").WriteTo(&stacks, 2)
	content, _ := os.ReadFile(path)
	t.Fatalf("%s hang detector\n%s\n%s", reason, content, stacks.String())
}

func address(t *testing.T, text string) (string, int) {
	t.Helper()
	host, portText, err := net.SplitHostPort(text)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
