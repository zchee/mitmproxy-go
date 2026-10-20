// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build (difftest || webprivileged) && unix

package acceptance_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type webProcess struct {
	cmd      *exec.Cmd
	done     chan struct{}
	waitErr  error // Written before done closes; read only after that close.
	logPath  string
	stopOnce sync.Once
}

func startWebProcess(t *testing.T, executable string, args []string, label string) *webProcess {
	t.Helper()
	artifactRoot := os.Getenv("MITMPROXY_TEST_WEB_ARTIFACTS")
	if artifactRoot == "" {
		artifactRoot = t.TempDir()
	} else if !filepath.IsAbs(artifactRoot) {
		t.Fatal("MITMPROXY_TEST_WEB_ARTIFACTS must be an absolute owned output directory")
	}
	if err := os.MkdirAll(artifactRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	processOutput, err := os.MkdirTemp(artifactRoot, "process-")
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(processOutput, label+".log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(errors.Join(err, log.Close()))
	}
	process := &webProcess{cmd: cmd, done: make(chan struct{}), logPath: logPath}
	go func() {
		process.waitErr = errors.Join(cmd.Wait(), log.Close())
		close(process.done)
	}()
	t.Cleanup(func() { process.stop(t) })
	return process
}

func (process *webProcess) stop(t *testing.T) {
	t.Helper()
	process.stopOnce.Do(func() {
		if err := unix.Kill(-process.cmd.Process.Pid, unix.SIGTERM); err != nil && !errors.Is(err, unix.ESRCH) {
			t.Errorf("stop owned %d: %v", process.cmd.Process.Pid, err)
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 15*time.Second)
		defer cancel()
		select {
		case <-process.done:
		case <-ctx.Done():
			if err := unix.Kill(-process.cmd.Process.Pid, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
				t.Errorf("kill owned group: %v", err)
			}
			<-process.done
			t.Error("owned process exceeded SIGTERM grace; group was killed and reaped")
		}
		if process.waitErr != nil {
			log, err := os.ReadFile(process.logPath)
			if err != nil {
				t.Errorf("read child log: %v", err)
			}
			t.Errorf("owned process exit: %v\n%s", process.waitErr, log)
		}
		// Reap the direct child first. A surviving descendant is not success.
		if err := unix.Kill(-process.cmd.Process.Pid, 0); !errors.Is(err, unix.ESRCH) {
			killErr := unix.Kill(-process.cmd.Process.Pid, unix.SIGKILL)
			t.Errorf("owned process group still exists after reap: %v; kill: %v", err, killErr)
		}
	})
}

func waitWebReady(t *testing.T, process *webProcess, client *http.Client, tuple webInputTuple, ready func([]byte) bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	timer := time.NewTicker(50 * time.Millisecond)
	defer timer.Stop()
	var last error
	for {
		status, _, raw, err := requestWeb(ctx, client, tuple, http.MethodGet, "/state", nil)
		if err == nil && status == http.StatusOK && ready(raw) {
			return
		}
		last = fmt.Errorf("state readiness: status=%d error=%v", status, err)
		select {
		case <-process.done:
			log, readErr := os.ReadFile(process.logPath)
			t.Fatalf("web child exited before readiness: %v; log=%s; read=%v", process.waitErr, log, readErr)
		case <-ctx.Done():
			t.Fatalf("web readiness failed: %v; %v", ctx.Err(), last)
		case <-timer.C:
		}
	}
}
