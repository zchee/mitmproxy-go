// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package freeport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func stallWindowsRangeFixture(verb, protocol string) error {
	dir := os.Getenv("MITMPROXY_FREEPORT_STALL_DIR")
	log, err := os.OpenFile(filepath.Join(dir, "queries.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintln(log, verb+" "+protocol)
	closeErr := log.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if verb != "excludedportrange" || protocol != "protocol=tcp" {
		return nil
	}
	if err := os.WriteFile(filepath.Join(dir, "started"), []byte("ready"), 0o600); err != nil {
		return err
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-deadline.C:
			return errors.New("stalled fixture was not released")
		case <-ticker.C:
		}
	}
}

func TestWindowsListenPairDiscoveryCancellation(t *testing.T) {
	if os.Getenv("MITMPROXY_FREEPORT_FIXTURE") == "stall" {
		dir := os.Getenv("MITMPROXY_FREEPORT_STALL_DIR")
		defer func() {
			if err := os.WriteFile(filepath.Join(dir, "release"), []byte("released"), 0o600); err != nil {
				t.Error(err)
			}
			if _, err := pairPortDomain(t.Context()); err != nil {
				t.Error(err)
			}
		}()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		binds := 0
		result := make(chan error, 1)
		go func() {
			tcp, udp, err := listenPair(ctx, "tcp4", "127.0.0.1:0", pairListeners{
				domain: pairPortDomain,
				listen: func(context.Context, string, string) (net.Listener, error) {
					binds++
					return nil, errors.New("unexpected bind")
				},
				retryable: retryablePairBind,
			})
			if tcp != nil || udp != nil {
				result <- errors.New("cancelled discovery returned sockets")
				return
			}
			result <- err
		}()
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		waiting := true
		for waiting {
			if _, err := os.Stat(filepath.Join(dir, "started")); err == nil {
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			select {
			case <-deadline.C:
				t.Fatal("netsh discovery did not start")
			case <-ticker.C:
			}
		}
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled caller cause: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("caller did not cancel while discovery was stalled")
		}
		if binds != 0 {
			t.Fatalf("cancelled waiter bound %d sockets", binds)
		}
		if err := os.WriteFile(filepath.Join(dir, "release"), []byte("released"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := pairPortDomain(t.Context()); err != nil {
			t.Fatal(err)
		}
		tcp, udp, err := ListenPair(t.Context(), "tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tcp.Close(); _ = udp.Close() }()
		queries, err := os.ReadFile(filepath.Join(dir, "queries.log"))
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"excludedportrange protocol=tcp", "excludedportrange protocol=udp", "dynamicportrange protocol=tcp", "dynamicportrange protocol=udp"}
		if diff := gocmp.Diff(want, strings.FieldsFunc(strings.TrimSpace(string(queries)), func(r rune) bool { return r == '\n' })); diff != "" {
			t.Fatalf("single cached discovery queries (-want +got):\n%s", diff)
		}
		t.Log("cancelled stalled waiter: zero binds; shared worker joined; subsequent acquisition reused four cached queries")
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "netsh.exe"), binary, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestWindowsListenPairDiscoveryCancellation$", "-test.v")
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "MITMPROXY_FREEPORT_FIXTURE=stall", "MITMPROXY_FREEPORT_STALL_DIR="+dir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("stalled discovery subprocess: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}
