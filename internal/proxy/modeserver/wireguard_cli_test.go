// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build integration

package modeserver_test

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestWireGuardExecutableMode(t *testing.T) {
	tests := map[string]struct{ payload string }{
		"encrypted TCP reaches executable handler": {payload: "wireguard-cli"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, file, _, ok := runtime.Caller(0)
			if !ok {
				t.Fatal("cannot locate module source")
			}
			root := filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
			binary := filepath.Join(t.TempDir(), "mitmdump")
			if runtime.GOOS == "windows" {
				binary += ".exe"
			}
			build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/mitmdump")
			build.Dir = root
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build executable: %v\n%s", err, output)
			}
			directory := t.TempDir()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			command := exec.CommandContext(ctx, binary, "--mode", "wireguard@127.0.0.1:0", "--set", "confdir="+directory, "--set", "rawtcp=true")
			command.Dir = root
			if runtime.GOOS != "windows" {
				command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
			}
			command.WaitDelay = 30 * time.Second
			reader, writer := io.Pipe()
			command.Stdout, command.Stderr = writer, writer
			ready := make(chan string, 1)
			scanned := make(chan struct{})
			go func() {
				defer close(scanned)
				pattern := regexp.MustCompile(`WireGuard server listening at (127\.0\.0\.1:[0-9]+)\.`)
				scanner := bufio.NewScanner(reader)
				for scanner.Scan() {
					if match := pattern.FindStringSubmatch(scanner.Text()); len(match) == 2 {
						select {
						case ready <- match[1]:
						default:
						}
					}
				}
			}()
			if err := command.Start(); err != nil {
				_ = writer.Close()
				_ = reader.Close()
				<-scanned
				t.Fatal(err)
			}
			exited := make(chan error, 1)
			go func() { err := command.Wait(); _ = writer.Close(); exited <- err }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-exited:
				case <-time.After(30 * time.Second):
					_ = command.Process.Kill()
					<-exited
					t.Error("executable shutdown hang detector")
				}
				_ = reader.Close()
				<-scanned
			})
			var endpoint string
			select {
			case endpoint = <-ready:
			case err := <-exited:
				exited <- err
				t.Fatalf("executable exited before WireGuard listener: %v", err)
			case <-time.After(30 * time.Second):
				t.Fatal("executable startup hang detector")
			}
			origin := proxytest.StartEchoOrigin(t)
			network := modeWireGuardClient(t, filepath.Join(directory, "wireguard.conf"), endpoint, false)
			readCtx, readCancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer readCancel()
			peer, err := network.DialContext(readCtx, "tcp", origin.Addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			if err := peer.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(peer, tt.payload); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len(tt.payload))
			if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != tt.payload {
				t.Fatalf("executable TCP reply = %q, %v", buf, err)
			}
		})
	}
}
