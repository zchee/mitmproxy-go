// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/internal/netstack"
)

// TestServerEncryptedFlows mirrors the upstream userspace client and uppercase
// connection handler. It exercises accepted TCP/UDP flows, not CLI mode admission.
func TestServerEncryptedFlows(t *testing.T) {
	// py:test/mitmproxy/proxy/test_mode_servers.py:172-225.
	tests := map[string]struct{ fixture string }{
		"success: upstream TCP and UDP client": {fixture: "../../testdata/wg-test-client/test.conf"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cfg, err := LoadConfig(test.fixture)
			if err != nil {
				t.Fatal(err)
			}
			stack, err := netstack.New(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stack.Close() }()
			socket, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server, err := New(ctx, socket, cfg, stack, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Close() }()
			deadline, _ := ctx.Deadline()
			failures := make(chan error, 2)
			var workers sync.WaitGroup
			defer func() { cancel(); _ = stack.Close(); workers.Wait() }()
			workers.Go(func() {
				select {
				case stream, ok := <-stack.TCPConns():
					if !ok {
						failures <- fmt.Errorf("TCP accept ended before client handshake")
						return
					}
					defer func() { _ = stream.Close() }()
					if err := stream.SetDeadline(deadline); err != nil {
						failures <- err
						return
					}
					data := make([]byte, len("hello world!"))
					if _, err := io.ReadFull(stream, data); err != nil {
						failures <- fmt.Errorf("TCP payload: %w", err)
						return
					}
					if !gocmp.Equal(data, []byte("hello world!")) {
						failures <- fmt.Errorf("unexpected TCP plaintext %q", data)
						return
					}
					_, err := stream.Write(bytes.ToUpper(data))
					if err == nil {
						err = stream.Drain(ctx)
					}
					failures <- err
				case <-ctx.Done():
					failures <- ctx.Err()
				}
			})
			workers.Go(func() {
				select {
				case transport, ok := <-stack.UDPConns():
					if !ok {
						failures <- fmt.Errorf("UDP accept ended before client datagram")
						return
					}
					defer func() { _ = transport.Close() }()
					if err := transport.SetDeadline(deadline); err != nil {
						failures <- err
						return
					}
					var data [65535]byte
					n, peer, err := transport.ReadFrom(data[:])
					if err != nil {
						failures <- fmt.Errorf("UDP payload: %w", err)
						return
					}
					if !gocmp.Equal(data[:n], []byte("hello")) {
						failures <- fmt.Errorf("unexpected UDP plaintext %q", data[:n])
						return
					}
					_, err = transport.WriteTo(bytes.ToUpper(data[:n]), peer)
					failures <- err
				case <-ctx.Done():
					failures <- ctx.Err()
				}
			})
			clientName := runtime.GOOS + "-" + runtime.GOARCH
			switch clientName {
			case "linux-amd64":
				clientName = "linux-x86_64"
			case "darwin-arm64":
				clientName = "macos-aarch64"
			case "darwin-amd64":
				clientName = "macos-x86_64"
			case "windows-amd64":
				clientName = "windows-x86_64.exe"
			default:
				t.Fatalf("no upstream WireGuard client fixture for %s", clientName)
			}
			clientPath, err := filepath.Abs(filepath.Join("../../testdata/wg-test-client", clientName))
			if err != nil {
				t.Fatal(err)
			}
			client := exec.CommandContext(ctx, clientPath, strconv.Itoa(server.Addr().(*net.UDPAddr).Port))
			client.WaitDelay = 5 * time.Second
			output, err := client.CombinedOutput()
			if err != nil {
				if ctx.Err() != nil {
					deviceTestTimeout(t, ctx)
				}
				t.Fatalf("upstream encrypted TCP/UDP client: %v\n%s", err, output)
			}
			for range 2 {
				select {
				case err := <-failures:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					deviceTestTimeout(t, ctx)
				}
			}
		})
	}
}
