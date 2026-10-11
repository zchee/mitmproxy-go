// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/internal/netutil/freeport"
)

func TestAuthoritativeServerCleanup(t *testing.T) {
	const fatalFixtureEnv = "DNSRESOLVER_FATAL_FIXTURE"
	fixtures := map[string]func(*testing.T) netip.AddrPort{
		"paired origin": func(t *testing.T) netip.AddrPort {
			address, _ := authoritativeServer(t, false, func(request *dns.Message) *dns.Message {
				return request.Succeed(nil)
			})
			return address
		},
		"UDP origin":            dnsServer,
		"authoritative library": func(t *testing.T) netip.AddrPort { return startAcceptanceUpstream(t).address },
	}
	if name := os.Getenv(fatalFixtureEnv); name != "" {
		fixture, ok := fixtures[name]
		if !ok {
			t.Fatalf("unknown fatal fixture %q", name)
		}
		var address netip.AddrPort
		t.Cleanup(func() {
			tcp, udp, err := freeport.ListenPair(context.WithoutCancel(t.Context()), "tcp4", address.String())
			if err != nil {
				t.Errorf("fatal setup retained origin sockets: %v", err)
				return
			}
			_ = tcp.Close()
			_ = udp.Close()
			t.Log("fatal setup released both origin sockets")
		})
		address = fixture(t)
		t.Fatal("intentional fatal after origin setup")
	}
	for name, fixture := range fixtures {
		t.Run("success: cleanup "+name, func(t *testing.T) {
			var address netip.AddrPort
			if !t.Run("owned origin", func(t *testing.T) { address = fixture(t) }) {
				t.Fatal("origin setup failed")
			}
			tcp, udp, err := freeport.ListenPair(t.Context(), "tcp4", address.String())
			if err != nil {
				t.Fatalf("cleanup retained origin sockets: %v", err)
			}
			t.Cleanup(func() { _ = tcp.Close(); _ = udp.Close() })
		})
		t.Run("error: fatal setup "+name, func(t *testing.T) {
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), executable, "-test.run=^TestAuthoritativeServerCleanup$", "-test.v", "-test.timeout=30s")
			command.Env = append(os.Environ(), fatalFixtureEnv+"="+name)
			output, err := command.CombinedOutput()
			if _, ok := errors.AsType[*exec.ExitError](err); !ok {
				t.Fatalf("fatal setup subprocess did not fail as expected: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), "intentional fatal after origin setup") || !strings.Contains(string(output), "fatal setup released both origin sockets") || strings.Contains(string(output), "fatal setup retained origin sockets") {
				t.Fatalf("fatal setup cleanup was not certified:\n%s", output)
			}
		})
	}
}
