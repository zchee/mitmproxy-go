// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnslayer

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/internal/netutil/freeport"
)

func TestUDPSessionSocketCleanup(t *testing.T) {
	const childEnv = "MITMPROXY_DNS_SESSION_CLEANUP"
	const receipt = "session sockets released"
	if mode := os.Getenv(childEnv); mode != "" {
		var s *session
		t.Run("fixture", func(t *testing.T) {
			s = newSession(t, true, nil)
			lc := new(net.ListenConfig)
			tcp, err := lc.Listen(t.Context(), "tcp4", s.context.ClientPackets.LocalAddr().String())
			if err != nil {
				t.Fatalf("unused TCP mate is still bound: %v", err)
			}
			if err := tcp.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "failure" {
				if err := s.client.Close(); err != nil {
					t.Fatal(err)
				}
				if err := s.client.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("closed peer setup error = %v, want net.ErrClosed", err)
				}
				t.Fatal("injected closed-peer setup failure")
			}
		})
		if s == nil {
			t.Fatal("fixture was not acquired")
		}
		if err := s.client.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("peer cleanup error = %v, want net.ErrClosed", err)
		}
		if _, err := s.context.ClientPackets.WriteTo([]byte("closed tuple"), nil); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("tuple cleanup error = %v, want net.ErrClosed", err)
		}
		tcp, udp, err := freeport.ListenPair(t.Context(), "tcp4", s.context.ClientPackets.LocalAddr().String())
		if err != nil {
			t.Fatalf("session socket remains bound after cleanup: %v", err)
		}
		if err := tcp.Close(); err != nil {
			t.Fatal(err)
		}
		if err := udp.Close(); err != nil {
			t.Fatal(err)
		}
		t.Log(receipt)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		mode string
		fail bool
	}{
		"success: ordinary cleanup":  {mode: "cleanup"},
		"error: fatal setup cleanup": {mode: "failure", fail: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestUDPSessionSocketCleanup$", "-test.v")
			cmd.Env = append(os.Environ(), childEnv+"="+test.mode)
			output, err := cmd.CombinedOutput()
			if (err != nil) != test.fail || test.fail && !strings.Contains(string(output), "injected closed-peer setup failure") || !strings.Contains(string(output), receipt) {
				t.Fatalf("cleanup subprocess error = %v, want failure %v:\n%s", err, test.fail, output)
			}
		})
	}
}

func TestUDPSessionAcquisitionCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	tcp, udp, err := freeport.ListenPair(ctx, "tcp4", "127.0.0.1:0")
	if tcp != nil {
		_ = tcp.Close()
	}
	if udp != nil {
		_ = udp.Close()
	}
	if tcp != nil || udp != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled acquisition = (%v, %v, %v), want no sockets and context.Canceled", tcp, udp, err)
	}
}
