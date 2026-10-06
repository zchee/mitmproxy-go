// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest_test

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestClientConnectionLimit(t *testing.T) {
	tests := map[string]struct {
		initial int
		clients int
	}{
		"success: cap shared across two modes":                     {initial: 1, clients: 1},
		"success: lowering unlimited cap retains existing clients": {clients: 2},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			origin := proxytest.StartEchoOrigin(t)
			p := proxytest.Start(t, proxytest.WithOptions(map[string]any{
				"max_client_connections": tt.initial,
				"mode": []string{
					"reverse:tcp://" + origin.Addr + "@127.0.0.1:0",
					"reverse:tcp://" + origin.Addr + "@localhost:0",
				},
			}))
			addrs := p.Server.ListenAddrs()
			if len(addrs) != 2 {
				t.Fatalf("listeners = %v, want two distinct modes", addrs)
			}
			var held []net.Conn
			for i := range tt.clients {
				client := dial(t, addrs[i].String())
				if err := clientLimitEcho(client); err != nil {
					t.Fatal(err)
				}
				held = append(held, client)
			}
			if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
				return p.Master.Options.Update(ctx, map[string]any{"max_client_connections": 1})
			}); err != nil {
				t.Fatal(err)
			}
			denied := dial(t, addrs[1].String())
			var byte [1]byte
			n, err := denied.Read(byte[:])
			if n != 0 || err == nil {
				t.Fatalf("over-cap connection read = %d, %v; want closure", n, err)
			}
			if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
				clientLimitHang(t, "over-cap client was not closed")
			}
			_ = denied.Close()
			got, err := p.Master.Call(t.Context(), "proxyserver.active_connections")
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.clients, got); diff != "" {
				t.Fatalf("denied client entered live registry (-want +got):\n%s", diff)
			}
			for _, client := range held {
				if err := clientLimitEcho(client); err != nil {
					t.Fatalf("lowering the cap dropped an existing connection: %v", err)
				}
				_ = client.Close()
			}
			// Handler cleanup releases reservations after disconnect hooks and pool joins.
			// Socket probes observe that completion without a sleep or a timing assertion.
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			for {
				if ctx.Err() != nil {
					clientLimitHang(t, "released client capacity was not reusable")
				}
				client, err := (&net.Dialer{}).DialContext(ctx, "tcp", addrs[1].String())
				if err != nil {
					t.Fatal(err)
				}
				deadline, _ := ctx.Deadline()
				if err := client.SetDeadline(deadline); err != nil {
					_ = client.Close()
					t.Fatal(err)
				}
				err = clientLimitEcho(client)
				_ = client.Close()
				if err == nil {
					break
				}
				if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
					clientLimitHang(t, "accepted client stopped responding")
				}
			}
		})
	}
}

func clientLimitEcho(client net.Conn) error {
	const text = "capacity probe\n"
	if _, err := io.WriteString(client, text); err != nil {
		return err
	}
	var got [len(text)]byte
	if _, err := io.ReadFull(client, got[:]); err != nil {
		return err
	}
	if string(got[:]) != text {
		return errors.New("unexpected capacity probe echo")
	}
	return nil
}

func clientLimitHang(t *testing.T, reason string) {
	t.Helper()
	stack := make([]byte, 1<<20)
	t.Fatalf("%s\n%s", reason, stack[:runtime.Stack(stack, true)])
}
