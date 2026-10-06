// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest_test

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
)

func TestRuntimeModeSwitchKeepsAcceptedClients(t *testing.T) {
	first := proxytest.StartEchoOrigin(t)
	second := proxytest.StartOrigin(t, func(conn net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if _, werr := io.WriteString(conn, "second:"+string(buf[:n])); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
	p := proxytest.Start(t, proxytest.WithOptions(map[string]any{"mode": []string{"reverse:tcp://" + first.Addr}}))
	accepted := dial(t, p.Addr)
	exchange(t, accepted, "before the switch")
	if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
		return p.Master.Options.Update(ctx, map[string]any{"mode": []string{"reverse:tcp://" + second.Addr}})
	}); err != nil {
		t.Fatal(err)
	}
	// The listener set is replaced asynchronously, outside dispatch.
	deadline := time.Now().Add(30 * time.Second)
	var switched string
	for {
		if addrs := p.Server.ListenAddrs(); len(addrs) > 0 && addrs[0].String() != p.Addr {
			switched = addrs[0].String()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("listeners never moved away from %s", p.Addr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	client := dial(t, switched)
	if _, err := io.WriteString(client, "after"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("second:after"))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "second:after" {
		t.Fatalf("new listener reached %q, want the second origin", string(buf))
	}
	// The connection accepted before the switch still exchanges through the
	// first origin: replacing listeners never interrupts live clients.
	exchange(t, accepted, "after the switch")
}

// reserveTCPPort binds an ephemeral loopback TCP port and releases it so the
// proxy can listen there. The TCP-only reservation is deliberate: a reverse
// TCP mode needs no UDP port, and freeport's paired UDP bind fails often enough
// on the Windows runner that it reports no port at all.
func reserveTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestSelfConnectGuard(t *testing.T) {
	port := reserveTCPPort(t)
	p := proxytest.Start(t, proxytest.WithOptions(map[string]any{
		"mode": []string{"reverse:tcp://127.0.0.1:" + strconv.Itoa(port) + "@" + strconv.Itoa(port)},
	}))
	client := dial(t, p.Addr)
	if _, err := io.WriteString(client, "loop"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("self-targeted connection relayed data")
	}
	awaitHook(t, p, "server_connect_error")
	var message string
	if err := p.Master.Do(t.Context(), func(context.Context) error {
		for _, call := range p.Recorder.Calls() {
			if call.Hook == "server_connect_error" {
				if data := call.Arg.(*hookdata.ServerConnection); data.Server.Error != nil {
					message = *data.Server.Error
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(message, "Request destination unknown. Unable to figure out where this request should be forwarded to.") {
		t.Fatalf("self-connect error = %q", message)
	}
}
