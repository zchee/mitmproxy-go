// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	miekg "codeberg.org/miekg/dns"
	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/modeserver"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

type acceptanceUpstream struct {
	address netip.AddrPort
	mu      sync.Mutex
	queries map[uint16]int
	errors  chan error
}

func (u *acceptanceUpstream) counts() map[uint16]int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return map[uint16]int{miekg.TypeA: u.queries[miekg.TypeA], miekg.TypeAAAA: u.queries[miekg.TypeAAAA]}
}

func acceptanceValue[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(30 * time.Second):
		stack := make([]byte, 1<<20)
		t.Fatalf("DNS acceptance operation did not finish:\n%s", stack[:runtime.Stack(stack, true)])
		var zero T
		return zero
	}
}

func startAcceptanceUpstream(t *testing.T) *acceptanceUpstream {
	t.Helper()
	stream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp4", stream.Addr().String())
	if err != nil {
		_ = stream.Close()
		t.Fatal(err)
	}
	u := &acceptanceUpstream{address: stream.Addr().(*net.TCPAddr).AddrPort(), queries: make(map[uint16]int), errors: make(chan error, 32)}
	handler := miekg.HandlerFunc(func(_ context.Context, w miekg.ResponseWriter, request *miekg.Msg) {
		if len(request.Question) != 1 || request.Question[0].Header().Name != "example.test." {
			u.errors <- fmt.Errorf("unexpected authoritative question: %s", request)
			return
		}
		header := miekg.Header{Name: "example.test.", Class: miekg.ClassINET, TTL: 137}
		var record miekg.RR
		var typ uint16
		switch request.Question[0].(type) {
		case *miekg.A:
			answer := &miekg.A{Hdr: header}
			answer.Addr = netip.MustParseAddr("192.0.2.1")
			record, typ = answer, miekg.TypeA
		case *miekg.AAAA:
			answer := &miekg.AAAA{Hdr: header}
			answer.Addr = netip.MustParseAddr("2001:db8::1")
			record, typ = answer, miekg.TypeAAAA
		default:
			u.errors <- fmt.Errorf("unexpected authoritative question type: %T", request.Question[0])
			return
		}
		u.mu.Lock()
		u.queries[typ]++
		u.mu.Unlock()
		response := &miekg.Msg{ID: request.ID, Response: true, Authoritative: true, RecursionDesired: request.RecursionDesired, Question: request.Question, Answer: []miekg.RR{record}}
		if _, err := response.WriteTo(w); err != nil {
			u.errors <- err
		}
	})
	started, done := make(chan struct{}, 2), make(chan error, 2)
	tcp, udp := miekg.NewServer(), miekg.NewServer()
	tcp.Net, tcp.Listener, udp.Net, udp.PacketConn = "tcp", stream, "udp", packet
	for _, server := range []*miekg.Server{tcp, udp} {
		server.Handler, server.ReadTimeout, server.IdleTimeout = handler, 30*time.Second, 30*time.Second
		server.NotifyStartedFunc = func(context.Context) { started <- struct{}{} }
		go func() { done <- server.ListenAndServe() }()
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
		defer cancel()
		tcp.Shutdown(ctx)
		udp.Shutdown(ctx)
		for range 2 {
			if err := acceptanceValue(t, done); err != nil {
				t.Error(err)
			}
		}
	})
	for range 2 {
		acceptanceValue(t, started)
	}
	return u
}

// Resolver answers synthesize DefaultTTL; reverse mode bypasses the resolver and
// retains the authoritative answer's TTL. Repeated queries intentionally reach
// upstream again: only resolver configuration, not DNS answers, is cached.
func TestModeServerResolverAcceptance(t *testing.T) {
	tests := map[string]struct {
		mode, network string
		typ           uint16
		wantAddress   string
	}{
		"standalone UDP A":    {"dns", "udp", miekg.TypeA, "192.0.2.1"},
		"standalone TCP A":    {"dns", "tcp", miekg.TypeA, "192.0.2.1"},
		"standalone UDP AAAA": {"dns", "udp", miekg.TypeAAAA, "2001:db8::1"},
		"standalone TCP AAAA": {"dns", "tcp", miekg.TypeAAAA, "2001:db8::1"},
		"reverse UDP A":       {"reverse", "udp", miekg.TypeA, "192.0.2.1"},
		"reverse TCP A":       {"reverse", "tcp", miekg.TypeA, "192.0.2.1"},
		"reverse UDP AAAA":    {"reverse", "udp", miekg.TypeAAAA, "2001:db8::1"},
		"reverse TCP AAAA":    {"reverse", "tcp", miekg.TypeAAAA, "2001:db8::1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			upstream := startAcceptanceUpstream(t)
			logger := slog.New(slog.DiscardHandler)
			m := master.New(master.Config{Logger: logger})
			t.Cleanup(func() {
				if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
					t.Error(err)
				}
			})
			resolver := New(m.Options, logger)
			// The existing internal port seam avoids privileged port53 in CI.
			resolver.port = upstream.address.Port()
			if err := m.Options.Add(t.Context(), "connection_strategy", options.TypeStr, "eager", "Server connection strategy."); err != nil {
				t.Fatal(err)
			}
			if err := m.Addons.Add(t.Context(), resolver, nextlayer.New(m.Options)); err != nil {
				t.Fatal(err)
			}
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return m.Options.Update(ctx, map[string]any{"dns_name_servers": []string{upstream.address.Addr().String()}, "dns_use_hosts_file": false})
			}); err != nil {
				t.Fatal(err)
			}
			connections := new(proxy.Connections)
			t.Cleanup(connections.Close)
			handler, err := proxy.NewHandler(proxy.Config{Manager: m.Addons, Options: m.Options, Connections: connections, Logger: logger})
			if err != nil {
				t.Fatal(err)
			}
			spec := "dns@127.0.0.1:0"
			if tt.mode == "reverse" {
				spec = "reverse:dns://" + upstream.address.String() + "@127.0.0.1:0"
			}
			mode, err := modespec.Parse(spec)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := modeserver.New(mode, modeserver.Config{Handler: handler, Logger: logger})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(func() { cancel(); _ = instance.Stop() })
			if err := instance.Start(ctx); err != nil {
				t.Fatal(err)
			}
			client := &miekg.Client{Transport: &miekg.Transport{Dialer: &net.Dialer{Timeout: 30 * time.Second}, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}}
			var previous *resolverConfig
			var previousAnswer string
			for round := range 2 {
				request := miekg.NewMsg("example.test", tt.typ)
				request.ID = uint16(round + 1)
				response, _, err := client.Exchange(t.Context(), request, tt.network, instance.ListenAddrs()[0].String())
				if err != nil {
					t.Fatal(err)
				}
				if !response.Response || response.ID != request.ID || response.Rcode != 0 || len(response.Answer) != 1 {
					t.Fatalf("unexpected acceptance response: %s", response)
				}
				var address netip.Addr
				switch answer := response.Answer[0].(type) {
				case *miekg.A:
					address = answer.Addr
				case *miekg.AAAA:
					address = answer.Addr
				default:
					t.Fatalf("unexpected acceptance answer type: %T", answer)
				}
				if diff := gocmp.Diff(tt.wantAddress, address.String()); diff != "" {
					t.Fatal(diff)
				}
				wantTTL := uint32(dns.DefaultTTL)
				if tt.mode == "reverse" {
					wantTTL = 137
				}
				if diff := gocmp.Diff(miekg.Header{Name: "example.test.", Class: miekg.ClassINET, TTL: wantTTL}, *response.Answer[0].Header()); diff != "" {
					t.Fatal(diff)
				}
				if round == 1 && previousAnswer != response.Answer[0].String() {
					t.Fatal("repeated query changed the answer")
				}
				previousAnswer = response.Answer[0].String()
				if err := m.Do(t.Context(), func(context.Context) error {
					if tt.mode == "reverse" {
						if resolver.cached != nil {
							t.Error("reverse mode unexpectedly invoked resolver lookup")
						}
					} else {
						if resolver.cached == nil || round == 1 && resolver.cached != previous {
							t.Error("resolver configuration snapshot missing or replaced")
						}
						previous = resolver.cached
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			wantCounts := map[uint16]int{miekg.TypeA: 2, miekg.TypeAAAA: 2}
			if tt.mode == "reverse" {
				wantCounts = map[uint16]int{miekg.TypeA: 0, miekg.TypeAAAA: 0}
				wantCounts[tt.typ] = 2
			}
			if diff := gocmp.Diff(wantCounts, upstream.counts()); diff != "" {
				t.Fatal(diff)
			}
			select {
			case err := <-upstream.errors:
				t.Fatal(err)
			default:
			}
			cancel()
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
