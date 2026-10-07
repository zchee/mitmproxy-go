// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/dns"
)

func authoritativeServer(t *testing.T, truncate bool, reply func(*dns.Message) *dns.Message) (netip.AddrPort, <-chan string) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := tcp.Addr().(*net.TCPAddr).AddrPort()
	udp, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(address))
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	queries := make(chan string, 256)
	respond := func(wire []byte, network string) []byte {
		request, err := dns.Unpack(wire, nil)
		if err != nil {
			t.Error(err)
			return nil
		}
		question, ok := request.Question()
		if !ok {
			t.Error("authoritative server requires one question")
			return nil
		}
		queries <- network + ":" + question.Name
		response := reply(request)
		response.Truncation = truncate && network == "udp"
		wire, err = dns.Pack(response)
		if err != nil {
			t.Error(err)
			return nil
		}
		return wire
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			wire := respond(buffer[:n], "udp")
			if wire == nil {
				return
			}
			if _, err := udp.WriteToUDP(wire, peer); err != nil {
				return
			}
		}
	})
	workers.Go(func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			func() {
				defer func() { _ = conn.Close() }()
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer stop()
				if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Error(err)
					return
				}
				var size [2]byte
				if _, err := io.ReadFull(conn, size[:]); err != nil {
					if ctx.Err() == nil {
						t.Error(err)
					}
					return
				}
				wire := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(conn, wire); err != nil {
					t.Error(err)
					return
				}
				wire = respond(wire, "tcp")
				if wire == nil {
					return
				}
				wire = append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)
				for len(wire) > 0 {
					n, err := conn.Write(wire)
					if err != nil {
						return
					}
					wire = wire[n:]
				}
			}()
		}
	})
	t.Cleanup(func() { cancel(); _ = udp.Close(); _ = tcp.Close(); workers.Wait(); close(queries) })
	return address, queries
}

func TestLookupCNAME(t *testing.T) {
	tests := map[string]struct {
		hops    int
		inline  bool
		loop    bool
		wantErr string
	}{
		"single response":    {hops: 3, inline: true},
		"separate responses": {hops: 3},
		"maximum inline":     {hops: 16, inline: true},
		"maximum separate":   {hops: 16},
		"inline limit":       {hops: 17, inline: true, wantErr: "exceeds 16 hops"},
		"separate limit":     {hops: 17, wantErr: "exceeds 16 hops"},
		"inline cycle":       {hops: 3, inline: true, loop: true, wantErr: "CNAME loop"},
		"separate cycle":     {hops: 3, loop: true, wantErr: "CNAME loop"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			address, _ := authoritativeServer(t, false, func(request *dns.Message) *dns.Message {
				question, _ := request.Question()
				first, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(question.Name, "alias"), ".example"))
				if err != nil {
					t.Error(err)
					return request.Succeed(nil)
				}
				answers := []dns.ResourceRecord{}
				last := min(first+1, tt.hops)
				if tt.inline {
					last = tt.hops
				}
				for i := first; i < last; i++ {
					next := fmt.Sprintf("alias%d.example", i+1)
					if tt.loop && i == tt.hops-1 {
						next = "alias0.example"
					}
					record := dns.ResourceRecord{Name: fmt.Sprintf("alias%d.example", i), Type: dns.TypeCNAME, Class: dns.ClassIN}
					if err := record.SetDomainName(next); err != nil {
						t.Error(err)
					}
					answers = append(answers, record)
				}
				if last == tt.hops && !tt.loop {
					answers = append(answers, dns.A(fmt.Sprintf("alias%d.example", tt.hops), netip.MustParseAddr("192.0.2.1"), 60))
				}
				return request.Succeed(answers)
			})
			cfg := resolverConfig{servers: []string{address.Addr().String()}, port: address.Port()}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			got, err := cfg.lookupType(ctx, "alias0.example", dns.TypeA)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("lookup = %v, %v; want %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
			if diff := gocmp.Diff(want, got, gocmp.Comparer(func(a, b netip.Addr) bool { return a == b })); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestLookupNamesAndTCP(t *testing.T) {
	tests := map[string]struct {
		query       string
		truncate    bool
		nxdomain    bool
		wantQueries []string
	}{
		"no suffix expansion": {query: "host", nxdomain: true, wantQueries: []string{"udp:host"}},
		"absolute name":       {query: "host.example", wantQueries: []string{"udp:host.example"}},
		"trailing dot":        {query: "host.example.", wantQueries: []string{"udp:host.example"}},
		"TCP fallback":        {query: "host.example", truncate: true, wantQueries: []string{"udp:host.example", "tcp:host.example"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			address, queries := authoritativeServer(t, tt.truncate, func(request *dns.Message) *dns.Message {
				question, _ := request.Question()
				if question.Name == "host.example" {
					return request.Succeed([]dns.ResourceRecord{dns.A(question.Name, netip.MustParseAddr("192.0.2.2"), 60)})
				}
				response, err := request.Fail(dns.ResponseCodeNXDOMAIN)
				if err != nil {
					t.Error(err)
				}
				return response
			})
			cfg := resolverConfig{servers: []string{address.Addr().String()}, port: address.Port()}
			got, err := cfg.lookup(t.Context(), tt.query, dns.TypeA)
			if tt.nxdomain {
				lookup, ok := errors.AsType[*lookupError](err)
				if !ok || lookup.code != dns.ResponseCodeNXDOMAIN {
					t.Fatalf("lookup = %v, %v; want NXDOMAIN", got, err)
				}
			} else if err != nil || len(got) != 1 || got[0].String() != "192.0.2.2" {
				t.Fatalf("lookup = %v, %v", got, err)
			}
			// Both address families are queried concurrently; inspect each family's names independently.
			counts := make(map[string]int)
			for len(queries) > 0 {
				counts[<-queries]++
			}
			want := make(map[string]int)
			for _, query := range tt.wantQueries {
				want[query] = 2
			}
			if diff := gocmp.Diff(want, counts); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestExchangeValidation(t *testing.T) {
	tests := map[string]struct{ change func(*dns.Message) }{
		"wrong ID":       {change: func(message *dns.Message) { message.ID ^= 1 }},
		"query response": {change: func(message *dns.Message) { message.Query = true }},
		"wrong question": {change: func(message *dns.Message) { message.Questions[0].Name = "other.example" }},
		"wrong class":    {change: func(message *dns.Message) { message.Questions[0].Class = dns.ClassCH }},
		"wrong type":     {change: func(message *dns.Message) { message.Questions[0].Type = dns.TypeAAAA }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			address, _ := authoritativeServer(t, false, func(request *dns.Message) *dns.Message {
				response := request.Succeed(nil)
				tt.change(response)
				return response
			})
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if _, err := exchange(ctx, "host.example", dns.TypeA, address.String()); err == nil {
				t.Fatal("mismatched reply accepted")
			}
		})
	}
}

func TestLookupCancelled(t *testing.T) {
	cfg := resolverConfig{hosts: map[string][]netip.Addr{"host": {netip.MustParseAddr("127.0.0.1")}}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := cfg.lookup(ctx, "host", dns.TypeA); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled lookup = %v", err)
	}
}
