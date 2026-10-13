// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/netutil/freeport"
)

type dnsSocketPair struct {
	tcp        net.Listener
	udp        *net.UDPConn
	address    string
	tcpRequest string
}

func acquireDNSSockets(t *testing.T, network, address string) *dnsSocketPair {
	t.Helper()
	tcp, udp, err := freeport.ListenPair(t.Context(), network, address)
	if err != nil {
		t.Fatal(err)
	}
	pair := &dnsSocketPair{tcp: tcp, udp: udp, address: tcp.Addr().String()}
	t.Cleanup(pair.close)
	if diff := gocmp.Diff(pair.address, udp.LocalAddr().String()); diff != "" {
		t.Fatalf("DNS paired address (-TCP +UDP):\n%s", diff)
	}
	return pair
}

func prepareDNSSockets(t *testing.T, instance *Instance) *dnsSocketPair {
	t.Helper()
	network := "tcp4"
	if net.ParseIP(instance.host).To4() == nil {
		network = "tcp6"
	}
	address := net.JoinHostPort(instance.host, strconv.Itoa(instance.port))
	pair := acquireDNSSockets(t, network, address)
	pair.tcpRequest = address
	// The fixture already chose the port, so product selection must not rewrite the request.
	instance.portCandidates = nil
	instance.listenTCP = pair.listenTCP
	instance.listenUDP = pair.listenUDP
	return pair
}

func (p *dnsSocketPair) listenTCP(ctx context.Context, network, address string) (net.Listener, error) {
	if network != "tcp" || address != p.tcpRequest {
		return nil, fmt.Errorf("DNS TCP bind mismatch: %s %s, want tcp %s", network, address, p.tcpRequest)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.tcp == nil {
		return nil, errors.New("DNS TCP socket already transferred or closed")
	}
	listener := p.tcp
	p.tcp = nil
	return listener, nil
}

func (p *dnsSocketPair) listenUDP(ctx context.Context, network, address string) (net.PacketConn, error) {
	if network != "udp" || address != p.address {
		return nil, fmt.Errorf("DNS UDP bind mismatch: %s %s, want udp %s", network, address, p.address)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.udp == nil {
		return nil, errors.New("DNS UDP socket already transferred or closed")
	}
	socket := p.udp
	p.udp = nil
	return socket, nil
}

func (p *dnsSocketPair) close() {
	if p.tcp != nil {
		_ = p.tcp.Close()
		p.tcp = nil
	}
	if p.udp != nil {
		_ = p.udp.Close()
		p.udp = nil
	}
}

func (p *dnsSocketPair) start(ctx context.Context, instance *Instance) error {
	// Start owns transferred sockets even on failure; close only the unconsumed mates.
	defer p.close()
	return instance.Start(ctx)
}

func startDNSInstance(t *testing.T, instance *Instance) {
	t.Helper()
	pair := prepareDNSSockets(t, instance)
	if err := pair.start(t.Context(), instance); err != nil {
		t.Fatal(err)
	}
	for _, address := range instance.ListenAddrs() {
		if diff := gocmp.Diff(pair.address, address.String()); diff != "" {
			t.Fatalf("DNS listener address (-acquired +published):\n%s", diff)
		}
	}
}
