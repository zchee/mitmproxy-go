// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

type pairDomain struct {
	bounds    portRange
	excluded  []portRange
	available bool
}

type pairListeners struct {
	listen       func(context.Context, string, string) (net.Listener, error)
	listenPacket func(context.Context, string, string) (net.PacketConn, error)
	domain       func(context.Context) (pairDomain, error)
	retryable    func(error) bool
	choose       func(int) (int, error)
	randomIPv6   bool
}

// ListenPair acquires live TCP and UDP sockets on the same host and port.
// Network must be tcp4 or tcp6, and address must contain an explicit
// family-compatible host and a numeric port. The caller owns both sockets.
// Only port zero permits reselection, with at most 64 candidate acquisitions.
// Every partial pair is closed before retrying or returning an error.
// On Windows IPv4, readable dynamic and excluded ranges constrain selection.
// Windows IPv6 and unavailable IPv4 bounds use distinct randomized IANA
// dynamic-range candidates; IPv4 discovery is never applied to IPv6.
// Exhaustion errors include candidate and per-protocol bind tallies.
// Context cancellation stops waiting for shared discovery without duplicating
// its bounded background worker; it does not close successfully returned sockets.
func ListenPair(ctx context.Context, network, address string) (net.Listener, *net.UDPConn, error) {
	lc := new(net.ListenConfig)
	return listenPair(ctx, network, address, pairListeners{
		listen:       lc.Listen,
		listenPacket: lc.ListenPacket,
		domain:       pairPortDomain,
		retryable:    retryablePairBind,
		randomIPv6:   randomIPv6PairCandidates,
	})
}

func listenPair(ctx context.Context, network, address string, lc pairListeners) (net.Listener, *net.UDPConn, error) {
	host, port, err := resolvePairAddress(ctx, network, address)
	if err != nil {
		return nil, nil, &net.OpError{Op: "listen", Net: network, Err: err}
	}
	udpNetwork := "udp" + network[3:]
	var candidates []int
	var domain pairDomain
	if port == 0 && network == "tcp4" && lc.domain != nil {
		domain, err = lc.domain(ctx)
		if err != nil {
			return nil, nil, &net.OpError{Op: "listen", Net: network, Err: err}
		}
		candidates, err = portCandidates(domain)
		if err != nil {
			return nil, nil, &net.OpError{Op: "listen", Net: network, Err: err}
		}
	}
	if port == 0 && network == "tcp6" && lc.randomIPv6 {
		// Sequential native ports can all fall inside one UDP-excluded block.
		// Spread IPv6 bind checks across the IANA range without IPv4 discovery.
		candidates, err = portCandidates(pairDomain{bounds: portRange{first: 49152, last: 65535}})
		if err != nil {
			return nil, nil, &net.OpError{Op: "listen", Net: network, Err: err}
		}
	}
	limit := attempts
	if port != 0 {
		limit = 1
	} else if candidates != nil {
		limit = min(limit, len(candidates))
	}
	var last error
	stopped := false
	tcpBinds, udpBinds := 0, 0
	// Native :0 cannot prefilter the kernel's choice. Bound probes independently
	// so readable exclusions cannot cause unbounded socket acquisition.
	for range limit {
		if err := ctx.Err(); err != nil {
			return nil, nil, &net.OpError{Op: "listen", Net: network, Err: err}
		}
		candidate := port
		if candidates != nil {
			candidate, err = takePortCandidate(&candidates, lc.choose)
			if err != nil {
				return nil, nil, &net.OpError{Op: "listen", Net: network, Err: err}
			}
		}
		tcpBinds++
		tcp, err := lc.listen(ctx, network, net.JoinHostPort(host, strconv.Itoa(candidate)))
		if err == nil {
			tcpAddress, ok := tcp.Addr().(*net.TCPAddr)
			if !ok {
				_ = tcp.Close()
				return nil, nil, &net.OpError{Op: "listen", Net: network, Err: errors.New("TCP listener returned a non-TCP address")}
			}
			if candidate == 0 && inPortRanges(tcpAddress.Port, domain.excluded) {
				_ = tcp.Close()
				last = fmt.Errorf("native ephemeral probe selected excluded port %d", tcpAddress.Port)
				continue
			}
			var packet net.PacketConn
			if err = ctx.Err(); err == nil {
				udpBinds++
				packet, err = lc.listenPacket(ctx, udpNetwork, tcpAddress.String())
			}
			if err == nil {
				udp, ok := packet.(*net.UDPConn)
				if !ok {
					_ = packet.Close()
					_ = tcp.Close()
					return nil, nil, &net.OpError{Op: "listen", Net: udpNetwork, Err: errors.New("UDP bind returned a non-UDP socket")}
				}
				if err = ctx.Err(); err == nil {
					return tcp, udp, nil
				}
				_ = udp.Close()
			}
			_ = tcp.Close()
		}
		last = err
		if port != 0 || !lc.retryable(err) {
			stopped = true
			break
		}
	}
	if err := ctx.Err(); err != nil {
		last = err
	} else if !stopped && tcpBinds == limit {
		last = fmt.Errorf("paired acquisition exhausted: candidates=%d TCP_binds=%d UDP_binds=%d: %w", tcpBinds, tcpBinds, udpBinds, last)
	}
	return nil, nil, &net.OpError{Op: "listen", Net: network, Err: last}
}

func portCandidates(domain pairDomain) ([]int, error) {
	if !domain.available && domain.bounds == (portRange{}) {
		return nil, nil
	}
	if domain.bounds.first < 1 || domain.bounds.last > 65535 {
		return nil, errors.New("invalid TCP/UDP dynamic-range bounds")
	}
	var candidates []int
	for candidate := domain.bounds.first; candidate <= domain.bounds.last; candidate++ {
		if !inPortRanges(candidate, domain.excluded) {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("no unexcluded port in the TCP/UDP dynamic-range intersection")
	}
	return candidates, nil
}

func takePortCandidate(candidates *[]int, choose func(int) (int, error)) (int, error) {
	var selected int
	var err error
	if choose != nil {
		selected, err = choose(len(*candidates))
	} else {
		var index *big.Int
		index, err = rand.Int(rand.Reader, big.NewInt(int64(len(*candidates))))
		if err == nil {
			selected = int(index.Int64())
		}
	}
	if err != nil {
		return 0, err
	}
	if selected < 0 || selected >= len(*candidates) {
		return 0, errors.New("candidate selector returned an invalid index")
	}
	candidate := (*candidates)[selected]
	(*candidates)[selected] = (*candidates)[len(*candidates)-1]
	*candidates = (*candidates)[:len(*candidates)-1]
	return candidate, nil
}

func resolvePairAddress(ctx context.Context, network, address string) (string, int, error) {
	if network != "tcp4" && network != "tcp6" {
		return "", 0, net.UnknownNetworkError(network)
	}
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	host, number, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(number)
	if err != nil || port < 0 || port > 65535 || number == "" || host == "" {
		return "", 0, &net.AddrError{Err: "explicit host and numeric port required", Addr: address}
	}
	for _, digit := range number {
		if digit < '0' || digit > '9' {
			return "", 0, &net.AddrError{Err: "numeric port required", Addr: address}
		}
	}
	ip, parseErr := netip.ParseAddr(host)
	if parseErr != nil {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip"+network[3:], host)
		if err != nil {
			return "", 0, err
		}
		if len(ips) == 0 {
			return "", 0, &net.AddrError{Err: "no address for requested family", Addr: address}
		}
		ip = ips[0]
	}
	if (network == "tcp4") != ip.Is4() || network == "tcp6" && ip.Is4In6() {
		return "", 0, &net.AddrError{Err: "host does not match requested family", Addr: address}
	}
	return ip.String(), port, nil
}

func newPairDiscovery(discover func() pairDomain) func(context.Context) (pairDomain, error) {
	var domain pairDomain
	start := sync.OnceValue(func() <-chan struct{} {
		done := make(chan struct{})
		go func() {
			domain = discover()
			close(done)
		}()
		return done
	})
	return func(ctx context.Context) (pairDomain, error) {
		if err := ctx.Err(); err != nil {
			return pairDomain{}, err
		}
		select {
		case <-ctx.Done():
			return pairDomain{}, ctx.Err()
		case <-start():
			if err := ctx.Err(); err != nil {
				return pairDomain{}, err
			}
			return domain, nil
		}
	}
}

func parseDynamicPorts(output string) (portRange, error) {
	values := make([]int, 0, 2)
	for line := range strings.SplitSeq(output, "\n") {
		_, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		number, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return portRange{}, fmt.Errorf("invalid dynamic port bounds: %q", line)
		}
		values = append(values, number)
	}
	if len(values) != 2 || values[0] < 1 || values[0] > 65535 || values[1] < 1 || values[1] > 65536-values[0] {
		return portRange{}, errors.New("invalid dynamic port range")
	}
	return portRange{first: values[0], last: values[0] + values[1] - 1}, nil
}
