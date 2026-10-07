// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/zchee/mitmproxy-go/dns"
)

func canonicalName(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

func (cfg *resolverConfig) lookupIP(ctx context.Context, name string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// mitmproxy passes explicit servers; system search options are inert.
	return cfg.lookupAbsolute(ctx, strings.TrimSuffix(name, "."))
}

func (cfg *resolverConfig) lookupAbsolute(ctx context.Context, name string) ([]netip.Addr, error) {
	type result struct {
		typ       int
		addresses []netip.Addr
		err       error
	}
	results := make(chan result, 2)
	for _, typ := range []int{dns.TypeA, dns.TypeAAAA} {
		go func() { ips, err := cfg.lookupType(ctx, name, typ); results <- result{typ, ips, err} }()
	}
	var ipv4, ipv6 []netip.Addr
	var error4, error6 error
	for range 2 {
		result := <-results
		if result.typ == dns.TypeA {
			ipv4, error4 = result.addresses, result.err
		} else {
			ipv6, error6 = result.addresses, result.err
		}
	}
	addresses := append(ipv4, ipv6...)
	if len(addresses) == 0 {
		if error4 != nil {
			return nil, error4
		}
		if error6 != nil {
			return nil, error6
		}
	}
	interleave(addresses)
	return addresses, nil
}

// interleave retains the pinned resolver's swap ordering, starting with IPv4.
func interleave(addresses []netip.Addr) {
	lookahead, expects := 1, true
	for i := 0; i < len(addresses); {
		if addresses[i].Is4() == expects {
			i++
			expects = !expects
			lookahead = i + 1
			continue
		}
		for lookahead < len(addresses) && addresses[lookahead].Is4() != expects {
			lookahead++
		}
		if lookahead == len(addresses) {
			break
		}
		addresses[i], addresses[lookahead] = addresses[lookahead], addresses[i]
		lookahead++
		i += 2
	}
}

func (cfg *resolverConfig) lookupType(ctx context.Context, name string, typ int) ([]netip.Addr, error) {
	seen := map[string]struct{}{canonicalName(name): {}}
	hops := 0
	for {
		key := canonicalName(name)
		var response *dns.Message
		var err error
		for _, server := range cfg.servers {
			response, err = exchange(ctx, name, typ, net.JoinHostPort(server, strconv.Itoa(int(cfg.port))))
			if err == nil && response.ResponseCode != dns.ResponseCodeSERVFAIL {
				break
			}
		}
		if err != nil {
			return nil, err
		}
		if response.ResponseCode != dns.ResponseCodeNOERROR {
			return nil, &lookupError{code: response.ResponseCode}
		}
		var addresses []netip.Addr
		target := name
		for range len(response.Answers) + 1 {
			changed := false
			for i := range response.Answers {
				record := &response.Answers[i]
				if record.Class != dns.ClassIN || canonicalName(record.Name) != canonicalName(target) {
					continue
				}
				if record.Type == typ {
					ip, ok := netip.AddrFromSlice(record.Data)
					if !ok || typ == dns.TypeA && !ip.Is4() || typ == dns.TypeAAAA && !ip.Is6() {
						return nil, errors.New("invalid DNS address record")
					}
					addresses = append(addresses, ip)
				} else if record.Type == dns.TypeCNAME {
					next, err := record.DomainName()
					if err != nil {
						return nil, err
					}
					if _, exists := seen[canonicalName(next)]; exists {
						return nil, errors.New("DNS CNAME loop")
					}
					if hops == 16 {
						return nil, errors.New("DNS CNAME chain exceeds 16 hops")
					}
					hops++
					seen[canonicalName(next)] = struct{}{}
					target = next
					changed = true
					break
				}
			}
			if len(addresses) > 0 {
				return addresses, nil
			}
			if !changed {
				break
			}
		}
		if canonicalName(target) == key {
			return nil, nil
		}
		name = target
	}
}

func exchange(ctx context.Context, name string, typ int, address string) (*dns.Message, error) {
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	query := &dns.Message{ID: int(binary.BigEndian.Uint16(id[:])), Query: true, RecursionDesired: true, Questions: []dns.Question{{Name: name, Type: typ, Class: dns.ClassIN}}}
	wire, err := dns.Pack(query)
	if err != nil {
		return nil, err
	}
	for _, network := range []string{"udp", "tcp"} {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		response, err := exchangeConn(ctx, conn, wire, network == "tcp")
		_ = conn.Close()
		if err != nil {
			return nil, err
		}
		if response.ID != query.ID || response.Query || response.OpCode != query.OpCode {
			return nil, errors.New("DNS response does not match query")
		}
		q, ok := response.Question()
		if !ok || canonicalName(q.Name) != canonicalName(name) || q.Type != typ || q.Class != dns.ClassIN {
			return nil, errors.New("DNS response question does not match query")
		}
		if !response.Truncation {
			return response, nil
		}
	}
	return nil, errors.New("truncated DNS TCP response")
}

func exchangeConn(ctx context.Context, conn net.Conn, wire []byte, tcp bool) (*dns.Message, error) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if tcp {
		wire = append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)
	}
	for len(wire) > 0 {
		n, err := conn.Write(wire)
		if err != nil {
			return nil, err
		}
		if n == 0 || !tcp && n != len(wire) {
			return nil, io.ErrShortWrite
		}
		wire = wire[n:]
	}
	var data []byte
	if tcp {
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		data = make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, err := io.ReadFull(conn, data); err != nil {
			return nil, err
		}
	} else {
		data = make([]byte, 65535)
		n, err := conn.Read(data)
		if err != nil {
			return nil, err
		}
		data = data[:n]
	}
	return dns.Unpack(data, nil)
}
