// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package dnsresolver resolves address questions in DNS and WireGuard modes.
package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/options"
)

// DnsResolver answers address queries and selects the upstream for other records.
// Configuration and its cached resolver snapshot are confined to addon dispatch.
type DnsResolver struct {
	opts       *options.Manager
	logger     *slog.Logger
	generation uint64
	cached     *resolverConfig
	resolvPath string
	hostsPath  string
	port       uint16
}

type resolverConfig struct {
	servers  []string
	hosts    map[string][]netip.Addr
	useHosts bool
	port     uint16
}

// New returns a resolver using opts and logger; nil logger uses slog.Default.
// Resolver configuration is loaded lazily outside dispatch on the first query.
func New(opts *options.Manager, logger *slog.Logger) *DnsResolver {
	if logger == nil {
		logger = slog.Default()
	}
	return &DnsResolver{opts: opts, logger: logger, resolvPath: "/etc/resolv.conf", hostsPath: defaultHostsPath(), port: 53}
}

// Name returns the upstream addon name.
func (*DnsResolver) Name() string { return "dnsresolver" }

// Load registers the upstream name-server and hosts-file options.
func (*DnsResolver) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "dns_use_hosts_file", options.TypeBool, true, "Use the hosts file for DNS lookups in regular DNS mode/wireguard mode."); err != nil {
		return err
	}
	return loader.AddOption(ctx, "dns_name_servers", options.TypeSeq, []string{}, "Name servers to use for lookups in regular DNS mode/wireguard mode. Default: operating system's name servers")
}

// Configure invalidates the private resolver snapshot when its options change.
func (r *DnsResolver) Configure(_ context.Context, updated map[string]struct{}) error {
	_, hosts := updated["dns_use_hosts_file"]
	_, servers := updated["dns_name_servers"]
	if hosts || servers {
		r.generation++
		r.cached = nil
	}
	return nil
}

// DNSRequest resolves a single IN A/AAAA question or selects a forwarding server.
// Network and hosts-file I/O release dispatch; cancellation returns without edits.
func (r *DnsResolver) DNSRequest(ctx context.Context, f *flow.DNSFlow) error {
	if !shouldResolve(f) || f.Request == nil {
		return nil
	}
	request := f.Request.Clone()
	question, single := request.Question()
	addressLookup := request.Query && request.OpCode == dns.OpCodeQUERY && single && question.Class == dns.ClassIN && (question.Type == dns.TypeA || question.Type == dns.TypeAAAA)
	generation := r.generation
	cfg := r.cached
	servers := r.opts.Seq("dns_name_servers")
	useHosts := r.opts.Bool("dns_use_hosts_file")
	resolvPath, hostsPath, port := r.resolvPath, r.hostsPath, r.port
	var configErr, hostsErr, lookupErr error
	var addrs []netip.Addr
	_, err := addon.Concurrent(ctx, func(ctx context.Context) error {
		if cfg == nil {
			cfg = &resolverConfig{servers: slices.Clone(servers), useHosts: useHosts, port: port}
			if len(cfg.servers) == 0 {
				var system resolvConfig
				system, configErr = systemConfiguration(resolvPath)
				cfg.servers = system.servers
			}
			if useHosts {
				cfg.hosts, hostsErr = readHosts(hostsPath)
			}
		}
		if addressLookup && (len(cfg.servers) > 0 || cfg.useHosts) {
			addrs, lookupErr = cfg.lookup(ctx, question.Name, question.Type)
		}
		return ctx.Err()
	})
	if err != nil {
		return err
	}
	if r.generation == generation {
		r.cached = cfg
		if hostsErr != nil {
			r.logger.Warn("Failed to read hosts file", "error", hostsErr)
		}
		if configErr != nil {
			r.logger.Warn(fmt.Sprintf("Failed to get system dns servers: %v\nThe dns_name_servers option needs to be set manually.", configErr))
		}
	}
	if !shouldResolve(f) {
		return nil
	}
	if len(cfg.servers) == 0 && (!addressLookup || !cfg.useHosts) {
		f.Error = flow.NewError("Cannot resolve, dns_name_servers unknown.")
		return nil
	}
	if !addressLookup {
		f.ServerConn.Address = &connection.Address{Host: cfg.servers[0], Port: 53}
		return nil
	}
	if lookupErr != nil {
		code := dns.ResponseCodeSERVFAIL
		if e, ok := errors.AsType[*lookupError](lookupErr); ok && e.code == dns.ResponseCodeNXDOMAIN {
			code = e.code
		}
		f.Response, err = request.Fail(code)
		return err
	}
	answers := make([]dns.ResourceRecord, 0, len(addrs))
	for _, ip := range addrs {
		if question.Type == dns.TypeA {
			answers = append(answers, dns.A(question.Name, ip, dns.DefaultTTL))
		} else {
			answers = append(answers, dns.AAAA(question.Name, ip, dns.DefaultTTL))
		}
	}
	f.Response = request.Succeed(answers)
	return nil
}

func shouldResolve(f *flow.DNSFlow) bool {
	if f == nil || !f.Live || f.Response != nil || f.Error != nil || f.ClientConn == nil || f.ServerConn == nil {
		return false
	}
	mode, err := modespec.Parse(f.ClientConn.ProxyMode)
	if err != nil {
		return false
	}
	if mode.Name() == "dns" {
		return true
	}
	address := f.ServerConn.Address
	return mode.Name() == "wireguard" && address != nil && address.Host == "10.0.0.53" && address.Port == 53
}

type lookupError struct{ code int }

func (e *lookupError) Error() string { return dns.ResponseCodeToString(e.code) }

func noRecords() error {
	if runtime.GOOS == "windows" {
		return &lookupError{code: dns.ResponseCodeNXDOMAIN}
	}
	return nil
}

func (cfg *resolverConfig) lookup(ctx context.Context, name string, typ int) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(name); err == nil {
		if typ == dns.TypeA && ip.Is4() || typ == dns.TypeAAAA && ip.Is6() {
			return []netip.Addr{ip}, nil
		}
		return nil, noRecords()
	}
	addresses, found := cfg.hosts[canonicalName(name)]
	if !found {
		if len(cfg.servers) == 0 {
			var err error
			addresses, err = net.DefaultResolver.LookupNetIP(ctx, "ip", name)
			for i := range addresses {
				addresses[i] = addresses[i].Unmap()
			}
			if err != nil {
				if e, ok := errors.AsType[*net.DNSError](err); ok && e.IsNotFound {
					return nil, &lookupError{code: dns.ResponseCodeNXDOMAIN}
				}
				return nil, err
			}
		} else {
			var err error
			addresses, err = cfg.lookupIP(ctx, name)
			if err != nil {
				return nil, err
			}
		}
	}
	filtered := make([]netip.Addr, 0, len(addresses))
	for _, ip := range addresses {
		if typ == dns.TypeA && ip.Is4() || typ == dns.TypeAAAA && ip.Is6() {
			filtered = append(filtered, ip)
		}
	}
	if len(filtered) == 0 {
		return nil, noRecords()
	}
	return filtered, nil
}

var (
	_ addon.LoadHandler       = (*DnsResolver)(nil)
	_ addon.ConfigureHandler  = (*DnsResolver)(nil)
	_ addon.DNSRequestHandler = (*DnsResolver)(nil)
)
