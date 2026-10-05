// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package block filters client connections by their source IP address.
package block

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/options"
)

// Block rejects public or private client addresses according to its options.
type Block struct{ options *options.Manager }

// New returns a connection filter using opts.
func New(opts *options.Manager) *Block { return &Block{options: opts} }

// Load registers the upstream block_global and block_private options.
func (b *Block) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "block_global", options.TypeBool, true, "Block connections from public IP addresses."); err != nil {
		return err
	}
	return loader.AddOption(ctx, "block_private", options.TypeBool, false, "Block connections from local (private) IP addresses. This option does not affect loopback addresses (connections from the local machine), which are always permitted.")
}

// ClientConnected marks disallowed connections with an error. Loopback clients
// and local interception mode are always allowed.
func (b *Block) ClientConnected(ctx context.Context, client *connection.Client) error {
	if client.Peername == nil {
		return fmt.Errorf("block: missing client address")
	}
	host, _, _ := strings.Cut(client.Peername.Host, "%")
	address, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	address = address.Unmap()
	if address.IsLoopback() {
		return nil
	}
	mode, err := modespec.Parse(client.ProxyMode)
	if err == nil && mode.Name() == "local" {
		return nil
	}
	private := isPrivate(address)
	global := !private && !shared.Contains(address)
	option := ""
	if b.options.Bool("block_private") && private {
		option = "block_private"
	}
	if b.options.Bool("block_global") && global {
		option = "block_global"
	}
	if option != "" {
		slog.WarnContext(ctx, fmt.Sprintf("Client connection from %s killed by %s option.", client.Peername.Host, option))
		client.Error = new("Connection killed by " + option + ".")
	}
	return nil
}

// Python ipaddress defines private as not globally reachable, not merely RFC
// 1918 or unique-local. These IANA ranges include its special-use exceptions.
var (
	shared          = netip.MustParsePrefix("100.64.0.0/10")
	privateNetworks = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("::/128"), netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	}
	privateExceptions = []netip.Prefix{
		netip.MustParsePrefix("192.0.0.9/32"), netip.MustParsePrefix("192.0.0.10/32"),
		netip.MustParsePrefix("2001:1::1/128"), netip.MustParsePrefix("2001:1::2/128"), netip.MustParsePrefix("2001:3::/32"),
		netip.MustParsePrefix("2001:4:112::/48"), netip.MustParsePrefix("2001:20::/28"), netip.MustParsePrefix("2001:30::/28"),
	}
)

func isPrivate(address netip.Addr) bool {
	contains := func(prefix netip.Prefix) bool { return prefix.Contains(address) }
	return slices.ContainsFunc(privateNetworks, contains) && !slices.ContainsFunc(privateExceptions, contains)
}
