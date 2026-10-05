// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package nextlayer chooses protocol layer stacks from connection metadata and buffered bytes.
package nextlayer

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"maps"
	"regexp"
	"strconv"
	"time"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/filter/regex"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/options"
	"github.com/zchee/mitmproxy-go/tlsparse"
)

const sniffLimit = 64 << 10

var (
	errNeedsMoreData = errors.New("nextlayer: incomplete protocol header")
	httpPrefix       = regexp.MustCompile(`^[A-Za-z]{3,}.+[Hh][Tt][Tt][Pp]/`)
	hostHeader       = regexp.MustCompile(`\r\n(?:[Hh][Oo][Ss][Tt]:[ \t\n\r\f\v]+(.+?)[ \t\n\r\f\v]*)?\r\n`)
	hostPort         = regexp.MustCompile(`:\p{Nd}+$`)
)

// NextLayer selects the next protocol stack. Its hooks must run within an
// addon.Manager dispatch domain; it never performs network I/O.
type NextLayer struct {
	opts         *options.Manager
	hosts        map[string][]regex.Matcher
	logger       *slog.Logger
	matchTimeout time.Duration
}

// New returns a layer selection addon using opts, whose core options include
// ignore_hosts, allow_hosts, tcp_hosts, udp_hosts, rawtcp and show_ignored_hosts.
func New(opts *options.Manager) *NextLayer {
	return &NextLayer{opts: opts, hosts: make(map[string][]regex.Matcher), matchTimeout: regex.MatchTimeout}
}

// Configure compiles host patterns before replacing the active configuration.
// Invalid patterns return an options error and leave all compiled lists intact.
func (a *NextLayer) Configure(_ context.Context, updated map[string]struct{}) error {
	next := maps.Clone(a.hosts)
	_, ignoreChanged := updated["ignore_hosts"]
	_, allowChanged := updated["allow_hosts"]
	for _, name := range []string{"ignore_hosts", "allow_hosts", "tcp_hosts", "udp_hosts"} {
		_, changed := updated[name]
		if name == "ignore_hosts" || name == "allow_hosts" {
			changed = ignoreChanged || allowChanged
		}
		if !changed {
			continue
		}
		patterns := a.opts.Seq(name)
		compiled := make([]regex.Matcher, 0, len(patterns))
		for _, pattern := range patterns {
			m, err := regex.Compile(pattern, regex.IgnoreCase)
			if err != nil {
				return options.Errorf("Invalid %s pattern: %v", name, err)
			}
			compiled = append(compiled, m)
		}
		next[name] = compiled
	}
	a.hosts = next
	return nil
}

func (a *NextLayer) log() *slog.Logger {
	if a.logger != nil {
		return a.logger
	}
	return slog.Default()
}

// NextLayer preserves an existing decision or selects an outermost-first stack.
// Incomplete HTTP or TLS sniffing leaves Layer nil for the caller to retry.
// Sniffing that reaches the buffer limit falls back to raw TCP with a warning.
func (a *NextLayer) NextLayer(ctx context.Context, d *hookdata.NextLayer) error {
	if d.Layer != nil {
		return nil
	}
	if d.Context == nil || d.Context.Client == nil || d.Context.Server == nil {
		return errors.New("nextlayer: missing connection context")
	}
	if d.Context.Client.TransportProtocol != connection.TCP {
		return nil
	}
	if len(d.DataClient) >= sniffLimit {
		a.sniffFallback(ctx, d)
		return nil
	}
	stack, err := a.choose(ctx, d)
	switch {
	case errors.Is(err, tlsparse.ErrTooLarge):
		a.sniffFallback(ctx, d)
	case errors.Is(err, errNeedsMoreData):
		a.log().DebugContext(ctx, "Deferring layer decision, not enough data", "client_bytes", len(d.DataClient))
	case err != nil:
		return err
	default:
		d.Layer = stack
	}
	return nil
}

func (a *NextLayer) sniffFallback(ctx context.Context, d *hookdata.NextLayer) {
	a.log().WarnContext(ctx, "Protocol sniff limit reached; falling back to raw TCP", "limit", sniffLimit)
	d.Layer = hookdata.LayerStack{{Kind: hookdata.LayerTCP}}
}

func (a *NextLayer) choose(ctx context.Context, d *hookdata.NextLayer) (hookdata.LayerStack, error) {
	c := d.Context
	isTLS := tlsparse.StartsLikeTLSRecord(d.DataClient)
	var hello *tlsparse.ClientHello
	var incomplete bool
	if isTLS {
		var err error
		hello, err = tlsparse.ParseClientHello(d.DataClient)
		if errors.Is(err, tlsparse.ErrTooLarge) {
			return nil, err
		}
		incomplete = err == nil && hello == nil
	}
	ignored, err := a.ignoreConnection(ctx, d, hello, incomplete)
	if err != nil {
		return nil, err
	}
	if ignored {
		return hookdata.LayerStack{{Kind: hookdata.LayerTCP, Ignore: !a.opts.Bool("show_ignored_hosts")}}, nil
	}

	if len(c.Layers) == 1 {
		if top, ok := c.Layers[0].(interface{ Kind() hookdata.LayerKind }); ok {
			switch top.Kind() {
			case hookdata.LayerReverse:
				return reverseStack(c.Client.ProxyMode, isTLS)
			case hookdata.LayerRegular, hookdata.LayerUpstream:
				mode := hookdata.HTTPModeRegular
				if top.Kind() == hookdata.LayerUpstream {
					mode = hookdata.HTTPModeUpstream
				}
				stack := make(hookdata.LayerStack, 0, 2)
				if isTLS {
					stack = append(stack, hookdata.LayerSpec{Kind: hookdata.LayerClientTLS})
				}
				return append(stack, hookdata.LayerSpec{Kind: hookdata.LayerHTTP, HTTPMode: mode}), nil
			}
		}
	}
	if isTLS {
		return hookdata.LayerStack{{Kind: hookdata.LayerServerTLS}, {Kind: hookdata.LayerClientTLS}}, nil
	}
	for _, pattern := range a.hosts["tcp_hosts"] {
		if c.Server.Address != nil && a.matchHost(ctx, "tcp_hosts", pattern, c.Server.Address.Host) ||
			c.Client.SNI != nil && a.matchHost(ctx, "tcp_hosts", pattern, *c.Client.SNI) {
			return hookdata.LayerStack{{Kind: hookdata.LayerTCP}}, nil
		}
	}
	switch string(c.Client.ALPN) {
	case "h2", "http/1.1", "http/1.0", "http/0.9":
		return hookdata.LayerStack{{Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeTransparent}}, nil
	}
	space := bytes.IndexByte(d.DataClient, ' ')
	probablyNotHTTP := len(d.DataClient) < 3 || space < 0 || space > bytes.IndexByte(d.DataClient, '\n') ||
		!asciiAlpha(d.DataClient[:3]) || len(d.DataServer) != 0 || bytes.HasPrefix(d.DataClient, []byte("SSH"))
	if a.opts.Bool("rawtcp") && probablyNotHTTP {
		return hookdata.LayerStack{{Kind: hookdata.LayerTCP}}, nil
	}
	return hookdata.LayerStack{{Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeTransparent}}, nil
}

func (a *NextLayer) ignoreConnection(ctx context.Context, d *hookdata.NextLayer, hello *tlsparse.ClientHello, incomplete bool) (bool, error) {
	if len(a.hosts["ignore_hosts"]) == 0 && len(a.hosts["allow_hosts"]) == 0 {
		return false, nil
	}
	c := d.Context
	hosts := make([]string, 0, 5)
	if peer := c.Server.Peername; peer != nil {
		hosts = append(hosts, peer.Host+":"+strconv.Itoa(peer.Port))
	}
	if address := c.Server.Address; address != nil {
		port := ":" + strconv.Itoa(address.Port)
		hosts = append(hosts, address.Host+port)
		if len(d.DataServer) == 0 && httpPrefix.Match(d.DataClient) {
			match := hostHeader.FindSubmatch(d.DataClient)
			if match == nil {
				return false, errNeedsMoreData
			}
			if len(match[1]) != 0 {
				host := string(match[1])
				if !hostPort.MatchString(host) {
					host += port
				}
				hosts = append(hosts, host)
			}
		}
		if incomplete {
			return false, errNeedsMoreData
		}
		if hello != nil && hello.SNI() != "" {
			hosts = append(hosts, hello.SNI()+port)
		}
		if c.Client.SNI != nil && *c.Client.SNI != "" {
			hosts = append(hosts, *c.Client.SNI+port)
		}
	}
	if len(hosts) == 0 {
		return false, nil
	}
	if patterns := a.hosts["allow_hosts"]; len(patterns) != 0 {
		allowed := false
		for _, host := range hosts {
			for _, pattern := range patterns {
				if a.matchHost(ctx, "allow_hosts", pattern, host) {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}
		if !allowed {
			return true, nil
		}
	}
	for _, host := range hosts {
		for _, pattern := range a.hosts["ignore_hosts"] {
			if a.matchHost(ctx, "ignore_hosts", pattern, host) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (a *NextLayer) matchHost(ctx context.Context, option string, pattern regex.Matcher, host string) bool {
	matched, abandoned := regex.MatchStringReportTimeout(pattern, host, a.matchTimeout)
	if abandoned {
		a.log().WarnContext(ctx, "Host pattern match abandoned", "option", option, "pattern", pattern.Pattern(), "host", host)
		return option == "ignore_hosts"
	}
	return matched
}

func reverseStack(spec string, clientTLS bool) (hookdata.LayerStack, error) {
	mode, err := modespec.Parse(spec)
	if err != nil {
		return nil, err
	}
	reverse, ok := mode.(modespec.ReverseMode)
	if !ok {
		return nil, errors.New("nextlayer: reverse layer requires a reverse proxy mode")
	}
	var app hookdata.LayerSpec
	switch reverse.Scheme {
	case "http", "https":
		app = hookdata.LayerSpec{Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeTransparent}
	case "tcp", "tls":
		app = hookdata.LayerSpec{Kind: hookdata.LayerTCP}
	default:
		return nil, nil
	}
	stack := make(hookdata.LayerStack, 0, 3)
	if reverse.Scheme == "https" || reverse.Scheme == "tls" {
		stack = append(stack, hookdata.LayerSpec{Kind: hookdata.LayerServerTLS})
	}
	if clientTLS {
		stack = append(stack, hookdata.LayerSpec{Kind: hookdata.LayerClientTLS})
	}
	return append(stack, app), nil
}

func asciiAlpha(data []byte) bool {
	for _, b := range data {
		if (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') {
			return false
		}
	}
	return true
}
