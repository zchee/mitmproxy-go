// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package stickyauth carries Authorization headers onto matching later requests.
package stickyauth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

const (
	maxJarBytes = 16 << 20
	maxJarHosts = 100_000
)

// StickyAuth retains Authorization values by exact host, independent of port and
// scheme. Its jar retains at most 100,000 hosts and 16 MiB of string bytes.
// Overflow drops growing writes and warns once until an overwrite releases bytes.
// All mutable state is confined to addon dispatch.
type StickyAuth struct {
	options  *options.Manager
	flt      filter.Expr
	hosts    map[string]string
	bytes    int
	overflow bool
}

// New returns a sticky authentication addon using opts.
func New(opts *options.Manager) *StickyAuth {
	return &StickyAuth{options: opts, hosts: make(map[string]string)}
}

// Name returns the upstream addon name.
func (*StickyAuth) Name() string { return "stickyauth" }

// Load registers the upstream stickyauth filter option.
func (*StickyAuth) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "stickyauth", options.TypeOptStr, (*string)(nil), "Set sticky auth filter. Matched against requests.")
}

// Configure updates the filter without discarding retained Authorization values.
func (s *StickyAuth) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, changed := updated["stickyauth"]; !changed {
		return nil
	}
	s.flt = nil
	pattern := s.options.OptStr("stickyauth")
	if pattern == nil || *pattern == "" {
		return nil
	}
	parsed, err := filter.Parse(*pattern)
	if err != nil {
		return options.Errorf("%v", err)
	}
	s.flt = parsed
	return nil
}

// Request stores explicit Authorization whenever enabled, even when the request
// filter does not match. Otherwise, a matching request reuses the exact host's value.
func (s *StickyAuth) Request(ctx context.Context, f *flow.HTTPFlow) error {
	if s.flt == nil {
		return nil
	}
	host := f.Request.Host
	if f.Request.Headers.Has("authorization") {
		value := f.Request.Headers.Get("authorization")
		old, exists := s.hosts[host]
		delta := len(value) - len(old)
		if !exists {
			delta += len(host)
		}
		if (!exists && len(s.hosts) >= maxJarHosts) || delta > maxJarBytes-s.bytes || (s.overflow && delta > 0) {
			if !s.overflow {
				slog.WarnContext(ctx, fmt.Sprintf("stickyauth: jar limit reached (%d hosts, %d); growing writes are not retained until an overwrite releases bytes", len(s.hosts), s.bytes))
				s.overflow = true
			}
			return nil
		}
		s.hosts[strings.Clone(host)] = strings.Clone(value)
		s.bytes += delta
		if delta < 0 {
			s.overflow = false
		}
	} else if filter.Match(s.flt, f) {
		if value, ok := s.hosts[host]; ok {
			f.Request.Headers.Set("authorization", value)
		}
	}
	return nil
}

var (
	_ addon.LoadHandler      = (*StickyAuth)(nil)
	_ addon.ConfigureHandler = (*StickyAuth)(nil)
	_ addon.RequestHandler   = (*StickyAuth)(nil)
)
