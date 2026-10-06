// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package stickycookie carries server cookies onto matching later requests.
package stickycookie

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/omap"
	"github.com/zchee/mitmproxy-go/options"
)

const (
	maxJarBytes   = 16 << 20
	maxJarCookies = 100_000
)

// Python cookiejar excludes every hostname ending in a dot and ASCII digits,
// not just valid IPv4 addresses. Its dollar anchor also permits a final newline.
var ipv4Suffix = regexp.MustCompile(`\.[0-9]+(?:\n)?$`)

type origin struct {
	domain string
	port   int
	path   string
}

func (o origin) key() string {
	return fmt.Sprintf("%d:%s:%d:%s", len(o.domain), o.domain, o.port, o.path)
}

type entry struct {
	origin  origin
	cookies omap.Map[*string]
}

// StickyCookie retains cookies in domain/port/path and cookie insertion order.
// Its jar holds at most 100,000 cookies and 16 MiB of retained string bytes.
// Overflow drops growing writes and warns once until deletion frees capacity.
// All mutable state is confined to addon dispatch.
type StickyCookie struct {
	options      *options.Manager
	flt          filter.Expr
	jar          omap.Map[*entry]
	bytes, count int
	overflow     bool
}

// New returns a sticky cookie addon using opts.
func New(opts *options.Manager) *StickyCookie { return &StickyCookie{options: opts} }

// Name returns the upstream addon name.
func (*StickyCookie) Name() string { return "stickycookie" }

// Load registers the upstream stickycookie filter option.
func (*StickyCookie) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "stickycookie", options.TypeOptStr, (*string)(nil), "Set sticky cookie filter. Matched against requests.")
}

// Configure updates the filter without discarding the retained jar.
func (s *StickyCookie) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, changed := updated["stickycookie"]; !changed {
		return nil
	}
	s.flt = nil
	pattern := s.options.OptStr("stickycookie")
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

func domainMatch(a, b string) bool {
	lower := cases.Lower(language.Und)
	a = lower.String(a)
	b = lower.String(b)
	for _, domain := range []string{b, strings.Trim(b, ".")} {
		if a == domain {
			return true
		}
		if a == "" || strings.HasPrefix(a, ".") || strings.HasSuffix(a, ".") || ipv4Suffix.MatchString(a) {
			continue
		}
		if strings.LastIndex(a, domain) <= 0 || !strings.HasPrefix(domain, ".") {
			continue
		}
		suffix := domain[1:]
		if suffix != "" && !strings.HasPrefix(suffix, ".") && !strings.HasSuffix(suffix, ".") && !ipv4Suffix.MatchString(suffix) {
			return true
		}
	}
	return false
}

func ckey(attrs httpmsg.CookieAttrs, f *flow.HTTPFlow) origin {
	o := origin{domain: f.Request.Host, port: f.Request.Port, path: "/"}
	if value, ok := attrs.Lookup("domain"); ok && value != nil {
		o.domain = *value
	}
	if value, ok := attrs.Lookup("path"); ok && value != nil {
		o.path = *value
	}
	return o
}

func valueSize(v *string) int {
	if v == nil {
		return 0
	}
	return len(*v)
}

func (s *StickyCookie) warnLimit(ctx context.Context) {
	if !s.overflow {
		slog.WarnContext(ctx, fmt.Sprintf("stickycookie: jar limit reached (%d cookies, %d); new cookies are not retained until existing ones expire or are deleted", s.count, s.bytes))
		s.overflow = true
	}
}

// Response stores matching-domain cookies whenever the feature is enabled.
// The request filter is deliberately not evaluated on responses; Secure is not
// enforced and path matching later is a simple prefix, as upstream specifies.
func (s *StickyCookie) Response(ctx context.Context, f *flow.HTTPFlow) error {
	if f.Response == nil {
		return errors.New("stickycookie: response is required")
	}
	if s.flt == nil {
		return nil
	}
	for _, cookie := range f.Response.Cookies() {
		o := ckey(cookie.Attrs, f)
		if !domainMatch(f.Request.Host, o.domain) {
			continue
		}
		key := o.key()
		e, _ := s.jar.Get(key)
		if httpmsg.CookieExpired(cookie.Attrs) {
			if e == nil {
				continue
			}
			old, found := e.cookies.Pop(cookie.Name)
			if !found {
				continue
			}
			s.count--
			s.bytes -= len(cookie.Name) + valueSize(old)
			s.overflow = false
			if e.cookies.Len() == 0 {
				s.bytes -= len(key) + len(e.origin.domain) + len(e.origin.path)
				s.jar.Delete(key)
			}
			continue
		}
		var old *string
		found := false
		if e != nil {
			old, found = e.cookies.Get(cookie.Name)
		}
		delta := valueSize(cookie.Value) - valueSize(old)
		if !found {
			delta += len(cookie.Name)
		}
		if e == nil {
			delta += len(key) + len(o.domain) + len(o.path)
		}
		if (!found && s.count >= maxJarCookies) || delta > maxJarBytes-s.bytes || (s.overflow && delta > 0) {
			s.warnLimit(ctx)
			continue
		}
		if e == nil {
			e = &entry{origin: origin{domain: strings.Clone(o.domain), port: o.port, path: strings.Clone(o.path)}}
			s.jar.Set(key, e)
		}
		var value *string
		if cookie.Value != nil {
			value = new(strings.Clone(*cookie.Value))
		}
		e.cookies.Set(strings.Clone(cookie.Name), value)
		s.bytes += delta
		if !found {
			s.count++
		}
		if delta < 0 {
			s.overflow = false
		}
	}
	return nil
}

// Request replaces the Cookie header only when retained cookies match the
// enabled filter, request domain, port and path prefix.
func (s *StickyCookie) Request(_ context.Context, f *flow.HTTPFlow) error {
	if s.flt == nil || !filter.Match(s.flt, f) {
		return nil
	}
	var parts []string
	for _, e := range s.jar.All() {
		o := e.origin
		if !domainMatch(f.Request.Host, o.domain) || f.Request.Port != o.port || !strings.HasPrefix(f.Request.Path, o.path) {
			continue
		}
		for name, value := range e.cookies.All() {
			if value == nil {
				parts = append(parts, name)
			} else {
				parts = append(parts, httpmsg.FormatCookieHeader([]httpmsg.CookiePair{{Name: name, Value: *value}}))
			}
		}
	}
	if len(parts) > 0 {
		if f.Metadata == nil {
			f.Metadata = state.NewMap(1)
		}
		f.Metadata.Set("stickycookie", true)
		f.Request.Headers.Set("cookie", strings.Join(parts, "; "))
	}
	return nil
}

var (
	_ addon.LoadHandler      = (*StickyCookie)(nil)
	_ addon.ConfigureHandler = (*StickyCookie)(nil)
	_ addon.RequestHandler   = (*StickyCookie)(nil)
	_ addon.ResponseHandler  = (*StickyCookie)(nil)
)
