// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"fmt"
	"strings"

	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

func (b *Bridge) statusSnapshot(ctx context.Context) contract.Status {
	opts := b.cfg.Master.Options
	text := func(name string) string {
		o, ok := opts.Lookup(name)
		if !ok {
			return ""
		}
		switch value := o.Current().(type) {
		case string:
			return value
		case *string:
			if value != nil {
				return *value
			}
		}
		return ""
	}
	flag := func(name string) bool {
		o, ok := opts.Lookup(name)
		if !ok {
			return false
		}
		value, _ := o.Current().(bool)
		return value
	}
	count := func(name string) int {
		o, ok := opts.Lookup(name)
		if !ok {
			return 0
		}
		value, _ := o.Current().([]string)
		return len(value)
	}
	s := contract.Status{Reverse: flag("view_order_reversed"), InterceptActive: flag("intercept_active"), Intercept: text("intercept"), Filter: text("view_filter"), Order: text("view_order"), ContentView: text("console_default_contentview"), StickyCookie: text("stickycookie"), StickyAuth: text("stickyauth")}
	if value, err := b.cfg.Master.Call(ctx, "view.properties.marked"); err == nil {
		s.Marked, _ = value.(bool)
	}
	if value, err := b.cfg.Master.Call(ctx, "replay.client.count"); err == nil {
		s.ClientReplay, _ = value.(int)
	}
	if value, err := b.cfg.Master.Call(ctx, "replay.server.count"); err == nil {
		s.ServerReplay, _ = value.(int)
	}
	var out strings.Builder
	if count("modify_headers") > 0 {
		out.WriteString("[Headers]")
	}
	if n := count("modify_body"); n > 0 {
		fmt.Fprintf(&out, "[%d body modifications]", n)
	}
	if s.ClientReplay > 0 {
		fmt.Fprintf(&out, "[cplayback:%d]", s.ClientReplay)
	}
	if s.ServerReplay > 0 {
		fmt.Fprintf(&out, "[splayback:%d]", s.ServerReplay)
	}
	if n := count("ignore_hosts"); n > 0 {
		fmt.Fprintf(&out, "[Ignore:%d]", n)
	} else if n := count("allow_hosts"); n > 0 {
		fmt.Fprintf(&out, "[Allow:%d]", n)
	}
	if n := count("tcp_hosts"); n > 0 {
		fmt.Fprintf(&out, "[TCP:%d]", n)
	}
	if s.Intercept != "" {
		prefix := ""
		if !s.InterceptActive {
			prefix = "X"
		}
		fmt.Fprintf(&out, "[%si:%s]", prefix, s.Intercept)
	}
	for _, item := range []struct{ key, value string }{{"f", s.Filter}, {"t", s.StickyCookie}, {"u", s.StickyAuth}} {
		if item.value != "" {
			fmt.Fprintf(&out, "[%s:%s]", item.key, item.value)
		}
	}
	if s.ContentView != "" && s.ContentView != "auto" {
		fmt.Fprintf(&out, "[contentview:%s]", s.ContentView)
	}
	if option, ok := opts.Lookup("view_order"); ok && option.HasChanged() {
		fmt.Fprintf(&out, "[o:%s]", s.Order)
	}
	var indicators []string
	for _, name := range []string{"anticache", "anticomp", "showhost"} {
		if flag(name) {
			indicators = append(indicators, name)
		}
	}
	if !flag("server_replay_refresh") {
		indicators = append(indicators, "norefresh")
	}
	if !flag("upstream_cert") {
		indicators = append(indicators, "no-upstream-cert")
	}
	if flag("console_focus_follow") {
		indicators = append(indicators, "following")
	}
	if value := text("stream_large_bodies"); value != "" {
		indicators = append(indicators, value)
	}
	if len(indicators) > 0 {
		fmt.Fprintf(&out, "[%s]", strings.Join(indicators, ":"))
	}
	if option, ok := opts.Lookup("mode"); ok {
		modes, _ := option.Current().([]string)
		if len(modes) == 1 && modes[0] != "regular" {
			fmt.Fprintf(&out, "[%s]", modes[0])
		} else if len(modes) > 1 {
			fmt.Fprintf(&out, "[modes:%d]", len(modes))
		}
	}
	if n := count("scripts"); n > 0 {
		fmt.Fprintf(&out, "[scripts:%d]", n)
	}
	if path := text("save_stream_file"); path != "" {
		fmt.Fprintf(&out, "[W:%s]", path)
	}
	s.Indicators = out.String()
	if b.cfg.Listeners != nil {
		s.Listeners = b.cfg.Listeners()
	}
	return s
}
