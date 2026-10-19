// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import "github.com/zchee/mitmproxy-go/internal/proxy/modespec"

// WebState copies the upstream server presentation from one immutable instance
// state. It never takes a lifecycle lock or reads configuration files. The
// returned map and address tuples belong to the caller; optional native-mode
// members are present with null values when their source is stopped.
func (i *Instance) WebState() map[string]any {
	state := i.state.Load()
	addrs := make([][2]any, 0, len(state.addrs))
	for _, addr := range state.addrs {
		addrs = append(addrs, [2]any{addr.Host, addr.Port})
	}
	var lastException any
	if state.err != nil {
		lastException = state.err.Error()
	}
	out := map[string]any{
		"type":           i.mode.Name(),
		"description":    i.mode.Description(),
		"full_spec":      i.mode.String(),
		"is_running":     state.local != nil || state.tun != nil || len(state.addrs) != 0,
		"last_exception": lastException,
		"listen_addrs":   addrs,
	}
	switch i.mode.(type) {
	case modespec.WireGuardMode:
		out["wireguard_conf"] = nil
		if state.wireguard != nil {
			out["wireguard_conf"] = state.wireguardConf
		}
	case modespec.TunMode:
		out["tun_name"] = nil
		if state.tun != nil {
			out["tun_name"] = state.tunName
		}
	}
	return out
}

func (i *Instance) signalPresentation() {
	select {
	case i.presentationChanged <- struct{}{}:
	default:
	}
}
