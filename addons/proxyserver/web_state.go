// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyserver

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"maps"
)

// ServerSnapshot is an owned copy of the completed server presentation.
// Generation orders publications internally and must not appear on the wire.
// Servers is keyed by full mode specification and contains content-only JSON.
// Callers may modify every returned map or byte slice without changing the addon.
// Servers can contain WireGuard client private keys; never log this snapshot or
// its Servers map.
type ServerSnapshot struct {
	Generation uint64                    `json:"-"`
	Servers    map[string]jsontext.Value `json:"servers"`
}

// ServerSnapshot returns the current immutable publication without acquiring
// updateMu, an instance lock or addon dispatch. Every returned byte slice is a
// copy; retaining the snapshot across subsequent reconciliations is safe.
func (p *ProxyServer) ServerSnapshot() ServerSnapshot {
	return p.presentation.Load().clone()
}

func (state *ServerSnapshot) clone() ServerSnapshot {
	out := ServerSnapshot{Generation: state.Generation, Servers: make(map[string]jsontext.Value, len(state.Servers))}
	for spec, value := range state.Servers {
		out.Servers[spec] = bytes.Clone(value)
	}
	return out
}

// SubscribeServerState registers fn under addon dispatch. It is called under a
// fresh dispatch hold after a completed publication, outside updateMu and every
// instance lifecycle lock. Coalesced invalidations deliver the current snapshot,
// never a captured older generation. The callback may only copy/serialize and
// enqueue nonblocking data; no I/O or waiting. The returned idempotent unsubscribe
// also requires dispatch. Unsubscribe affects future notifications, not the
// callback set already captured for delivery. A nil callback is ignored. No
// initial event is sent. Snapshots are secret-bearing and must never be logged.
func (p *ProxyServer) SubscribeServerState(fn func(context.Context, ServerSnapshot)) func() {
	if fn == nil {
		return func() {}
	}
	p.nextStateObserver++
	id := p.nextStateObserver
	p.stateObservers[id] = fn
	return func() {
		if p.stateObservers[id] != nil {
			delete(p.stateObservers, id)
		}
	}
}

// publishServerState is called only under updateMu after lifecycle work has
// completed. Every instance supplies one immutable state version, so getters
// from different versions cannot produce a mixed running/error/address tuple.
func (p *ProxyServer) publishServerState() {
	servers := make(map[string]jsontext.Value)
	for _, instance := range p.instances.Load().instances {
		value, err := json.Marshal(instance.WebState(), json.Deterministic(true))
		if err != nil {
			p.logger.Error("Serializing server presentation", "error", err)
			return
		}
		servers[instance.Mode().String()] = value
	}
	previous := p.presentation.Load()
	if maps.EqualFunc(previous.Servers, servers, func(a, b jsontext.Value) bool { return bytes.Equal(a, b) }) {
		return
	}
	p.presentation.Store(&ServerSnapshot{Generation: previous.Generation + 1, Servers: servers})
}

func (p *ProxyServer) refreshServerState(revision uint64) {
	for {
		p.updateMu.Lock()
		p.publishServerState()
		p.updateMu.Unlock()
		current := p.presentationRevision.Load()
		if current == revision {
			return
		}
		revision = current
	}
}

func (p *ProxyServer) signalServerState() {
	select {
	case p.presentationWake <- struct{}{}:
	default:
	}
}

func (p *ProxyServer) deliverServerState(ctx context.Context) {
	_ = p.manager.Do(ctx, func(ctx context.Context) error {
		state := p.presentation.Load()
		if state.Generation <= p.lastStateGeneration {
			return nil
		}
		p.lastStateGeneration = state.Generation
		for _, observer := range maps.Clone(p.stateObservers) {
			observer(ctx, state.clone())
		}
		return nil
	})
}
