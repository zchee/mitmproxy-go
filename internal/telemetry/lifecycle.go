// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"math"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"weak"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
)

var flowKinds = [...]string{"http", "websocket", "tcp", "udp", "dns"}

type scalarAttributes struct {
	values [32]attribute.KeyValue
	count  int
}

func (a *scalarAttributes) set(value attribute.KeyValue) {
	for i := range a.count {
		if a.values[i].Key == value.Key {
			a.values[i] = value
			return
		}
	}
	if a.count < len(a.values) {
		a.values[a.count] = value
		a.count++
	}
}

func (a *scalarAttributes) remove(key string) {
	for i := range a.count {
		if a.values[i].Key == attribute.Key(key) {
			a.count--
			a.values[i] = a.values[a.count]
			a.values[a.count] = attribute.KeyValue{}
			return
		}
	}
}

type flowState struct {
	key              weak.Pointer[flow.Base]
	client           weak.Pointer[connection.Client]
	kind             int
	attributes       scalarAttributes
	first            time.Time
	terminalObserved time.Time
	start            float64
	end              float64
	failed           bool
	pending          bool
	confirmed        bool
	messageCount     int
	messageKnown     bool
	clientBytes      int64
	serverBytes      int64
	lastTCP          weak.Pointer[tcp.Message]
	lastUDP          weak.Pointer[udp.Message]
}

// A separate registry prevents cleanup arguments from reaching the controller,
// its Master, or a retained flow through any callback or capability closure.
type tombstoneRegistry struct {
	mu        sync.Mutex
	completed map[weak.Pointer[flow.Base]]runtime.Cleanup
	closed    bool
}

type cleanupArgument struct {
	key      weak.Pointer[flow.Base]
	registry *tombstoneRegistry
}

func removeTombstone(arg cleanupArgument) {
	arg.registry.mu.Lock()
	delete(arg.registry.completed, arg.key)
	arg.registry.mu.Unlock()
}

type stateRegistry struct {
	mu         sync.Mutex
	active     map[weak.Pointer[flow.Base]]*flowState
	clients    map[weak.Pointer[connection.Client]]map[weak.Pointer[flow.Base]]struct{}
	tombstones *tombstoneRegistry
	closed     bool
}

func newStateRegistry() stateRegistry {
	return stateRegistry{active: make(map[weak.Pointer[flow.Base]]*flowState), clients: make(map[weak.Pointer[connection.Client]]map[weak.Pointer[flow.Base]]struct{}), tombstones: &tombstoneRegistry{completed: make(map[weak.Pointer[flow.Base]]runtime.Cleanup)}}
}

// OnHookComplete copies only bounded scalar state under its synchronous dispatch
// frame. It performs no I/O, addon reentry, exporter flush, wait or shutdown.
func (c *Controller) OnHookComplete(_ context.Context, hook addon.Hook) {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if c.state.closed {
		return
	}
	if hook.Name() == "client_disconnected" {
		var client *connection.Client
		switch h := hook.(type) {
		case addon.ClientDisconnectedHook:
			client = h.Client
		case *addon.ClientDisconnectedHook:
			client = h.Client
		}
		if client != nil {
			key := weak.Make(client)
			for identity := range c.state.clients[key] {
				entry := c.state.active[identity]
				if entry == nil {
					continue
				}
				if !entry.pending {
					entry.failed = true
					if client.TimestampEnd != nil {
						entry.end = *client.TimestampEnd
					}
					entry.terminalObserved = time.Now()
				}
				c.complete(entry, entry.key.Value())
			}
			delete(c.state.clients, key)
		}
		return
	}
	f := addon.HookFlow(hook)
	if f == nil {
		return
	}
	base := f.Common()
	key := weak.Make(base)
	c.state.tombstones.mu.Lock()
	_, completed := c.state.tombstones.completed[key]
	c.state.tombstones.mu.Unlock()
	if completed {
		return
	}
	entry := c.state.active[key]
	if entry == nil {
		kind := -1
		switch f.(type) {
		case *flow.HTTPFlow:
			kind = 0
		case *flow.TCPFlow:
			kind = 2
		case *flow.UDPFlow:
			kind = 3
		case *flow.DNSFlow:
			kind = 4
		}
		if kind < 0 {
			return
		}
		entry = &flowState{key: key, kind: kind, first: time.Now()}
		if base.ClientConn != nil {
			entry.client = weak.Make(base.ClientConn)
			index := c.state.clients[entry.client]
			if index == nil {
				index = make(map[weak.Pointer[flow.Base]]struct{})
				c.state.clients[entry.client] = index
			}
			index[key] = struct{}{}
		}
		c.state.active[key] = entry
		c.flows[kind].Add(1)
	}
	c.copyScalars(entry, f, hook.Name())
	terminal := false
	switch hook.Name() {
	case "response":
		h := f.(*flow.HTTPFlow)
		websocketEnabled := c.master != nil && c.master.Options.Bool("websocket")
		if h.Response != nil {
			upgrade, _ := h.Response.Headers.Lookup("Upgrade")
			if h.Response.StatusCode == 101 && strings.EqualFold(strings.TrimSpace(upgrade), "websocket") && websocketEnabled {
				entry.pending = true
				entry.terminalObserved = time.Now()
				return
			}
		}
		terminal = true
	case "websocket_start":
		if !entry.confirmed {
			c.flows[entry.kind].Add(-1)
			entry.kind = 1
			c.flows[entry.kind].Add(1)
			entry.pending, entry.confirmed = false, true
		}
	case "error", "http_connect_error", "tcp_error", "udp_error", "dns_error":
		entry.failed = true
		terminal = true
	case "websocket_end", "tcp_end", "udp_end", "dns_response", "http_connected":
		terminal = true
	}
	if terminal {
		entry.terminalObserved = time.Now()
		c.complete(entry, base)
	}
	runtime.KeepAlive(f)
}

func (c *Controller) complete(entry *flowState, base *flow.Base) {
	delete(c.state.active, entry.key)
	if index := c.state.clients[entry.client]; index != nil {
		delete(index, entry.key)
		if len(index) == 0 {
			delete(c.state.clients, entry.client)
		}
	}
	c.flows[entry.kind].Add(-1)
	if base != nil {
		registry := c.state.tombstones
		registry.mu.Lock()
		if !registry.closed {
			registry.completed[entry.key] = runtime.AddCleanup(base, removeTombstone, cleanupArgument{key: entry.key, registry: registry})
		}
		registry.mu.Unlock()
	}
	c.materialize(entry)
	runtime.KeepAlive(base)
}

func (c *Controller) finishActive() {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	c.state.closed = true
	for _, entry := range c.state.active {
		entry.failed = true
		entry.end = 0
		entry.terminalObserved = time.Now()
		c.complete(entry, nil)
	}
	clear(c.state.clients)
	registry := c.state.tombstones
	registry.mu.Lock()
	registry.closed = true
	for key, cleanup := range registry.completed {
		cleanup.Stop()
		delete(registry.completed, key)
	}
	registry.mu.Unlock()
}

func (c *Controller) materialize(entry *flowState) {
	attrs := &entry.attributes
	attrs.set(attribute.String("flow_kind", flowKinds[entry.kind]))
	known := validTimestamp(entry.start) && validTimestamp(entry.end) && entry.end >= entry.start
	attrs.set(attribute.Bool("timing_known", known))
	if validTimestamp(entry.start) {
		attrs.set(attribute.Float64("flow_start_unix_seconds", entry.start))
	}
	if known {
		attrs.set(attribute.Float64("flow_end_unix_seconds", entry.end))
		attrs.set(attribute.Float64("flow_duration_seconds", entry.end-entry.start))
	}
	start, end := entry.first, entry.terminalObserved
	if validTimestamp(entry.start) {
		start = timestamp(entry.start)
	}
	if known {
		end = timestamp(entry.end)
	}
	if end.Before(start) {
		start, end = entry.first, entry.terminalObserved
	}
	c.admit.Lock()
	defer c.admit.Unlock()
	if c.admissionStopped {
		return
	}
	if c.current == nil {
		c.disabled.Add(1)
		return
	}
	if c.current.pending.Add(1) > 1024 && !c.current.pressured {
		// This is a queue-pressure diagnostic, not a claimed exact loss count.
		// It remains fixed-cardinality even when the collector is unavailable.
		c.current.pressured = true
		c.queuePressure.Add(1)
	}
	_, span := c.current.tracer.Start(context.Background(), "proxy.flow."+flowKinds[entry.kind], trace.WithTimestamp(start), trace.WithAttributes(attrs.values[:attrs.count]...))
	if entry.failed {
		span.SetStatus(codes.Error, "")
	}
	span.End(trace.WithTimestamp(end))
}

func (c *Controller) copyScalars(entry *flowState, f flow.Flow, hook string) {
	base := f.Common()
	attrs := &entry.attributes
	mode := "unknown"
	if base.ClientConn != nil {
		kind, _, _ := strings.Cut(base.ClientConn.ProxyMode, ":")
		switch kind {
		case "regular", "reverse", "upstream", "transparent", "socks5", "dns", "wireguard", "local", "tun":
			mode = strings.Clone(kind)
		}
	}
	attrs.set(attribute.String("mode", mode))
	var fidelity uint64
	if c.cfg.Fidelity != nil {
		fidelity = c.cfg.Fidelity.Load()
	}
	attrs.set(attribute.String("http_fidelity", strconv.FormatUint(fidelity, 10)))
	entry.start = f.TimestampStart()
	if base.ClientConn != nil && base.ClientConn.TimestampEnd != nil {
		entry.end = *base.ClientConn.TimestampEnd
	}
	if base.Error != nil {
		entry.failed = true
		entry.end = base.Error.Timestamp
	}
	switch value := f.(type) {
	case *flow.HTTPFlow:
		if value.Request != nil {
			c.copyString(attrs, "method", value.Request.Method, 64, true)
			c.copyString(attrs, "host", value.Request.Host, 253, false)
			copyBody(attrs, "request", &value.Request.Message)
			copyTiming(attrs, "request", value.Request.TimestampStart, value.Request.TimestampEnd)
		} else {
			attrs.set(attribute.Bool("request_size_known", false))
		}
		if value.Response != nil {
			attrs.set(attribute.Int64("status", int64(value.Response.StatusCode)))
			copyBody(attrs, "response", &value.Response.Message)
			copyTiming(attrs, "response", value.Response.TimestampStart, value.Response.TimestampEnd)
			if value.Response.TimestampEnd != nil {
				entry.end = *value.Response.TimestampEnd
			}
		} else {
			attrs.set(attribute.Bool("response_size_known", false))
		}
		if entry.confirmed && value.WebSocket != nil && value.WebSocket.TimestampEnd != nil {
			entry.end = *value.WebSocket.TimestampEnd
			if validTimestamp(entry.end) {
				attrs.set(attribute.Float64("websocket_end_unix_seconds", entry.end))
			}
		}
		if base.Error != nil {
			entry.end = base.Error.Timestamp
		}
	case *flow.TCPFlow:
		c.copyServerHost(attrs, base)
		if hook == "tcp_start" && len(value.Messages) == 0 {
			entry.messageKnown = true
		}
		if hook == "tcp_message" && len(value.Messages) > 0 {
			last := value.Messages[len(value.Messages)-1]
			if last == nil {
				entry.messageKnown = false
			} else if len(value.Messages) == entry.messageCount+1 {
				entry.addMessage(last.FromClient, len(last.Content))
				entry.lastTCP = weak.Make(last)
			} else if len(value.Messages) != entry.messageCount || entry.lastTCP != weak.Make(last) {
				entry.messageKnown = false
			}
			entry.messageCount = len(value.Messages)
		}
		if len(value.Messages) != entry.messageCount {
			entry.messageKnown = false
		}
		copyMessageSizes(entry)
	case *flow.UDPFlow:
		c.copyServerHost(attrs, base)
		if hook == "udp_start" && len(value.Messages) == 0 {
			entry.messageKnown = true
		}
		if hook == "udp_message" && len(value.Messages) > 0 {
			last := value.Messages[len(value.Messages)-1]
			if last == nil {
				entry.messageKnown = false
			} else if len(value.Messages) == entry.messageCount+1 {
				entry.addMessage(last.FromClient, len(last.Content))
				entry.lastUDP = weak.Make(last)
			} else if len(value.Messages) != entry.messageCount || entry.lastUDP != weak.Make(last) {
				entry.messageKnown = false
			}
			entry.messageCount = len(value.Messages)
		}
		if len(value.Messages) != entry.messageCount {
			entry.messageKnown = false
		}
		copyMessageSizes(entry)
	case *flow.DNSFlow:
		c.copyServerHost(attrs, base)
		attrs.set(attribute.Bool("request_size_known", false))
		attrs.set(attribute.Bool("response_size_known", false))
		if value.Request != nil && value.Request.Timestamp != nil {
			entry.start = *value.Request.Timestamp
			if validTimestamp(entry.start) {
				attrs.set(attribute.Float64("dns_request_unix_seconds", entry.start))
			}
		}
		if value.Response != nil && value.Response.Timestamp != nil {
			entry.end = *value.Response.Timestamp
			if validTimestamp(entry.end) {
				attrs.set(attribute.Float64("dns_response_unix_seconds", entry.end))
			}
		}
		if base.Error != nil {
			entry.end = base.Error.Timestamp
		}
	}
}

func (entry *flowState) addMessage(client bool, length int) {
	if client {
		entry.clientBytes += int64(length)
	} else {
		entry.serverBytes += int64(length)
	}
}

func copyMessageSizes(entry *flowState) {
	entry.attributes.set(attribute.Bool("message_size_known", entry.messageKnown))
	if entry.messageKnown {
		entry.attributes.set(attribute.Int64("client_message_bytes", entry.clientBytes))
		entry.attributes.set(attribute.Int64("server_message_bytes", entry.serverBytes))
	} else {
		entry.attributes.remove("client_message_bytes")
		entry.attributes.remove("server_message_bytes")
	}
}

func (c *Controller) copyServerHost(attrs *scalarAttributes, base *flow.Base) {
	if base.ServerConn != nil && base.ServerConn.Address != nil {
		c.copyString(attrs, "host", base.ServerConn.Address.Host, 253, false)
	}
}

func (c *Controller) copyString(attrs *scalarAttributes, key, value string, limit int, method bool) {
	valid := len(value) > 0 && len(value) <= limit
	if valid {
		if !method {
			if ip, err := netip.ParseAddr(value); err == nil && ip.Zone() == "" {
				attrs.set(attribute.String(key, strings.Clone(value)))
				return
			}
		}
		for _, ch := range []byte(value) {
			allowed := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '.'
			if method {
				allowed = allowed || strings.ContainsRune("!#$%&'*+^_`|~", rune(ch))
			}
			if !allowed {
				valid = false
				break
			}
		}
	}
	if valid {
		attrs.set(attribute.String(key, strings.Clone(value)))
	} else {
		attrs.remove(key)
		if value != "" {
			c.invalid.Add(1)
		}
	}
}

func copyBody(attrs *scalarAttributes, direction string, message *httpmsg.Message) {
	known := message.RawContent != nil
	attrs.set(attribute.Bool(direction+"_size_known", known))
	if known {
		attrs.set(attribute.Int64(direction+"_body_bytes", int64(len(message.RawContent))))
	} else {
		attrs.remove(direction + "_body_bytes")
	}
}

func copyTiming(attrs *scalarAttributes, direction string, start float64, end *float64) {
	for _, suffix := range []string{"_start_unix_seconds", "_end_unix_seconds", "_duration_seconds"} {
		attrs.remove(direction + suffix)
	}
	if validTimestamp(start) {
		attrs.set(attribute.Float64(direction+"_start_unix_seconds", start))
	}
	if end != nil && validTimestamp(*end) && (!validTimestamp(start) || *end >= start) {
		attrs.set(attribute.Float64(direction+"_end_unix_seconds", *end))
		if validTimestamp(start) {
			attrs.set(attribute.Float64(direction+"_duration_seconds", *end-start))
		}
	}
}

func validTimestamp(value float64) bool {
	return value > 0 && value <= 253402300799 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func timestamp(value float64) time.Time {
	seconds, fraction := math.Modf(value)
	return time.Unix(int64(seconds), int64(fraction*1e9))
}
