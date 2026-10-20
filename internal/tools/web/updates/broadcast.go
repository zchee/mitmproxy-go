// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updates

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flowio/flowjson"
)

func (c *client) send(kind string, payload any) {
	message := map[string]any{"type": kind}
	if payload != nil {
		message["payload"] = payload
	}
	body, err := json.Marshal(message, json.Deterministic(true))
	if err != nil {
		c.terminate(gows.CloseInternalServerErr, internalReason)
		return
	}
	c.enqueue(body)
}

func (h *Hub) broadcast(kind string, payload any) {
	if h.closed {
		return
	}
	message := map[string]any{"type": kind}
	if payload != nil {
		message["payload"] = payload
	}
	body, err := json.Marshal(message, json.Deterministic(true))
	for c := range h.clients {
		if err != nil {
			c.terminate(gows.CloseInternalServerErr, internalReason)
		} else {
			c.enqueue(body)
		}
	}
}

func (h *Hub) flowChanged(event view.Event) {
	if h.closed || len(h.clients) == 0 {
		return
	}
	switch event.Kind {
	case "view_add", "view_update":
		value, err := flowjson.Flow(event.Flow)
		var encoded []byte
		if err == nil {
			encoded, err = json.Marshal(value)
		}
		for c := range h.clients {
			if err != nil {
				c.terminate(gows.CloseInternalServerErr, internalReason)
				continue
			}
			matches := make(map[string]bool, len(c.filters))
			for name, expression := range c.filters {
				matches[name] = filter.Match(expression, event.Flow)
			}
			kind := "flows/add"
			if event.Kind == "view_update" {
				kind = "flows/update"
			}
			c.send(kind, map[string]any{"flow": jsontext.Value(encoded), "matching_filters": matches})
		}
	case "view_remove":
		h.broadcast("flows/remove", event.Flow.Common().ID)
	case "view_refresh":
		for c := range h.clients {
			c.send("flows/reset", nil)
			for _, name := range c.filterNames {
				c.updateFilter(name, c.filters[name])
			}
		}
	}
}

func (h *Hub) eventChanged(event eventstore.Event) {
	if event.Kind == "refresh" {
		h.broadcast("events/reset", nil)
		return
	}
	h.broadcast("events/add", map[string]any{"id": event.ID, "message": event.Entry.Msg, "level": event.Entry.LevelName()})
}

func (h *Hub) serverChanged(_ context.Context, state proxyserver.ServerSnapshot) {
	h.broadcast("state/update", map[string]any{"servers": state.Servers})
}

func (h *Hub) optionsChanged(ctx context.Context, updated map[string]struct{}) error {
	return h.cfg.Master.Do(ctx, func(context.Context) error {
		if h.closed || len(h.clients) == 0 {
			return nil
		}
		values := make(map[string]any, len(updated))
		for name := range updated {
			option, ok := h.cfg.Master.Options.Lookup(name)
			if !ok {
				continue
			}
			var choices any = jsontext.Value("null")
			if option.Choices() != nil {
				choices = option.Choices()
			}
			values[name] = map[string]any{"value": option.Current(), "choices": choices, "default": option.Default(), "help": option.Help(), "type": option.Type().String()}
		}
		h.broadcast("options/update", values)
		return nil
	})
}
