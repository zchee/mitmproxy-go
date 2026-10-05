// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package view

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/omap"
	"github.com/zchee/mitmproxy-go/options"
)

func generate(order string, f flow.Flow) orderValue {
	if order == "" || order == "time" {
		return orderValue{number: f.Common().TimestampCreated}
	}
	switch f := f.(type) {
	case *flow.HTTPFlow:
		switch order {
		case "method":
			return orderValue{text: strings.ToUpper(f.Request.Method)}
		case "url":
			return orderValue{text: f.Request.URL()}
		case "size":
			size := len(f.Request.RawContent)
			if f.Response != nil {
				size += len(f.Response.RawContent)
			}
			return orderValue{number: float64(size)}
		}
	case *flow.TCPFlow:
		switch order {
		case "method":
			return orderValue{text: "TCP"}
		case "url":
			return addressKey(f)
		case "size":
			size := 0
			for _, m := range f.Messages {
				size += len(m.Content)
			}
			return orderValue{number: float64(size)}
		}
	case *flow.UDPFlow:
		switch order {
		case "method":
			return orderValue{text: "UDP"}
		case "url":
			return addressKey(f)
		case "size":
			size := 0
			for _, m := range f.Messages {
				size += len(m.Content)
			}
			return orderValue{number: float64(size)}
		}
	case *flow.DNSFlow:
		switch order {
		case "method":
			return orderValue{text: dns.OpCodeToString(f.Request.OpCode)}
		case "url":
			if len(f.Request.Questions) > 0 {
				return orderValue{text: f.Request.Questions[0].Name}
			}
		case "size":
			if f.Response != nil {
				return orderValue{number: float64(f.Response.Size())}
			}
		}
	}
	return orderValue{}
}

func addressKey(f flow.Flow) orderValue {
	if f.Common().ServerConn != nil && f.Common().ServerConn.Address != nil {
		return orderValue{text: f.Common().ServerConn.Address.String()}
	}
	return orderValue{text: "<no address>"}
}

// Load registers the four upstream options and all view commands.
func (v *View) Load(ctx context.Context, loader *addon.Loader) error {
	opts := []struct {
		name    string
		typ     options.Type
		def     any
		help    string
		choices []string
	}{
		{"view_filter", options.TypeOptStr, (*string)(nil), "Limit the view to matching flows.", nil},
		{"view_order", options.TypeStr, "time", "Flow sort order.", []string{"time", "method", "url", "size"}},
		{"view_order_reversed", options.TypeBool, false, "Reverse the sorting order.", nil},
		{"console_focus_follow", options.TypeBool, false, "Focus follows new flows.", nil},
	}
	for _, o := range opts {
		if err := loader.AddOption(ctx, o.name, o.typ, o.def, o.help, o.choices...); err != nil {
			return err
		}
	}
	commands := []struct {
		name   string
		fn     any
		params []string
		help   string
	}{
		{"view.focus.go", v.goFocus, []string{"offset"}, "Go to a specified offset. Positive offests are from the beginning of the view, negative from the end of the view, so that 0 is the first flow, -1 is the last flow."},
		{"view.focus.next", v.focusNext, nil, "Set focus to the next flow."},
		{"view.focus.prev", v.focusPrev, nil, "Set focus to the previous flow."},
		{"view.order.options", v.orderOptions, nil, "Choices supported by the view_order option."},
		{"view.order.reverse", v.setReversed, []string{"boolean"}, ""},
		{"view.order.set", v.setOrder, []string{"order_key"}, "Sets the current view order."},
		{"view.order", v.getOrder, nil, "Returns the current view order."},
		{"view.filter.set", v.setFilterCommand, []string{"filter_expr"}, "Sets the current view filter."},
		{"view.clear", v.clear, nil, "Clears both the store and view."},
		{"view.clear_unmarked", v.clearUnmarked, nil, "Clears only the unmarked flows."},
		{"view.settings.getval", v.getValue, []string{"flow", "key", "default"}, "Get a value from the settings store for the specified flow."},
		{"view.settings.setval.toggle", v.toggleValue, []string{"flows", "key"}, "Toggle a boolean value in the settings store, setting the value to the string \"true\" or \"false\"."},
		{"view.settings.setval", v.setValue, []string{"flows", "key", "value"}, "Set a value in the settings store for the specified flows."},
		{"view.flows.duplicate", v.duplicate, []string{"flows"}, "Duplicates the specified flows, and sets the focus to the first duplicate."},
		{"view.flows.remove", v.remove, []string{"flows"}, "Removes the flow from the underlying store and the view."},
		{"view.flows.resolve", v.resolve, []string{"flow_spec"}, "Resolve a flow list specification to an actual list of flows."},
		{"view.flows.create", v.create, []string{"method", "url"}, ""},
		{"view.flows.load", v.loadFile, []string{"path"}, "Load flows into the view, without processing them with addons."},
		{"view.properties.length", v.getLength, nil, "Returns view length."},
		{"view.properties.marked", v.getMarked, nil, "Returns true if view is in marked mode."},
		{"view.properties.marked.toggle", v.toggleMarked, nil, "Toggle whether to show marked views only."},
		{"view.properties.inbounds", v.inbounds, []string{"index"}, "Is this 0 <= index < len(self)?"},
	}
	for _, cmd := range commands {
		if err := loader.AddCommand(cmd.name, cmd.fn, command.WithParams(cmd.params...), command.WithHelp(cmd.help)); err != nil {
			return err
		}
	}
	return nil
}

// Configure applies view filtering, ordering, reversal and follow options.
func (v *View) Configure(ctx context.Context, updated map[string]struct{}) error {
	opts := v.manager.Options()
	if _, ok := updated["view_filter"]; ok {
		var expression filter.Expr
		if value := opts.OptStr("view_filter"); value != nil && *value != "" {
			var err error
			expression, err = filter.Parse(*value)
			if err != nil {
				return options.Errorf("Invalid filter expression: %s", *value)
			}
		}
		v.SetFilter(expression)
	}
	if _, ok := updated["view_order"]; ok {
		if err := v.setOrder(ctx, opts.Str("view_order")); err != nil {
			return options.Errorf("%s", err)
		}
	}
	if _, ok := updated["view_order_reversed"]; ok {
		v.setReversed(ctx, opts.Bool("view_order_reversed"))
	}
	if _, ok := updated["console_focus_follow"]; ok {
		v.follow = opts.Bool("console_focus_follow")
	}
	return nil
}

func (v *View) goFocus(_ context.Context, offset int) {
	if v.Len() == 0 {
		return
	}
	if offset < 0 {
		offset += v.Len()
	}
	_ = v.Focus.SetIndex(min(max(offset, 0), v.Len()-1))
}

func (v *View) focusNext(ctx context.Context) {
	if idx := v.Focus.Index(); idx >= 0 && v.inbounds(ctx, idx+1) {
		_ = v.Focus.SetIndex(idx + 1)
	}
}

func (v *View) focusPrev(_ context.Context) {
	if idx := v.Focus.Index(); idx > 0 {
		_ = v.Focus.SetIndex(idx - 1)
	}
}

func (v *View) orderOptions(context.Context) []string {
	return []string{"method", "size", "time", "url"}
}

func (v *View) setReversed(_ context.Context, reversed bool) {
	v.reversed = reversed
	v.emit(Event{Kind: "view_refresh"})
}

func (v *View) setOrder(ctx context.Context, order string) error {
	if !slices.Contains(v.orderOptions(ctx), order) {
		return &command.Error{Msg: fmt.Sprintf("Unknown flow order: %s", order)}
	}
	// Rebuild from ascending order, preserving ties in the previous ordering.
	fs := make([]flow.Flow, 0, v.Len())
	v.tree.Ascend(func(i item) bool { fs = append(fs, i.f); return true })
	v.order = order
	v.tree.Clear(false)
	clear(v.visible)
	for _, f := range fs {
		v.insert(f)
	}
	return nil
}
func (v *View) getOrder(context.Context) string { return v.order }
func (v *View) setFilterCommand(_ context.Context, expression string) error {
	var compiled filter.Expr
	if expression != "" {
		var err error
		compiled, err = filter.Parse(expression)
		if err != nil {
			return &command.Error{Msg: "Invalid filter expression: " + expression, Err: err}
		}
	}
	v.SetFilter(compiled)
	return nil
}

func (v *View) clear(context.Context) {
	v.store = omap.New[flow.Flow]()
	v.tree.Clear(false)
	clear(v.visible)
	v.emit(Event{Kind: "view_refresh"})
	v.emit(Event{Kind: "store_refresh"})
}

func (v *View) clearUnmarked(context.Context) {
	for _, id := range v.store.Keys() {
		f, _ := v.store.Get(id)
		if f.Common().Marked == "" {
			v.store.Delete(id)
		}
	}
	v.refilter()
	v.emit(Event{Kind: "store_refresh"})
}

func (v *View) getValue(_ context.Context, f flow.Flow, key, def string) (string, error) {
	values, err := v.Settings.Values(f)
	if err != nil {
		return "", err
	}
	if value, ok := values[key]; ok {
		return value, nil
	}
	return def, nil
}

func (v *View) notify(ctx context.Context, fs []flow.Flow) error {
	if v.manager == nil {
		return v.Update(ctx, fs)
	}
	return v.manager.Trigger(ctx, addon.UpdateHook{Flows: fs})
}

func (v *View) toggleValue(ctx context.Context, fs []flow.Flow, key string) error {
	for _, f := range fs {
		values, err := v.Settings.Values(f)
		if err != nil {
			return err
		}
		if values[key] == "true" {
			values[key] = "false"
		} else {
			values[key] = "true"
		}
	}
	return v.notify(ctx, fs)
}

func (v *View) setValue(ctx context.Context, fs []flow.Flow, key, value string) error {
	for _, f := range fs {
		values, err := v.Settings.Values(f)
		if err != nil {
			return err
		}
		values[key] = value
	}
	return v.notify(ctx, fs)
}

func (v *View) duplicate(ctx context.Context, fs []flow.Flow) error {
	dups := make([]flow.Flow, 0, len(fs))
	for _, f := range fs {
		dups = append(dups, f.Copy())
	}
	if len(dups) > 0 {
		v.Add(ctx, dups)
		if err := v.Focus.Set(dups[0]); err != nil {
			return err
		}
		slog.Log(ctx, addon.LevelAlert, fmt.Sprintf("Duplicated %d flows", len(dups)))
	}
	return nil
}

func (v *View) remove(ctx context.Context, fs []flow.Flow) error {
	for _, f := range fs {
		if !v.store.Has(f.Common().ID) {
			continue
		}
		if f.Common().Killable() {
			if err := f.Common().Kill(); err != nil {
				return err
			}
		}
		if v.Contains(f) {
			idx := v.Index(f)
			if v.reversed {
				idx = v.Len() - idx - 1
			}
			v.erase(f)
			v.emit(Event{Kind: "view_remove", Flow: f, Index: idx})
		}
		v.store.Delete(f.Common().ID)
		v.emit(Event{Kind: "store_remove", Flow: f})
	}
	if len(fs) > 1 {
		slog.Log(ctx, addon.LevelAlert, fmt.Sprintf("Removed %d flows", len(fs)))
	}
	return nil
}

var idSpec = regexp.MustCompile(`^@[0-9a-f\-,]{36,}`)

func (v *View) resolve(_ context.Context, spec string) ([]flow.Flow, error) {
	fs := make([]flow.Flow, 0)
	if spec == "@focus" {
		if f := v.Focus.Flow(); f != nil {
			fs = append(fs, f)
		}
		return fs, nil
	}
	if spec == "@shown" {
		return v.Flows(), nil
	}
	var compiled filter.Expr
	var ids []string
	if idSpec.MatchString(spec) {
		ids = strings.Split(spec[1:], ",")
	} else if !slices.Contains([]string{"@all", "@hidden", "@marked", "@unmarked"}, spec) {
		var err error
		compiled, err = filter.Parse(spec)
		if err != nil {
			return nil, &command.Error{Msg: "Invalid filter expression: " + spec, Err: err}
		}
	}
	for _, f := range v.store.All() {
		matched := true
		switch spec {
		case "@hidden":
			matched = !v.Contains(f)
		case "@marked":
			matched = f.Common().Marked != ""
		case "@unmarked":
			matched = f.Common().Marked == ""
		default:
			if ids != nil {
				matched = slices.Contains(ids, f.Common().ID)
			} else {
				matched = filter.Match(compiled, f)
			}
		}
		if matched {
			fs = append(fs, f)
		}
	}
	return fs, nil
}

func (v *View) create(ctx context.Context, method, url string) error {
	req, err := httpmsg.MakeRequest(strings.ToUpper(method), url, []byte{}, nil)
	if err != nil {
		return &command.Error{Msg: "Invalid URL: " + err.Error(), Err: err}
	}
	client := connection.NewClient(connection.Address{}, connection.Address{}, req.TimestampStart-0.0001)
	server := connection.NewServer(&connection.Address{Host: req.Host, Port: req.Port})
	f := flow.NewHTTPFlow(client, server, false)
	f.Request = req
	req.Headers.Set("Host", req.Host)
	v.Add(ctx, []flow.Flow{f})
	return nil
}

func (v *View) loadFile(ctx context.Context, path command.Path) {
	file, err := os.Open(string(path))
	if err != nil {
		if e, ok := err.(*os.PathError); ok {
			slog.ErrorContext(ctx, e.Err.Error())
		} else {
			slog.ErrorContext(ctx, err.Error())
		}
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			slog.ErrorContext(ctx, err.Error())
		}
	}()
	for f, err := range flowio.NewReader(file).All() {
		if err != nil {
			if _, ok := errors.AsType[*tnetstring.SyntaxError](err); ok {
				slog.ErrorContext(ctx, "Invalid data format.")
			} else {
				slog.ErrorContext(ctx, err.Error())
			}
			return
		}
		v.Add(ctx, []flow.Flow{f.Copy()})
	}
}
func (v *View) getLength(context.Context) int              { return v.Len() }
func (v *View) getMarked(context.Context) bool             { return v.marked }
func (v *View) toggleMarked(context.Context)               { v.marked = !v.marked; v.refilter() }
func (v *View) inbounds(_ context.Context, index int) bool { return index >= 0 && index < v.Len() }
