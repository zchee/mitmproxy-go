// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package testflow_test

import (
	"fmt"
	"reflect"
	"strconv"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/websocket"
)

// bareFlows returns flows of every type with every optional part absent:
// no request, response, WebSocket data, messages or error, and connections
// without addresses, timestamps or TLS data. Where a part is a struct, it is
// also present but empty, so its own optional fields are absent.
func bareFlows() map[string]flow.Flow {
	httpNothing := flow.NewHTTPFlow(&connection.Client{}, &connection.Server{}, false)
	httpEmptyParts := flow.NewHTTPFlow(&connection.Client{}, &connection.Server{}, false)
	httpEmptyParts.Request = &httpmsg.Request{}
	httpEmptyParts.Response = &httpmsg.Response{}
	httpEmptyParts.WebSocket = &websocket.Data{}
	httpEmptyParts.Error = &flow.Error{}
	httpEmptyMessage := flow.NewHTTPFlow(&connection.Client{}, &connection.Server{}, false)
	httpEmptyMessage.WebSocket = &websocket.Data{Messages: []*websocket.Message{{}}}

	dnsNothing := flow.NewDNSFlow(&connection.Client{}, &connection.Server{}, false)
	dnsEmptyParts := flow.NewDNSFlow(&connection.Client{}, &connection.Server{}, false)
	dnsEmptyParts.Request = &dns.Message{}
	dnsEmptyParts.Response = &dns.Message{}

	tcpNothing := flow.NewTCPFlow(&connection.Client{}, &connection.Server{}, false)
	udpNothing := flow.NewUDPFlow(&connection.Client{}, &connection.Server{}, false)

	constructed := flow.NewTCPFlow(connection.NewClient(connection.Address{}, connection.Address{}, 0), connection.NewServer(nil), true)

	return map[string]flow.Flow{
		"http without request, response, websocket or error":  httpNothing,
		"http with empty request, response, websocket, error": httpEmptyParts,
		"http with an empty websocket message":                httpEmptyMessage,
		"dns without request or response":                     dnsNothing,
		"dns with empty request and response":                 dnsEmptyParts,
		"tcp without messages":                                tcpNothing,
		"udp without messages":                                udpNothing,
		"tcp over constructor-built connections":              constructed,
	}
}

// typedNils walks a state value and returns the path of every typed nil it
// holds: a nil *state.Map, a nil slice (byte strings included) or any other
// nil pointer, map, channel or function in an interface. The encoder writes
// such a value as an empty dict, list or byte string, where mitmproxy writes
// None for an absent part; an absent part must be an untyped nil.
func typedNils(path string, v any) []string {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Chan, reflect.Func, reflect.Interface:
		if rv.IsNil() {
			return []string{fmt.Sprintf("%s: typed nil %T", path, v)}
		}
	}
	var found []string
	switch v := v.(type) {
	case *state.Map:
		for k, child := range v.All() {
			found = append(found, typedNils(path+"."+k, child)...)
		}
	case []byte:
	default:
		if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
			for i := range rv.Len() {
				found = append(found, typedNils(path+"["+strconv.Itoa(i)+"]", rv.Index(i).Interface())...)
			}
		}
	}
	return found
}

// TestStateHasNoTypedNil walks the state of every builder's flows, which
// have their optional parts present, and of flows of every type with those
// parts absent, and fails on any typed nil in the tree.
func TestStateHasNoTypedNil(t *testing.T) {
	tests := map[string]struct {
		flows []flow.Flow
	}{}
	for _, c := range builderCases() {
		tests["present: "+c.python] = struct{ flows []flow.Flow }{flows: c.build()}
	}
	for name, f := range bareFlows() {
		tests["absent: "+name] = struct{ flows []flow.Flow }{flows: []flow.Flow{f}}
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for i, f := range tt.flows {
				for _, p := range typedNils(fmt.Sprintf("flow[%d]", i), f.GetState()) {
					t.Errorf("%s in the %s flow's state", p, f.Type())
				}
			}
		})
	}
}

// TestTypedNilsFindsEveryKind checks the walk itself: each typed nil kind
// is reported with its path, and untyped nils and empty values are not.
func TestTypedNilsFindsEveryKind(t *testing.T) {
	var (
		nilMap   *state.Map
		nilList  []any
		nilBytes []byte
		nilPtr   *float64
	)
	m := state.NewMap(6)
	m.Set("none", nil)
	m.Set("empty", state.NewMap(0))
	m.Set("dict", nilMap)
	m.Set("list", []any{int64(1), nilList})
	m.Set("bytes", nilBytes)
	m.Set("pointer", nilPtr)
	got := typedNils("s", m)
	want := []string{
		"s.dict: typed nil *omap.Map[interface {}]",
		"s.list[1]: typed nil []interface {}",
		"s.bytes: typed nil []uint8",
		"s.pointer: typed nil *float64",
	}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Errorf("typedNils (-want +got):\n%s", diff)
	}
}
