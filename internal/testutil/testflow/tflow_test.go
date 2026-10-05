// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package testflow_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

// builderCase pairs a Python expression over upstream's tflow and tutils
// helpers with the Go builder call that must produce the same flows.
type builderCase struct {
	python string
	build  func() []flow.Flow
	// nowCreated marks flows whose creation timestamp is the current time
	// on both sides, so the comparison pins it.
	nowCreated bool
}

func one[F flow.Flow](f F) func() []flow.Flow {
	return func() []flow.Flow { return []flow.Flow{f} }
}

// builderCases lists every builder and flag combination upstream's tests use.
func builderCases() []builderCase {
	noQuestions := testflow.TDNSFlow()
	noQuestions.Request.Questions = nil
	return []builderCase{
		{python: "tflow()", build: one(testflow.TFlow())},
		{python: "tflow(resp=True)", build: one(testflow.TFlow(testflow.WithResponse))},
		{python: "tflow(err=True)", build: one(testflow.TFlow(testflow.WithError))},
		{python: "tflow(ws=True)", build: one(testflow.TFlow(testflow.WithWebSocket))},
		{python: "tflow(resp=True, err=True, ws=True)", build: one(testflow.TFlow(testflow.WithResponse, testflow.WithError, testflow.WithWebSocket))},
		{python: "ttcpflow()", build: one(testflow.TTCPFlow())},
		{python: "ttcpflow(err=True)", build: one(testflow.TTCPFlow(testflow.WithError))},
		{python: "tudpflow()", build: one(testflow.TUDPFlow())},
		{python: "tudpflow(err=True)", build: one(testflow.TUDPFlow(testflow.WithError))},
		{python: "tdnsflow()", build: one(testflow.TDNSFlow())},
		{python: "tdnsflow(resp=True)", build: one(testflow.TDNSFlow(testflow.WithResponse))},
		{python: "tdnsflow(err=True)", build: one(testflow.TDNSFlow(testflow.WithError))},
		{python: "tdnsflow(req=tdnsreq(questions=[]))", build: one(noQuestions)},
		{python: "twebsocketflow()", build: one(testflow.TWebSocketFlow()), nowCreated: true},
		{python: "twebsocketflow(err=True)", build: one(testflow.TWebSocketFlow(testflow.WithError)), nowCreated: true},
		{python: "tflows()", build: testflow.TFlows},
	}
}

// pinIDs replaces the random identifiers, and the creation timestamp when
// nowCreated is set, with values derived from the case and flow index, as the
// Python side of TestBuildersMatchUpstream does.
func pinIDs(f flow.Flow, c, i int, nowCreated bool) {
	b := f.Common()
	b.ID = fmt.Sprintf("flow-%d-%d", c, i)
	b.ClientConn.ID = fmt.Sprintf("client-%d-%d", c, i)
	b.ServerConn.ID = fmt.Sprintf("server-%d-%d", c, i)
	if nowCreated {
		b.TimestampCreated = 1
	}
}

// upstreamScript evaluates one expression per stdin line and writes, as a
// tnetstring list, the list of flow states each expression produced, with the
// same identifiers pinIDs sets.
const upstreamScript = `
import sys
from mitmproxy.io import tnetstring
from mitmproxy.test.tflow import tdnsflow, tflow, tflows, ttcpflow, tudpflow, twebsocketflow
from mitmproxy.test.tutils import tdnsreq

out = []
for c, line in enumerate(sys.stdin.read().splitlines()):
    expr, now_created = line.split("\t")
    result = eval(expr)
    flows = result if isinstance(result, list) else [result]
    states = []
    for i, f in enumerate(flows):
        f.id = f"flow-{c}-{i}"
        f.client_conn.id = f"client-{c}-{i}"
        f.server_conn.id = f"server-{c}-{i}"
        if now_created == "1":
            f.timestamp_created = 1
        states.append(f.get_state())
    out.append(states)
sys.stdout.buffer.write(tnetstring.dumps(out))
`

// TestBuildersMatchUpstream compares the state of every builder's flow with
// the state upstream's helper of the same name produces, under Python's ==
// (integer timestamps equal float ones), and checks that dictionaries list
// their keys in upstream's order, which flow files preserve.
func TestBuildersMatchUpstream(t *testing.T) {
	cases := builderCases()
	var stdin strings.Builder
	for _, c := range cases {
		nowCreated := "0"
		if c.nowCreated {
			nowCreated = "1"
		}
		fmt.Fprintf(&stdin, "%s\t%s\n", c.python, nowCreated)
	}
	out := difftest.Python(t, upstreamScript, []byte(stdin.String()))

	decoded, err := tnetstring.Loads(out)
	if err != nil {
		t.Fatalf("decode upstream states: %v", err)
	}
	upstream, ok := fromWire(decoded).([]any)
	if !ok || len(upstream) != len(cases) {
		t.Fatalf("upstream returned %T with %d entries, want a list of %d", decoded, len(upstream), len(cases))
	}

	for ci, c := range cases {
		t.Run(c.python, func(t *testing.T) {
			want, err := state.AsList(upstream[ci])
			if err != nil {
				t.Fatal(err)
			}
			flows := c.build()
			if len(flows) != len(want) {
				t.Fatalf("Go builds %d flows, upstream %d", len(flows), len(want))
			}
			for i, f := range flows {
				pinIDs(f, ci, i, c.nowCreated)
				got := f.GetState()
				path := fmt.Sprintf("flow[%d]", i)
				if d := stateDiff(path, want[i], got); d != "" {
					t.Errorf("state differs from upstream: %s", d)
				}
				if d := keyOrderDiff(path, want[i], got); d != "" {
					t.Errorf("key order differs from upstream: %s", d)
				}
			}
		})
	}
}

// fromWire rebuilds a decoded tnetstring value with every dictionary's keys
// reversed: tnetstring writes dictionary entries in reverse insertion order,
// so this restores the order of the Python dictionary.
func fromWire(v any) any {
	switch x := v.(type) {
	case *state.Map:
		keys := x.Keys()
		m := state.NewMap(len(keys))
		for _, k := range slices.Backward(keys) {
			e, _ := x.Get(k)
			m.Set(k, fromWire(e))
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = fromWire(e)
		}
		return out
	}
	return v
}

// stateDiff returns a description of the first difference between two state
// values under Python's ==, naming the path to it, or "" when they are equal.
func stateDiff(path string, want, got any) string {
	if state.Equal(want, got) {
		return ""
	}
	switch w := want.(type) {
	case *state.Map:
		g, ok := got.(*state.Map)
		if !ok {
			break
		}
		for k, wv := range w.All() {
			gv, ok := g.Get(k)
			if !ok {
				return fmt.Sprintf("%s.%s: missing in Go (upstream %s)", path, k, show(wv))
			}
			if d := stateDiff(path+"."+k, wv, gv); d != "" {
				return d
			}
		}
		for k, gv := range g.All() {
			if !w.Has(k) {
				return fmt.Sprintf("%s.%s: only in Go (%s)", path, k, show(gv))
			}
		}
	case []any:
		g, ok := got.([]any)
		if !ok {
			break
		}
		if len(w) != len(g) {
			return fmt.Sprintf("%s: upstream has %d elements, Go %d: upstream %s, Go %s", path, len(w), len(g), show(want), show(got))
		}
		for i := range w {
			if d := stateDiff(fmt.Sprintf("%s[%d]", path, i), w[i], g[i]); d != "" {
				return d
			}
		}
	}
	return fmt.Sprintf("%s: upstream %s, Go %s", path, show(want), show(got))
}

// keyOrderDiff returns a description of the first dictionary whose keys are
// in a different order, or "" when every dictionary matches.
func keyOrderDiff(path string, want, got any) string {
	switch w := want.(type) {
	case *state.Map:
		g, ok := got.(*state.Map)
		if !ok {
			return ""
		}
		if !slices.Equal(w.Keys(), g.Keys()) {
			return fmt.Sprintf("%s: upstream %q, Go %q", path, w.Keys(), g.Keys())
		}
		for k, wv := range w.All() {
			gv, _ := g.Get(k)
			if d := keyOrderDiff(path+"."+k, wv, gv); d != "" {
				return d
			}
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return ""
		}
		for i := range w {
			if d := keyOrderDiff(fmt.Sprintf("%s[%d]", path, i), w[i], g[i]); d != "" {
				return d
			}
		}
	}
	return ""
}

// show formats a state value with its Python type, so that bytes and str,
// or int and float, are told apart in failure messages.
func show(v any) string {
	if b, ok := v.([]byte); ok {
		return fmt.Sprintf("bytes(%q)", b)
	}
	return fmt.Sprintf("%s(%v)", state.TypeName(v), v)
}

// TestStateRoundTrip checks that every builder's flow survives GetState and
// FromState unchanged, so the builders produce self-consistent flows.
func TestStateRoundTrip(t *testing.T) {
	for ci, c := range builderCases() {
		t.Run(c.python, func(t *testing.T) {
			for i, f := range c.build() {
				pinIDs(f, ci, i, c.nowCreated)
				want := f.GetState()
				back, err := flow.FromState(state.Copy(want).(*state.Map))
				if err != nil {
					t.Fatalf("flow[%d]: FromState: %v", i, err)
				}
				if d := stateDiff(fmt.Sprintf("flow[%d]", i), want, back.GetState()); d != "" {
					t.Errorf("round trip changed the state: %s", d)
				}
			}
		})
	}
}

func TestBuilderDefaults(t *testing.T) {
	type summary struct {
		Type             string
		Live             bool
		TimestampCreated float64
		HasResponse      bool
		HasError         bool
		HasWebSocket     bool
		ProxyMode        string
		ClientTransport  connection.TransportProtocol
		ServerTransport  connection.TransportProtocol
		CloseCode        int
	}
	summarize := func(f flow.Flow) summary {
		b := f.Common()
		s := summary{
			Type:             f.Type(),
			Live:             b.Live,
			TimestampCreated: b.TimestampCreated,
			HasError:         b.Error != nil,
			ProxyMode:        b.ClientConn.ProxyMode,
			ClientTransport:  b.ClientConn.TransportProtocol,
			ServerTransport:  b.ServerConn.TransportProtocol,
		}
		switch f := f.(type) {
		case *flow.HTTPFlow:
			s.HasResponse = f.Response != nil
			s.HasWebSocket = f.WebSocket != nil
			if f.WebSocket != nil && f.WebSocket.CloseCode != nil {
				s.CloseCode = *f.WebSocket.CloseCode
			}
		case *flow.DNSFlow:
			s.HasResponse = f.Response != nil
		}
		return s
	}
	tcpConn := func(s summary) summary {
		s.ProxyMode, s.ClientTransport, s.ServerTransport = "regular", connection.TCP, connection.TCP
		s.Live = true
		return s
	}

	tests := map[string]struct {
		got  flow.Flow
		want summary
	}{
		"tflow(): request only, created at the request start": {
			got:  testflow.TFlow(),
			want: tcpConn(summary{Type: "http", TimestampCreated: 946681200}),
		},
		"tflow(resp=True, err=True, ws=True): all optional parts": {
			got:  testflow.TFlow(testflow.WithResponse, testflow.WithError, testflow.WithWebSocket),
			want: tcpConn(summary{Type: "http", TimestampCreated: 946681200, HasResponse: true, HasError: true, HasWebSocket: true, CloseCode: 1000}),
		},
		"ttcpflow(): created at the client connection start": {
			got:  testflow.TTCPFlow(),
			want: tcpConn(summary{Type: "tcp", TimestampCreated: 946681200}),
		},
		"tudpflow(err=True): error added": {
			got:  testflow.TUDPFlow(testflow.WithError),
			want: tcpConn(summary{Type: "udp", TimestampCreated: 946681200, HasError: true}),
		},
		"tdnsflow(resp=True): dns proxy mode over UDP": {
			got:  testflow.TDNSFlow(testflow.WithResponse),
			want: summary{Type: "dns", Live: true, TimestampCreated: 946681200, HasResponse: true, ProxyMode: "dns", ClientTransport: connection.UDP, ServerTransport: connection.UDP},
		},
		"twebsocketflow(err=True): abnormal close code and no flow error": {
			got:  testflow.TWebSocketFlow(testflow.WithError),
			want: tcpConn(summary{Type: "http", HasResponse: true, HasWebSocket: true, CloseCode: 1006}),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := summarize(tt.got)
			if strings.HasPrefix(name, "twebsocketflow") {
				// Created now, as upstream; only check that it was set.
				if got.TimestampCreated == 0 {
					t.Error("TimestampCreated is not set")
				}
				got.TimestampCreated = 0
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("flow mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBuildersReturnIndependentValues(t *testing.T) {
	a, b := testflow.TFlow(testflow.WithResponse), testflow.TFlow(testflow.WithResponse)
	if a.ID == b.ID || a.ClientConn.ID == b.ClientConn.ID || a.ServerConn.ID == b.ServerConn.ID {
		t.Errorf("two TFlow calls share identifiers: flow %s/%s, client %s/%s, server %s/%s",
			a.ID, b.ID, a.ClientConn.ID, b.ClientConn.ID, a.ServerConn.ID, b.ServerConn.ID)
	}
	a.Request.RawContent[0] = 'X'
	a.Response.Headers[0].Value[0] = 'X'
	if diff := gocmp.Diff("content", string(b.Request.RawContent)); diff != "" {
		t.Errorf("request content shared between calls (-want +got):\n%s", diff)
	}
	if diff := gocmp.Diff("svalue", string(b.Response.Headers[0].Value)); diff != "" {
		t.Errorf("response headers shared between calls (-want +got):\n%s", diff)
	}
}

func TestBuilderRejectsFlagsUpstreamDoesNotTake(t *testing.T) {
	tests := map[string]struct {
		build func()
		want  string
	}{
		"ttcpflow has no response": {
			build: func() { testflow.TTCPFlow(testflow.WithResponse) },
			want:  "testflow.TTCPFlow: WithResponse does not apply",
		},
		"tdnsflow has no websocket": {
			build: func() { testflow.TDNSFlow(testflow.WithWebSocket) },
			want:  "testflow.TDNSFlow: WithWebSocket does not apply",
		},
		"twebsocketflow has no response flag": {
			build: func() { testflow.TWebSocketFlow(testflow.WithResponse) },
			want:  "testflow.TWebSocketFlow: WithResponse does not apply",
		},
		"the zero flag is rejected": {
			build: func() { testflow.TFlow(0) },
			want:  "testflow.TFlow: With(0) does not apply",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if diff := gocmp.Diff(tt.want, recover()); diff != "" {
					t.Errorf("panic mismatch (-want +got):\n%s", diff)
				}
			}()
			tt.build()
		})
	}
}
