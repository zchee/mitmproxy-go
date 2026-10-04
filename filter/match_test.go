// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package filter

import (
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

// The builders below mirror upstream's mitmproxy.test.tflow and tutils
// field for field, so the ported assertions run against the same flows.

//go:fix inline

func tclientConn() *connection.Client {
	c := connection.NewClient(connection.Address{Host: "127.0.0.1", Port: 22}, connection.Address{Host: "", Port: 0}, 946681200)
	c.SNI = new("address")
	c.ALPN = []byte("http/1.1")
	return c
}

func tserverConn() *connection.Server {
	s := connection.NewServer(&connection.Address{Host: "address", Port: 22})
	s.Peername = &connection.Address{Host: "192.168.0.1", Port: 22}
	s.Sockname = &connection.Address{Host: "address", Port: 22}
	s.SNI = new("address")
	return s
}

func headers(kv ...string) httpmsg.Headers {
	h := make(httpmsg.Headers, 0, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		h = append(h, httpmsg.Field{Name: []byte(kv[i]), Value: []byte(kv[i+1])})
	}
	return h
}

func treq() *httpmsg.Request {
	return &httpmsg.Request{
		HTTPVersion:    "HTTP/1.1",
		Headers:        headers("header", "qvalue", "content-length", "7"),
		RawContent:     []byte("content"),
		TimestampStart: 946681200,
		TimestampEnd:   new(946681201.0),
		Host:           "address",
		Port:           22,
		Method:         "GET",
		Scheme:         "http",
		Path:           "/path",
	}
}

func tresp() *httpmsg.Response {
	return &httpmsg.Response{
		HTTPVersion:    "HTTP/1.1",
		Headers:        headers("header-response", "svalue", "content-length", "7"),
		RawContent:     []byte("message"),
		TimestampStart: 946681202,
		TimestampEnd:   new(946681203.0),
		StatusCode:     200,
		Reason:         "OK",
	}
}

func terr() *flow.Error { return &flow.Error{Msg: "error", Timestamp: 946681207} }

type tflowOpts struct {
	resp, err, ws bool
}

func tflow(o tflowOpts) *flow.HTTPFlow {
	f := flow.NewHTTPFlow(tclientConn(), tserverConn(), true)
	f.Request = treq()
	if o.resp {
		f.Response = tresp()
	}
	if o.err {
		f.Error = terr()
	}
	if o.ws {
		f.WebSocket = twebsocket()
	}
	return f
}

func twebsocket() *websocket.Data {
	return &websocket.Data{
		Messages: []*websocket.Message{
			{Type: websocket.OpBinary, FromClient: true, Content: []byte("hello binary"), Timestamp: 946681203},
			{Type: websocket.OpText, FromClient: true, Content: []byte("hello text"), Timestamp: 946681204},
			{Type: websocket.OpText, FromClient: false, Content: []byte("it's me"), Timestamp: 946681205},
		},
		ClosedByClient: new(false),
		CloseCode:      new(1000),
		CloseReason:    new("Close Reason"),
		TimestampEnd:   new(946681205.0),
	}
}

func twebsocketflow() *flow.HTTPFlow {
	f := flow.NewHTTPFlow(tclientConn(), tserverConn(), true)
	f.Request = &httpmsg.Request{
		HTTPVersion:    "HTTP/1.1",
		Headers:        headers("connection", "upgrade", "upgrade", "websocket", "sec-websocket-version", "13", "sec-websocket-key", "1234"),
		RawContent:     []byte{},
		TimestampStart: 946681200,
		TimestampEnd:   new(946681201.0),
		Host:           "example.com",
		Port:           80,
		Method:         "GET",
		Scheme:         "http",
		Authority:      "example.com",
		Path:           "/ws",
	}
	f.Response = &httpmsg.Response{
		HTTPVersion:    "HTTP/1.1",
		Headers:        headers("connection", "upgrade", "upgrade", "websocket", "sec-websocket-accept", ""),
		RawContent:     []byte{},
		TimestampStart: 946681202,
		TimestampEnd:   new(946681203.0),
		StatusCode:     101,
		Reason:         "Switching Protocols",
	}
	f.WebSocket = twebsocket()
	f.WebSocket.CloseReason = new("")
	return f
}

func ttcpflow(withErr bool) *flow.TCPFlow {
	f := flow.NewTCPFlow(tclientConn(), tserverConn(), true)
	f.Messages = []*tcp.Message{
		{FromClient: true, Content: []byte("hello"), Timestamp: 946681204.2},
		{FromClient: false, Content: []byte("it's me"), Timestamp: 946681204.5},
	}
	if withErr {
		f.Error = terr()
	}
	return f
}

func tudpflow(withErr bool) *flow.UDPFlow {
	f := flow.NewUDPFlow(tclientConn(), tserverConn(), true)
	f.Messages = []*udp.Message{
		{FromClient: true, Content: []byte("hello"), Timestamp: 946681204.2},
		{FromClient: false, Content: []byte("it's me"), Timestamp: 946681204.5},
	}
	if withErr {
		f.Error = terr()
	}
	return f
}

func tdnsreq() *dns.Message {
	return &dns.Message{
		ID:               42,
		Query:            true,
		OpCode:           dns.OpCodeQUERY,
		RecursionDesired: true,
		ResponseCode:     dns.ResponseCodeNOERROR,
		Questions:        []dns.Question{{Name: "dns.google", Type: dns.TypeA, Class: dns.ClassIN}},
		Timestamp:        new(946681200.0),
	}
}

func tdnsresp() *dns.Message {
	return &dns.Message{
		ID:                 42,
		OpCode:             dns.OpCodeQUERY,
		RecursionDesired:   true,
		RecursionAvailable: true,
		ResponseCode:       dns.ResponseCodeNOERROR,
		Questions:          []dns.Question{{Name: "dns.google", Type: dns.TypeA, Class: dns.ClassIN}},
		Answers: []dns.ResourceRecord{
			{Name: "dns.google", Type: dns.TypeA, Class: dns.ClassIN, TTL: 32, Data: []byte{8, 8, 8, 8}},
			{Name: "dns.google", Type: dns.TypeA, Class: dns.ClassIN, TTL: 32, Data: []byte{8, 8, 4, 4}},
		},
		Timestamp: new(946681201.0),
	}
}

func tdnsflow(resp, withErr bool) *flow.DNSFlow {
	client := tclientConn()
	client.ProxyMode = "dns"
	client.TransportProtocol = connection.UDP
	server := tserverConn()
	server.TransportProtocol = connection.UDP
	f := flow.NewDNSFlow(client, server, true)
	f.Request = tdnsreq()
	if resp {
		f.Response = tdnsresp()
	}
	if withErr {
		f.Error = terr()
	}
	return f
}

// dummyFlow is upstream's DummyFlow: a flow of no protocol type, which
// only the operators that apply to every flow can match.
type dummyFlow struct{ flow.Base }

func (*dummyFlow) Type() string              { return "dummy" }
func (*dummyFlow) TimestampStart() float64   { return 0 }
func (*dummyFlow) GetState() *state.Map      { return state.NewMap(0) }
func (*dummyFlow) SetState(*state.Map) error { return nil }
func (d *dummyFlow) Copy() flow.Flow         { return d }
func (*dummyFlow) Backup()                   {}
func (*dummyFlow) Revert() error             { return nil }
func (*dummyFlow) Modified() bool            { return false }

func tdummyflow(withErr bool) *dummyFlow {
	d := &dummyFlow{ClientConn: tclientConn(), ServerConn: tserverConn(), Metadata: state.NewMap(0)}
	if withErr {
		d.Error = terr()
	}
	return d
}

// q parses expr and matches it against f, failing the test on a parse
// error, like the q helper of upstream's test classes.
func q(t *testing.T, expr string, f flow.Flow) bool {
	t.Helper()
	e, err := Parse(expr)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", expr, err)
	}
	return e.Match(f)
}

// check is one assertion of an upstream test: expr must match f exactly
// when want is true.
type check struct {
	expr string
	want bool
}

func checkAll(t *testing.T, f flow.Flow, checks ...check) {
	t.Helper()
	for _, c := range checks {
		if got := q(t, c.expr, f); got != c.want {
			t.Errorf("%q matches %s flow = %v, want %v", c.expr, f.Type(), got, c.want)
		}
	}
}

func yes(expr string) check { return check{expr: expr, want: true} }
func no(expr string) check  { return check{expr: expr, want: false} }

func TestMatchingHTTPFlow(t *testing.T) {
	t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", "")
	req := func() *flow.HTTPFlow { return tflow(tflowOpts{}) }
	resp := func() *flow.HTTPFlow { return tflow(tflowOpts{resp: true}) }

	t.Run("http", func(t *testing.T) {
		checkAll(t, req(), yes("~http"), no("~tcp"))
	})
	t.Run("asset", func(t *testing.T) {
		s := resp()
		checkAll(t, s, no("~a"))
		s.Response.Headers.Set("content-type", "text/javascript")
		checkAll(t, s, yes("~a"))
	})
	t.Run("fcontenttype", func(t *testing.T) {
		qf, s := req(), resp()
		checkAll(t, qf, no("~t content"))
		checkAll(t, s, no("~t content"))
		qf.Request.Headers.Set("content-type", "text/json")
		checkAll(t, qf, yes("~t json"), yes("~tq json"), no("~ts json"))
		s.Response.Headers.Set("content-type", "text/json")
		checkAll(t, s, yes("~t json"))
		s.Response.Headers.Del("content-type")
		s.Request.Headers.Set("content-type", "text/json")
		checkAll(t, s, yes("~t json"), yes("~tq json"), no("~ts json"))
	})
	t.Run("freq fresp", func(t *testing.T) {
		checkAll(t, req(), yes("~q"), no("~s"))
		checkAll(t, resp(), no("~q"), yes("~s"))
	})
	t.Run("ferr", func(t *testing.T) {
		checkAll(t, tflow(tflowOpts{err: true}), yes("~e"))
	})
	t.Run("fmarked", func(t *testing.T) {
		f := req()
		checkAll(t, f, no("~marked"))
		f.Marked = ":default:"
		checkAll(t, f, yes("~marked"))
	})
	t.Run("fmarker char", func(t *testing.T) {
		f := req()
		f.Marked = ":default:"
		checkAll(t, f, no("~marker X"))
		f.Marked = "X"
		checkAll(t, f, yes("~marker X"))
	})
	t.Run("head", func(t *testing.T) {
		qf, s := req(), resp()
		checkAll(t, qf,
			no("~h nonexistent"), yes("~h qvalue"), yes("~h header"), yes("~h 'header: qvalue'"),
			yes("~hq 'header: qvalue'"), no("~hq 'header-request: svalue'"), no("~hs 'header: qvalue'"))
		checkAll(t, s,
			yes("~h 'header: qvalue'"), yes("~h 'header-response: svalue'"),
			yes("~hq 'header: qvalue'"), no("~hq 'header-response: svalue'"),
			no("~hs 'header: qvalue'"), yes("~hs 'header-response: svalue'"))
	})
	matchBody := func(t *testing.T, qf, s *flow.HTTPFlow) {
		t.Helper()
		checkAll(t, qf, no("~b nonexistent"), yes("~b content"), yes("~bq content"), no("~bq message"), no("~bs content"), no("~bs message"))
		checkAll(t, s, yes("~b message"), no("~bq nomatch"), yes("~bq content"), no("~bq message"))
		for _, text := range []string{"яч", "测试", "ॐ", "لله", "θεός", "לוהים", "神", "하나님", "Äÿ"} {
			s.Response.SetText(text)
			checkAll(t, s, yes("~bs "+text))
		}
		checkAll(t, s, no("~bs nomatch"), no("~bs content"))
		s.Response.SetText("message")
		checkAll(t, s, yes("~bs message"))
	}
	t.Run("body", func(t *testing.T) {
		qf, s := req(), resp()
		matchBody(t, qf, s)

		qf, s = req(), resp()
		for _, m := range []*httpmsg.Message{&qf.Request.Message, &s.Request.Message, &s.Response.Message} {
			if err := m.Encode("gzip"); err != nil {
				t.Fatal(err)
			}
		}
		if string(qf.Request.RawContent) == "content" {
			t.Fatal("Encode(gzip) left the body unencoded")
		}
		matchBody(t, qf, s)
	})
	t.Run("case sensitive", func(t *testing.T) {
		f := req()
		t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", "0")
		checkAll(t, f, yes("~m get"), yes("~m GET"), no("~m post"))
		f.Request.Method = "oink"
		checkAll(t, f, no("~m get"))

		f = req()
		t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", "1")
		checkAll(t, f, no("~m get"), yes("~m GET"), no("~m post"))
		f.Request.Method = "oink"
		checkAll(t, f, no("~m get"))
	})
	t.Run("method", func(t *testing.T) {
		f := req()
		checkAll(t, f, yes("~m get"), no("~m post"))
		f.Request.Method = "oink"
		checkAll(t, f, no("~m get"))
	})
	t.Run("domain", func(t *testing.T) {
		checkAll(t, req(), yes("~d address"), no("~d none"))
	})
	t.Run("url", func(t *testing.T) {
		qf, s := req(), resp()
		checkAll(t, qf, yes("~u address"), yes("~u address:22/path"), no("~u moo/path"))
		qf.Request = nil
		checkAll(t, qf, no("~u address"))
		checkAll(t, s, yes("~u address"), yes("~u address:22/path"), no("~u moo/path"))
	})
	t.Run("code", func(t *testing.T) {
		checkAll(t, req(), no("~c 200"))
		checkAll(t, resp(), yes("~c 200"), no("~c 201"))
	})
	t.Run("src", func(t *testing.T) {
		f := req()
		checkAll(t, f, yes("~src 127.0.0.1"), no("~src foobar"), yes("~src :22"), no("~src :99"), yes("~src 127.0.0.1:22"))
		f.ClientConn.Peername = nil
		checkAll(t, f, no("~src address:22"))
		f.ClientConn = nil
		checkAll(t, f, no("~src address:22"))
	})
	t.Run("dst", func(t *testing.T) {
		f := req()
		f.ServerConn = tserverConn()
		checkAll(t, f, yes("~dst address"), no("~dst foobar"), yes("~dst :22"), no("~dst :99"), yes("~dst address:22"))
		f.ServerConn.Address = nil
		checkAll(t, f, no("~dst address:22"))
		f.ServerConn = nil
		checkAll(t, f, no("~dst address:22"))
	})
	t.Run("and", func(t *testing.T) {
		checkAll(t, resp(),
			yes("~c 200 & ~h head"), no("~c 200 & ~h nohead"), yes("(~c 200 & ~h head) & ~b content"),
			no("(~c 200 & ~h head) & ~b nonexistent"), no("(~c 200 & ~h nohead) & ~b content"))
	})
	t.Run("or", func(t *testing.T) {
		checkAll(t, resp(), yes("~c 200 | ~h nohead"), yes("~c 201 | ~h head"), no("~c 201 | ~h nohead"), yes("(~c 201 | ~h nohead) | ~s"))
	})
	t.Run("not", func(t *testing.T) {
		checkAll(t, resp(), no("! ~c 200"), yes("! ~c 201"), yes("!~c 201 !~c 202"), no("!~c 201 !~c 200"))
	})
	t.Run("replay", func(t *testing.T) {
		f := req()
		checkAll(t, f, no("~replay"))
		f.IsReplay = new("request")
		checkAll(t, f, yes("~replay"), yes("~replayq"), no("~replays"))
		f.IsReplay = new("response")
		checkAll(t, f, yes("~replay"), no("~replayq"), yes("~replays"))
	})
	t.Run("metadata", func(t *testing.T) {
		f := req()
		f.Metadata.Set("a", int64(1))
		f.Metadata.Set("b", "string")
		c := state.NewMap(1)
		c.Set("key", "value")
		f.Metadata.Set("c", c)
		checkAll(t, f,
			yes("~meta a"), no("~meta no"), yes("~meta string"), yes("~meta key"), yes("~meta value"),
			yes(`~meta "b: string"`), yes(`~meta "'key': 'value'"`))
	})
}

func TestMatchingDNSFlow(t *testing.T) {
	t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", "")
	checkAll(t, tdnsflow(false, false), yes("~dns"), no("~http"), no("~tcp"))
	checkAll(t, tdnsflow(false, false), yes("~q"), no("~s"))
	checkAll(t, tdnsflow(true, false), no("~q"), yes("~s"))
	checkAll(t, tdnsflow(false, true), yes("~e"))
	checkAll(t, tdnsflow(false, false), no("~b nonexistent"), yes("~b dns.google"), yes("~bq dns.google"), no("~bs dns.google"))
	checkAll(t, tdnsflow(true, false), yes("~b 8.8.8.8"), no("~bq 8.8.8.8"), yes("~bq dns.google"), yes("~bs dns.google"), yes("~bs 8.8.8.8"))
	checkAll(t, tdnsflow(false, false), no("~u whatever"), yes("~u dns.google"))
}

// messageFlowChecks are the assertions upstream's TCP, UDP and WebSocket
// test classes share; f must have its server connection set.
func messageFlowChecks(t *testing.T, f flow.Flow) {
	t.Helper()
	checkAll(t, f,
		yes("~b hello"), yes("~b me"), no("~b nonexistent"),
		yes("~bq hello"), no("~bq me"), no("~bq nonexistent"),
		yes("~bs me"), no("~bs hello"), no("~bs nonexistent"),
		yes("~src 127.0.0.1"), no("~src foobar"), yes("~src :22"), no("~src :99"), yes("~src 127.0.0.1:22"),
		yes("~dst address"), no("~dst foobar"), yes("~dst :22"), no("~dst :99"), yes("~dst address:22"),
		yes("~b hello & ~b me"), no("~src wrongaddress & ~b hello"), yes("(~src :22 & ~dst :22) & ~b hello"),
		no("(~src address:22 & ~dst :22) & ~b nonexistent"), no("(~src address:22 & ~dst :99) & ~b hello"),
		yes("~b hello | ~b me"), yes("~src :22 | ~b me"), no("~src :99 | ~dst :99"), yes("(~src :22 | ~dst :22) | ~b me"),
		no("! ~src :22"), yes("! ~src :99"), yes("!~src :99 !~src :99"), no("!~src :99 !~src :22"))
}

// notHTTPChecks are the operators upstream's TCP and UDP classes check do
// not match a flow that is not HTTP.
var notHTTPChecks = []check{
	no("~q"), no("~s"), no("~h whatever"), no("~hq whatever"), no("~hs whatever"),
	no("~t whatever"), no("~tq whatever"), no("~ts whatever"), no("~c 200"),
	no("~d whatever"), no("~m whatever"), no("~u whatever"),
}

func TestMatchingTCPFlow(t *testing.T) {
	t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", "")
	checkAll(t, ttcpflow(false), yes("~tcp"), no("~udp"), no("~http"), no("~websocket"))
	checkAll(t, ttcpflow(true), yes("~e"))
	messageFlowChecks(t, ttcpflow(false))
	checkAll(t, ttcpflow(false), notHTTPChecks...)
}

func TestMatchingUDPFlow(t *testing.T) {
	t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", "")
	checkAll(t, tudpflow(false), yes("~udp"), no("~tcp"), no("~http"), no("~websocket"))
	checkAll(t, tudpflow(true), yes("~e"))
	messageFlowChecks(t, tudpflow(false))
	checkAll(t, tudpflow(false), notHTTPChecks...)
}

func TestMatchingWebSocketFlow(t *testing.T) {
	t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", "")
	checkAll(t, twebsocketflow(), yes("~websocket"), no("~tcp"), yes("~http"))
	checkAll(t, tflow(tflowOpts{}), no("~websocket"))
	checkAll(t, tflow(tflowOpts{resp: true}), no("~websocket"))
	checkAll(t, twebsocketflow(), yes("~d example.com"), no("~d none"))
	checkAll(t, twebsocketflow(), yes("~u example.com"), yes("~u example.com/ws"), no("~u moo/path"))
	messageFlowChecks(t, twebsocketflow())
}

func TestMatchingDummyFlow(t *testing.T) {
	t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", "")
	e, f := tdummyflow(true), tdummyflow(false)
	checkAll(t, f,
		yes("~all"), no("~a"), no("~b whatever"), no("~bq whatever"), no("~bs whatever"), no("~c 0"),
		no("~d whatever"), yes("~dst address"), no("~dst nonexistent"), no("~e"),
		no("~http"), no("~tcp"), no("~websocket"), no("~h whatever"), no("~hq whatever"), no("~hs whatever"),
		no("~m whatever"), no("~s"), yes("~src 127.0.0.1"), no("~src nonexistent"),
		no("~t whatever"), no("~tq whatever"), no("~ts whatever"), no("~u whatever"), no("~q"),
		no("~comment ."))
	checkAll(t, e, yes("~e"))
	f.Comment = "comment"
	checkAll(t, f, yes("~comment ."))
}

// TestMatch ports upstream's test_match: a nil filter matches everything.
func TestMatch(t *testing.T) {
	f := tflow(tflowOpts{})
	if !Match(nil, f) {
		t.Error("Match(nil) = false, want true")
	}
	e, err := Parse("foobar")
	if err != nil {
		t.Fatal(err)
	}
	if Match(e, f) {
		t.Error(`Match("foobar") = true, want false`)
	}
	if !Match(MatchAll, tdummyflow(false)) {
		t.Error("MatchAll does not match a dummy flow")
	}
	if _, err := Parse("[foobar"); err == nil {
		t.Error(`Parse("[foobar") succeeded, want error`)
	}
}

// TestMatchSemantics pins behaviour upstream has but its tests do not
// exercise.
func TestMatchSemantics(t *testing.T) {
	t.Setenv("MITMPROXY_CASE_SENSITIVE_FILTERS", "")
	t.Run("asset types are case-sensitive substrings", func(t *testing.T) {
		for ct, want := range map[string]bool{
			"image/png": true, "IMAGE/PNG": false, "font/woff2": true, "application/font-woff": true,
			"text/css; charset=utf-8": true, "x-text/css": true, "text/html": false, "application/json": false,
		} {
			f := tflow(tflowOpts{resp: true})
			f.Response.Headers.Set("Content-Type", ct)
			checkAll(t, f, check{expr: "~a", want: want})
		}
	})
	t.Run("content-type name is case-insensitive", func(t *testing.T) {
		f := tflow(tflowOpts{})
		f.Request.Headers = append(f.Request.Headers, httpmsg.Field{Name: []byte("CONTENT-TYPE"), Value: []byte("text/xml")})
		checkAll(t, f, yes("~tq xml"), no("~ts xml"))
	})
	t.Run("header patterns see the raw block line by line", func(t *testing.T) {
		checkAll(t, tflow(tflowOpts{}), no("~hq ^content-length: 7$"), yes(`~hq "^content-length: 7\r$"`), no("~hq ^qvalue"))
	})
	t.Run("body patterns cross lines and dollar accepts a final newline", func(t *testing.T) {
		f := tflow(tflowOpts{resp: true})
		f.Response.RawContent = []byte("first\nsecond\n")
		checkAll(t, f, yes("~bs first.second"), yes("~bs second$"), no("~bs first$"), yes("~b second$"), no("~bq second$"))
	})
	t.Run("dollar accepts one final newline in a request body, not two", func(t *testing.T) {
		f := tflow(tflowOpts{})
		f.Request.RawContent = []byte("done\n")
		checkAll(t, f, yes(`~b "done$"`))
		f.Request.RawContent = []byte("done\n\n")
		checkAll(t, f, no(`~b "done$"`))
	})
	t.Run("dollar accepts one final newline in a path set directly, not two", func(t *testing.T) {
		f := tflow(tflowOpts{})
		f.Request.Path = "/done\n"
		checkAll(t, f, yes(`~u "done$"`))
		f.Request.Path = "/done\n\n"
		checkAll(t, f, no(`~u "done$"`))
	})
	t.Run("lookahead takes the backtracking engine", func(t *testing.T) {
		f := tflow(tflowOpts{})
		f.Request.RawContent = []byte("fooy")
		checkAll(t, f, yes(`~bq "foo(?!x)"`))
		f.Request.RawContent = []byte("foox")
		checkAll(t, f, no(`~bq "foo(?!x)"`))
	})
	t.Run("a missing body is skipped and an empty one is searched", func(t *testing.T) {
		f := tflow(tflowOpts{})
		f.Request.RawContent = nil
		checkAll(t, f, no(`~bq ""`))
		f.Request.RawContent = []byte{}
		checkAll(t, f, yes(`~bq ""`), yes("~bq ^$"))
	})
	t.Run("undecodable body is matched raw", func(t *testing.T) {
		f := tflow(tflowOpts{})
		f.Request.Headers.Set("content-encoding", "gzip")
		f.Request.RawContent = []byte("not gzip")
		checkAll(t, f, yes("~bq ^not.gzip$"))
	})
	t.Run("domain uses the host header too", func(t *testing.T) {
		f := tflow(tflowOpts{})
		f.Request.Host = "10.0.0.1"
		f.Request.Headers.Set("Host", "example.org:8080")
		checkAll(t, f, yes("~d 10.0.0.1"), yes("~d ^example.org$"), no("~d 8080"))
	})
	t.Run("url is the pretty url", func(t *testing.T) {
		f := tflow(tflowOpts{})
		f.Request.Headers.Set("Host", "example.org")
		checkAll(t, f, yes("~u ^http://example.org/path$"))
	})
	t.Run("ipv6 addresses are not bracketed", func(t *testing.T) {
		f := tflow(tflowOpts{})
		f.ClientConn.Peername = &connection.Address{Host: "::1", Port: 443}
		checkAll(t, f, yes(`~src "^::1:443$"`))
	})
	t.Run("dns url without questions", func(t *testing.T) {
		f := tdnsflow(false, false)
		f.Request.Questions = nil
		checkAll(t, f, no("~u ."))
	})
	t.Run("websocket messages from either side", func(t *testing.T) {
		checkAll(t, twebsocketflow(), yes("~bq binary"), no("~bs binary"), yes(`~bs "^it's me$"`))
	})
	t.Run("status code canonical form", func(t *testing.T) {
		checkAll(t, tflow(tflowOpts{resp: true}), yes("~c 0200"), no("~c 2000"))
	})
	t.Run("operators restricted to http flows", func(t *testing.T) {
		for _, expr := range []string{"~a", "~h .", "~hq .", "~hs .", "~t .", "~tq .", "~ts .", "~m .", "~d .", "~c 200"} {
			checkAll(t, ttcpflow(false), no(expr))
			checkAll(t, tdnsflow(true, false), no(expr))
		}
	})
}

func TestPyStr(t *testing.T) {
	inner := state.NewMap(2)
	inner.Set("k", []any{int64(1), 2.5, nil, true})
	inner.Set("it's", []byte("a'b\x00\xff"))
	tests := map[string]struct {
		v    any
		want string
	}{
		"success: str is itself":         {v: "a'b", want: "a'b"},
		"success: int":                   {v: int64(-3), want: "-3"},
		"success: float repr":            {v: 1e16, want: "1e+16"},
		"success: whole float":           {v: 2.0, want: "2.0"},
		"success: none":                  {v: nil, want: "None"},
		"success: bools":                 {v: []any{true, false}, want: "[True, False]"},
		"success: bytes":                 {v: []byte("ab\n\t\\"), want: `b'ab\n\t\\'`},
		"success: bytes with only quote": {v: []byte("'"), want: `b"'"`},
		"success: bytes with both":       {v: []byte(`'"`), want: `b'\'"'`},
		"success: nested dict":           {v: inner, want: `{'k': [1, 2.5, None, True], "it's": b"a'b\x00\xff"}`},
		"success: str escapes in a list": {v: []any{"\u00e9\u00a0\x7f\u200b\U0001F600\n"}, want: "['\u00e9\\xa0\\x7f\\u200b\U0001F600\\n']"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := pyStr(tt.v); got != tt.want {
				t.Errorf("pyStr(%#v) = %s, want %s", tt.v, got, tt.want)
			}
		})
	}
}

func BenchmarkMatch(b *testing.B) {
	f := tflow(tflowOpts{resp: true})
	f.Response.RawContent = []byte(strings.Repeat("lorem ipsum dolor sit amet ", 400) + "needle")
	benchmarks := map[string]string{
		"url":       "~u address",
		"headers":   `~h "^header-response: svalue$"`,
		"body":      "~bs needle",
		"combined":  "~d address & ~m GET & !~c 404 & ~bs needle",
		"lookahead": `~bs "needle(?!x)"`,
	}
	for name, expr := range benchmarks {
		b.Run(name, func(b *testing.B) {
			e, err := Parse(expr)
			if err != nil {
				b.Fatal(err)
			}
			for b.Loop() {
				if !e.Match(f) {
					b.Fatal("no match")
				}
			}
		})
	}
}
