// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package testflow builds the flows, connections and messages that upstream's
// tests build with mitmproxy/test/tflow.py and mitmproxy/test/tutils.py, with
// the same field values, so that tests ported from upstream read the same.
//
// Upstream's keyword flags resp=True, err=True and ws=True are the [With]
// flags; any other keyword override is an assignment to a field of the
// returned value:
//
//	f := testflow.TFlow(testflow.WithResponse) // tflow(resp=True)
//	f.Request.Method = "POST"                  // tflow(req=treq(method=b"POST"), resp=True)
//
// The connection and flow IDs are random UUIDs, as upstream's are; every other
// field is deterministic except the creation timestamp of [TWebSocketFlow].
//
// The package imports the flow model packages, so their internal tests
// (package flow, package http, ...) cannot import it; external test packages
// (package flow_test) can.
package testflow

import (
	"fmt"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/http"
	"github.com/zchee/mitmproxy-go/internal/state"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

// With adds an optional part to a flow built by the T*Flow functions. Each
// flag is one of upstream's keyword flags; a builder panics when given a flag
// its upstream counterpart does not take.
type With uint8

const (
	// WithResponse adds a response: tflow(resp=True) and tdnsflow(resp=True).
	WithResponse With = 1 << iota
	// WithError adds the error of TErr: err=True. For TWebSocketFlow it
	// sets the abnormal close code instead, as upstream does.
	WithError
	// WithWebSocket adds the WebSocket data of TWebSocket: tflow(ws=True).
	WithWebSocket
)

func (w With) String() string {
	switch w {
	case WithResponse:
		return "WithResponse"
	case WithError:
		return "WithError"
	case WithWebSocket:
		return "WithWebSocket"
	default:
		return fmt.Sprintf("With(%d)", uint8(w))
	}
}

// collect merges flags into one set, panicking when a flag is not in allowed.
func collect(builder string, allowed With, flags []With) With {
	var set With
	for _, w := range flags {
		if w&^allowed != 0 || w == 0 {
			panic(fmt.Sprintf("testflow.%s: %v does not apply", builder, w))
		}
		set |= w
	}
	return set
}

// TFlow returns the HTTP flow of upstream's tflow: TReq over TClientConn and
// TServerConn, live, created at the request's start. The flags add TResp,
// TErr and TWebSocket.
func TFlow(flags ...With) *flow.HTTPFlow {
	set := collect("TFlow", WithResponse|WithError|WithWebSocket, flags)

	f := flow.NewHTTPFlow(TClientConn(), TServerConn(), true)
	f.Request = TReq()
	f.TimestampCreated = f.Request.TimestampStart
	if set&WithResponse != 0 {
		f.Response = TResp()
	}
	if set&WithError != 0 {
		f.Error = TErr()
	}
	if set&WithWebSocket != 0 {
		f.WebSocket = TWebSocket()
	}
	return f
}

// TTCPFlow returns the TCP flow of upstream's ttcpflow: two messages, "hello"
// from the client and "it's me" from the server, live, created at the client
// connection's start. WithError adds TErr.
func TTCPFlow(flags ...With) *flow.TCPFlow {
	set := collect("TTCPFlow", WithError, flags)

	f := flow.NewTCPFlow(TClientConn(), TServerConn(), true)
	f.TimestampCreated = *f.ClientConn.TimestampStart
	f.Messages = []*tcp.Message{
		{FromClient: true, Content: []byte("hello"), Timestamp: 946681204.2},
		{FromClient: false, Content: []byte("it's me"), Timestamp: 946681204.5},
	}
	if set&WithError != 0 {
		f.Error = TErr()
	}
	return f
}

// TUDPFlow returns the UDP flow of upstream's tudpflow, which has the same
// messages and timestamps as TTCPFlow. WithError adds TErr.
func TUDPFlow(flags ...With) *flow.UDPFlow {
	set := collect("TUDPFlow", WithError, flags)

	f := flow.NewUDPFlow(TClientConn(), TServerConn(), true)
	f.TimestampCreated = *f.ClientConn.TimestampStart
	f.Messages = []*udp.Message{
		{FromClient: true, Content: []byte("hello"), Timestamp: 946681204.2},
		{FromClient: false, Content: []byte("it's me"), Timestamp: 946681204.5},
	}
	if set&WithError != 0 {
		f.Error = TErr()
	}
	return f
}

// TDNSFlow returns the DNS flow of upstream's tdnsflow: TDNSReq over a UDP
// client connection in dns proxy mode and a UDP server connection, live,
// created at the query's timestamp. The flags add TDNSResp and TErr.
func TDNSFlow(flags ...With) *flow.DNSFlow {
	set := collect("TDNSFlow", WithResponse|WithError, flags)

	client := TClientConn()
	client.ProxyMode = "dns"
	client.TransportProtocol = connection.UDP
	server := TServerConn()
	server.TransportProtocol = connection.UDP

	f := flow.NewDNSFlow(client, server, true)
	f.Request = TDNSReq()
	f.TimestampCreated = *f.Request.Timestamp
	if set&WithResponse != 0 {
		f.Response = TDNSResp()
	}
	if set&WithError != 0 {
		f.Error = TErr()
	}
	return f
}

// TWebSocketFlow returns the flow of upstream's twebsocketflow: a GET of
// ws://example.com/ws answered by 101 Switching Protocols, with the messages
// of TWebSocket, an empty close reason and the close code 1000.
//
// WithError sets the close code to 1006 (abnormal closure) and, as upstream,
// leaves the flow's Error nil. Unlike the other builders, the flow is created
// now, because upstream does not set its creation timestamp.
func TWebSocketFlow(flags ...With) *flow.HTTPFlow {
	set := collect("TWebSocketFlow", WithError, flags)

	f := flow.NewHTTPFlow(TClientConn(), TServerConn(), true)
	f.Request = &http.Request{
		HTTPVersion: "HTTP/1.1",
		Headers: http.Headers{
			{Name: []byte("connection"), Value: []byte("upgrade")},
			{Name: []byte("upgrade"), Value: []byte("websocket")},
			{Name: []byte("sec-websocket-version"), Value: []byte("13")},
			{Name: []byte("sec-websocket-key"), Value: []byte("1234")},
		},
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
	f.Response = &http.Response{
		HTTPVersion: "HTTP/1.1",
		Headers: http.Headers{
			{Name: []byte("connection"), Value: []byte("upgrade")},
			{Name: []byte("upgrade"), Value: []byte("websocket")},
			{Name: []byte("sec-websocket-accept"), Value: []byte{}},
		},
		RawContent:     []byte{},
		TimestampStart: 946681202,
		TimestampEnd:   new(946681203.0),
		StatusCode:     101,
		Reason:         "Switching Protocols",
	}
	f.WebSocket = TWebSocket()
	f.WebSocket.CloseReason = new("")
	if set&WithError != 0 {
		f.WebSocket.CloseCode = new(1006)
	} else {
		f.WebSocket.CloseCode = new(1000)
	}
	return f
}

// TClientConn returns the client connection of upstream's tclient_conn: an
// open TCP connection from 127.0.0.1:22 in regular proxy mode with TLS
// metadata but TLS not in use.
func TClientConn() *connection.Client {
	return &connection.Client{
		Peername:          &connection.Address{Host: "127.0.0.1", Port: 22},
		Sockname:          &connection.Address{Host: "", Port: 0},
		State:             connection.Open,
		ID:                state.NewID(),
		TransportProtocol: connection.TCP,
		CertificateList:   [][]byte{},
		ALPN:              []byte("http/1.1"),
		ALPNOffers:        [][]byte{},
		Cipher:            new("cipher"),
		CipherList:        []string{},
		TLSVersion:        connection.TLSv1_2,
		SNI:               new("address"),
		TimestampStart:    new(946681200.0),
		TimestampEnd:      new(946681206.0),
		TimestampTLSSetup: new(946681201.0),
		ProxyMode:         "regular",
	}
}

// TServerConn returns the server connection of upstream's tserver_conn: a
// closed TCP connection to address:22 (peer 192.168.0.1:22) with TLS metadata
// but TLS not in use.
func TServerConn() *connection.Server {
	return &connection.Server{
		Peername:          &connection.Address{Host: "192.168.0.1", Port: 22},
		Sockname:          &connection.Address{Host: "address", Port: 22},
		State:             connection.Closed,
		ID:                state.NewID(),
		TransportProtocol: connection.TCP,
		CertificateList:   [][]byte{},
		ALPNOffers:        [][]byte{},
		CipherList:        []string{},
		TLSVersion:        connection.TLSv1_2,
		SNI:               new("address"),
		TimestampStart:    new(946681202.0),
		TimestampEnd:      new(946681205.0),
		TimestampTLSSetup: new(946681204.0),
		Address:           &connection.Address{Host: "address", Port: 22},
		TimestampTCPSetup: new(946681203.0),
	}
}

// TErr returns the flow error of upstream's terr: the message "error" at
// 946681207.
func TErr() *flow.Error {
	return &flow.Error{Msg: "error", Timestamp: 946681207}
}

// TWebSocket returns the WebSocket data of upstream's twebsocket: a binary
// and a text message from the client and a text message from the server,
// closed normally by the server with the reason "Close Reason".
func TWebSocket() *websocket.Data {
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

// TFlows returns one flow of each kind, as upstream's tflows does: HTTP flows
// with a response, an error and WebSocket data; TCP and UDP flows with and
// without an error; and DNS flows with a response, without questions and with
// an error.
func TFlows() []flow.Flow {
	noQuestions := TDNSFlow()
	noQuestions.Request.Questions = []dns.Question{}
	return []flow.Flow{
		TFlow(WithResponse),
		TFlow(WithError),
		TFlow(WithWebSocket),
		TTCPFlow(),
		TTCPFlow(WithError),
		TUDPFlow(),
		TUDPFlow(WithError),
		TDNSFlow(WithResponse),
		noQuestions,
		TDNSFlow(WithError),
	}
}
