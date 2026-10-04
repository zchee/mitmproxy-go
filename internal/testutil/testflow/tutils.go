// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package testflow

import (
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

// TReq returns the HTTP request of upstream's tutils.treq: GET
// http://address:22/path over HTTP/1.1 with the body "content".
// Change its fields to get upstream's keyword overrides.
func TReq() *httpmsg.Request {
	return &httpmsg.Request{
		HTTPVersion:    "HTTP/1.1",
		Headers:        httpmsg.Headers{{Name: []byte("header"), Value: []byte("qvalue")}, {Name: []byte("content-length"), Value: []byte("7")}},
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

// TResp returns the HTTP response of upstream's tutils.tresp: 200 OK over
// HTTP/1.1 with the body "message".
func TResp() *httpmsg.Response {
	return &httpmsg.Response{
		HTTPVersion:    "HTTP/1.1",
		Headers:        httpmsg.Headers{{Name: []byte("header-response"), Value: []byte("svalue")}, {Name: []byte("content-length"), Value: []byte("7")}},
		RawContent:     []byte("message"),
		TimestampStart: 946681202,
		TimestampEnd:   new(946681203.0),
		StatusCode:     200,
		Reason:         "OK",
	}
}

// TDNSReq returns the DNS query of upstream's tutils.tdnsreq: a recursive A
// query for dns.google with ID 42.
func TDNSReq() *dns.Message {
	return &dns.Message{
		ID:               42,
		Query:            true,
		OpCode:           dns.OpCodeQUERY,
		RecursionDesired: true,
		ResponseCode:     dns.ResponseCodeNOERROR,
		Questions:        []dns.Question{{Name: "dns.google", Type: dns.TypeA, Class: dns.ClassIN}},
		Answers:          []dns.ResourceRecord{},
		Authorities:      []dns.ResourceRecord{},
		Additionals:      []dns.ResourceRecord{},
		Timestamp:        new(946681200.0),
	}
}

// TDNSResp returns the DNS response of upstream's tutils.tdnsresp: the answer
// to TDNSReq with the A records 8.8.8.8 and 8.8.4.4.
func TDNSResp() *dns.Message {
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
		Authorities: []dns.ResourceRecord{},
		Additionals: []dns.ResourceRecord{},
		Timestamp:   new(946681201.0),
	}
}
