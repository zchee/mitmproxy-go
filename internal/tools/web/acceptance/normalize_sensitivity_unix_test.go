// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest && unix

package acceptance_test

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestMitmwebNormalization(t *testing.T) {
	tests := map[string]struct {
		left  string
		right string
		equal bool
	}{
		"ids and timestamp bijections": {
			left:  `{"type":"http","id":"a","timestamp_created":1,"client_conn":{"id":"client","timestamp_start":1},"server_conn":{"id":"server","timestamp_tcp_setup":2},"request":{"timestamp_start":1,"timestamp_end":2}}`,
			right: `{"type":"http","id":"b","timestamp_created":100,"client_conn":{"id":"other-client","timestamp_start":100},"server_conn":{"id":"other-server","timestamp_tcp_setup":200},"request":{"timestamp_start":100,"timestamp_end":200}}`,
			equal: true,
		},
		"numeric spellings denote the same value": {
			left: `{"id":"a","metadata":{"amount":1,"fraction":0.5}}`, right: `{"id":"b","metadata":{"amount":1.0,"fraction":5e-1}}`, equal: true,
		},
		"uint64 metadata is not rounded": {
			left: `{"id":"a","metadata":{"amount":18446744073709551615}}`, right: `{"id":"b","metadata":{"amount":18446744073709551614}}`,
		},
		"shared connection identity survives": {
			left: `{"id":"a","client_conn":{"id":"same"},"server_conn":{"id":"same"}}`, right: `{"id":"b","client_conn":{"id":"one"},"server_conn":{"id":"two"}}`,
		},
		"timestamp equality relations survive": {
			left: `{"id":"a","timestamp_created":1,"request":{"timestamp_start":1}}`, right: `{"id":"b","timestamp_created":100,"request":{"timestamp_start":200}}`,
		},
		"metadata ids are payload": {
			left: `{"id":"a","metadata":{"id":"first"}}`, right: `{"id":"b","metadata":{"id":"second"}}`,
		},
		"metadata timestamps are payload": {
			left: `{"id":"a","metadata":{"timestamp":1}}`, right: `{"id":"b","metadata":{"timestamp":2}}`,
		},
		"header order survives": {
			left: `{"id":"a","request":{"headers":[["X-A","one"],["X-B","two"]]}}`, right: `{"id":"b","request":{"headers":[["X-B","two"],["X-A","one"]]}}`,
		},
		"content hashes survive": {
			left: `{"id":"a","request":{"contentHash":"first"}}`, right: `{"id":"b","request":{"contentHash":"second"}}`,
		},
		"content lengths survive": {
			left: `{"id":"a","request":{"contentLength":1}}`, right: `{"id":"b","request":{"contentLength":2}}`,
		},
		"addresses are not implicitly remapped": {
			left: `{"id":"a","client_conn":{"id":"c","peername":["127.0.0.1",18080]}}`, right: `{"id":"b","client_conn":{"id":"d","peername":["127.0.0.1",18081]}}`,
		},
		"null remains distinct from missing": {
			left: `{"id":"a","response":null}`, right: `{"id":"b"}`,
		},
		"optional null timestamp remains present": {
			left: `{"id":"a","response":{"timestamp_end":null}}`, right: `{"id":"b","response":{}}`,
		},
		"zero is not null": {
			left: `{"id":"a","metadata":{"value":0}}`, right: `{"id":"b","metadata":{"value":null}}`,
		},
		"DNS message ids are not flow ids": {
			left: `{"type":"dns","id":"a","request":{"id":1,"timestamp":10}}`, right: `{"type":"dns","id":"b","request":{"id":2,"timestamp":20}}`,
		},
		"certificate validity is retained": {
			left: `{"id":"a","server_conn":{"id":"c","cert":{"notbefore":1}}}`, right: `{"id":"b","server_conn":{"id":"d","cert":{"notbefore":2}}}`,
		},
		"undeclared HTTP timestamp key is retained": {
			left: `{"type":"http","id":"a","request":{"timestamp":1}}`, right: `{"type":"http","id":"b","request":{"timestamp":2}}`,
		},
		"array order survives": {
			left: `{"id":"a","metadata":{"items":[1,2]}}`, right: `{"id":"b","metadata":{"items":[2,1]}}`,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			left, err := new(webBijections).flow([]byte(tt.left))
			if err != nil {
				t.Fatal(err)
			}
			right, err := new(webBijections).flow([]byte(tt.right))
			if err != nil {
				t.Fatal(err)
			}
			if got := gocmp.Equal(left, right); got != tt.equal {
				t.Fatalf("comparison=%v, want %v; difference (-left +right):\n%s", got, tt.equal, gocmp.Diff(left, right))
			}
		})
	}
}

func TestMitmwebNormalizationRejectsInvalidValues(t *testing.T) {
	tests := map[string]struct{ raw string }{
		"malformed JSON":        {`{"id":`},
		"missing flow id":       {`{}`},
		"numeric flow id":       {`{"id":1}`},
		"array flow":            {`[]`},
		"non-object connection": {`{"id":"a","client_conn":[]}`},
		"non-object request":    {`{"id":"a","request":"bad"}`},
		"nonnumeric timestamp":  {`{"id":"a","timestamp_created":"1"}`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := new(webBijections).flow([]byte(tt.raw)); err == nil {
				t.Fatal("invalid normalization input was accepted")
			}
		})
	}
}
