// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/tcp"
)

type metadataView struct{ contentviews.Raw }

func (metadataView) Name() string { return "Metadata" }

func (metadataView) Prettify(_ []byte, metadata contentviews.Metadata) (string, error) {
	return fmt.Sprintf("%s|%s|%s|%t|%t", metadata.ProtobufDefinitions, metadata.ContentType, metadata.Protocol, metadata.HTTPRequest != nil, metadata.Flow != nil), nil
}

func TestContentviewMetadata(t *testing.T) {
	request := &httpmsg.Request{RawContent: []byte("request")}
	request.Headers.Set("content-type", "application/grpc; charset=utf-8")
	response := &httpmsg.Response{RawContent: []byte("response")}
	response.Headers.Set("content-type", "application/x-protobuf")
	f := &flow.HTTPFlow{Request: request, Response: response}
	stale := &httpmsg.Request{RawContent: []byte("stale")}
	tests := map[string]struct {
		message  any
		metadata contentviews.Metadata
		want     string
	}{
		"request":                      {request, contentviews.Metadata{Flow: f, ProtobufDefinitions: "schemas"}, "schemas|application/grpc|http|true|true"},
		"response":                     {response, contentviews.Metadata{Flow: f, ProtobufDefinitions: "schemas", HTTPRequest: stale}, "schemas|application/x-protobuf|http|false|true"},
		"explicit request message":     {&request.Message, contentviews.Metadata{Flow: f, ProtobufDefinitions: "schemas"}, "schemas|application/grpc|http|true|true"},
		"explicit response message":    {&response.Message, contentviews.Metadata{Flow: f, ProtobufDefinitions: "schemas", HTTPRequest: request}, "schemas|application/x-protobuf|http|false|true"},
		"flowless request":             {request, contentviews.Metadata{ProtobufDefinitions: "schemas"}, "schemas|application/grpc|http|true|false"},
		"flowless response":            {response, contentviews.Metadata{ProtobufDefinitions: "schemas"}, "schemas|application/x-protobuf|http|false|false"},
		"optional metadata":            {request, contentviews.Metadata{}, "|application/grpc|http|true|false"},
		"clear stale message pointers": {&tcp.Message{Content: []byte("tcp")}, contentviews.Metadata{ContentType: "wrong", HTTPMessage: &stale.Message, HTTPRequest: stale}, "||tcp|false|false"},
	}
	registry := contentviews.NewRegistry()
	registry.Register(metadataView{})
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			before := tt.metadata
			got := PrettifyMessageWithMetadata(tt.message, tt.metadata, "Metadata", registry, 0)
			if got.Err != nil {
				t.Fatal(got.Err)
			}
			if diff := cmp.Diff(tt.want, got.Text); diff != "" {
				t.Fatalf("metadata rendering (-want +got):\n%s", diff)
			}
			if tt.metadata.Flow != before.Flow || tt.metadata.ProtobufDefinitions != before.ProtobufDefinitions || tt.metadata.HTTPRequest != before.HTTPRequest || tt.metadata.HTTPMessage != before.HTTPMessage {
				t.Fatal("supplied metadata was mutated")
			}
		})
	}
	var calls sync.WaitGroup
	for range 20 {
		calls.Go(func() {
			metadata := contentviews.Metadata{Flow: f, ProtobufDefinitions: "schemas"}
			got := PrettifyMessageWithMetadata(request, metadata, "Metadata", registry, 0)
			if got.Err != nil || got.Text != "schemas|application/grpc|http|true|true" {
				t.Errorf("concurrent rendering: %+v", got)
			}
		})
	}
	calls.Wait()
	if string(request.RawContent) != "request" || string(response.RawContent) != "response" {
		t.Fatal("message content mutated")
	}
}

func TestMessagePreservation(t *testing.T) {
	tests := map[string]struct {
		message any
		view    string
		cutoff  int
	}{
		"raw":            {&httpmsg.Message{RawContent: []byte("one\ntwo")}, "Raw", 0},
		"cutoff":         {&httpmsg.Message{RawContent: []byte("one\ntwo")}, "Raw", 1},
		"automatic":      {&httpmsg.Message{RawContent: []byte("body")}, "auto", 0},
		"missing":        {nil, "", 0},
		"typed nil":      {(*httpmsg.Request)(nil), "auto", 0},
		"unknown view":   {&httpmsg.Message{RawContent: []byte("body")}, "invalid", 0},
		"unsupported":    {42, "Raw", 0},
		"escape control": {&httpmsg.Message{RawContent: []byte("a\x00b")}, "Raw", 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			want := contentviews.PrettifyMessage(tt.message, nil, tt.view, nil, tt.cutoff)
			got := PrettifyMessage(tt.message, nil, tt.view, nil, tt.cutoff)
			if (got.Err == nil) != (want.Err == nil) || got.Err != nil && got.Err.Error() != want.Err.Error() {
				t.Fatalf("error got=%v want=%v", got.Err, want.Err)
			}
			if name == "unsupported" && !errors.Is(got.Err, contentviews.ErrUnsupportedMessage) {
				t.Fatal("unsupported-message cause lost")
			}
			got.Err, want.Err = nil, nil
			if diff := cmp.Diff(want, got); diff != "" {
				t.Fatalf("existing result changed (-want +got):\n%s", diff)
			}
		})
	}
}
