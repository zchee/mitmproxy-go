// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/tcp"
)

type metadataView struct{ Raw }

func (metadataView) Name() string { return "Metadata" }

func (metadataView) Prettify(_ []byte, metadata Metadata) (string, error) {
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
		metadata Metadata
		want     string
	}{
		"request":                      {request, Metadata{Flow: f, ProtobufDefinitions: "schemas"}, "schemas|application/grpc|http|true|true"},
		"response":                     {response, Metadata{Flow: f, ProtobufDefinitions: "schemas", HTTPRequest: stale}, "schemas|application/x-protobuf|http|false|true"},
		"explicit request message":     {&request.Message, Metadata{Flow: f, ProtobufDefinitions: "schemas"}, "schemas|application/grpc|http|true|true"},
		"explicit response message":    {&response.Message, Metadata{Flow: f, ProtobufDefinitions: "schemas", HTTPRequest: request}, "schemas|application/x-protobuf|http|false|true"},
		"flowless request":             {request, Metadata{ProtobufDefinitions: "schemas"}, "schemas|application/grpc|http|true|false"},
		"flowless response":            {response, Metadata{ProtobufDefinitions: "schemas"}, "schemas|application/x-protobuf|http|false|false"},
		"optional metadata":            {request, Metadata{}, "|application/grpc|http|true|false"},
		"clear stale message pointers": {&tcp.Message{Content: []byte("tcp")}, Metadata{ContentType: "wrong", HTTPMessage: &stale.Message, HTTPRequest: stale}, "||tcp|false|false"},
	}
	registry := NewRegistry()
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
			metadata := Metadata{Flow: f, ProtobufDefinitions: "schemas"}
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
	t.Run("definitions_home", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		absolute := filepath.Join(home, "absolute.proto")
		tests := map[string]struct {
			option *string
			want   string
		}{
			"home file":    {new("~/schemas/service.proto"), filepath.Join(home, "schemas", "service.proto")},
			"bare home":    {new("~"), home},
			"home slash":   {new("~/"), home},
			"home dot":     {new("~/./schemas"), filepath.Join(home, "schemas")},
			"absolute":     {new(absolute), absolute},
			"relative":     {new("schemas/service.proto"), "schemas/service.proto"},
			"empty option": {new(""), ""},
			"nil option":   {nil, ""},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				metadata := Metadata{Flow: f}
				if tt.option != nil {
					metadata.ProtobufDefinitions = *tt.option
				}
				original := metadata.ProtobufDefinitions
				got := PrettifyMessageWithMetadata(request, metadata, "Metadata", registry, 0)
				if got.Err != nil {
					t.Fatal(got.Err)
				}
				if diff := cmp.Diff(tt.want+"|application/grpc|http|true|true", got.Text); diff != "" {
					t.Fatal(diff)
				}
				if metadata.ProtobufDefinitions != original {
					t.Fatal("caller metadata was mutated by home expansion")
				}
			})
		}
	})
}
