// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/h2"
)

func TestHTTP2DriverBodyTransforms(t *testing.T) {
	tests := map[string]struct {
		transform string
		want      string
	}{
		"success: buffered append settles original DATA":                     {want: "abc"},
		"success: expansion writes all output before settling original DATA": {transform: "expand", want: "abcabc"},
		"success: deliberate drop settles original DATA":                     {transform: "drop"},
		"success: delayed transform emits its retained bytes at end":         {transform: "delay", want: "abc"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var held []byte
			a := &streamAddon{edit: func(name string, f *flow.HTTPFlow) {
				if name != "requestheaders" || tt.transform == "" {
					return
				}
				f.Request.Stream = true
				f.Request.StreamFunc = func(chunk []byte) [][]byte {
					switch tt.transform {
					case "expand":
						return [][]byte{bytes.Clone(chunk), bytes.Clone(chunk)}
					case "drop":
						return nil
					case "delay":
						if len(chunk) != 0 {
							held = append(held, chunk...)
							return nil
						}
						return [][]byte{held}
					default:
						t.Fatalf("unknown transform %q", tt.transform)
						return nil
					}
				}
			}}
			s, _ := newTestStream(t, a)
			peer, source := h2EndpointPair(t)
			destination, origin := h2EndpointPair(t)
			clientID, err := peer.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			serverID, err := destination.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := peer.Send(t.Context(), h2.Event{Kind: h2.Headers, Identity: clientID, Headers: []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "example.com"}}}); err != nil {
				t.Fatal(err)
			}
			head, err := source.Receive(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			client := &http2Server{engine: source, identity: head.Identity, id: 1, normalize: true, head: &head}
			server := &http2Client{engine: destination, identity: serverID, id: 1, normalize: true}
			driver := &streamDriver{stream: s, client: client, server: server}
			done := make(chan error, 1)
			go func() { done <- driver.run(t.Context()) }()
			if err := peer.Send(t.Context(), h2.Event{Kind: h2.Data, Identity: clientID, Data: []byte("abc"), EndStream: true}); err != nil {
				t.Fatal(err)
			}
			request, err := origin.Receive(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var body []byte
			ended := request.EndStream
			for !ended {
				event, err := origin.ReceiveStream(t.Context(), request.Identity)
				if err != nil {
					t.Fatal(err)
				}
				if event.Kind == h2.Data {
					body = append(body, event.Data...)
					if event.Receipt != nil {
						event.Receipt.Complete()
					}
				}
				ended = event.EndStream
			}
			if diff := gocmp.Diff(tt.want, string(body)); diff != "" {
				t.Errorf("transformed body (-want +got):\n%s", diff)
			}
			if err := origin.Send(t.Context(), h2.Event{Kind: h2.Headers, Identity: request.Identity, Headers: []hpack.HeaderField{{Name: ":status", Value: "204"}}, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			response, err := peer.ReceiveStream(t.Context(), clientID)
			if err != nil || response.Kind != h2.Headers || !response.EndStream {
				t.Fatalf("response = %+v, error = %v", response, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			<-source.StreamDone(head.Identity)
			if got := source.Budget().Granted; got != 0 {
				t.Errorf("source grants remain after consumed request: %d", got)
			}
			if diff := gocmp.Diff([]string{"requestheaders", "request", "responseheaders", "response"}, a.calls); diff != "" {
				t.Errorf("hooks (-want +got):\n%s", diff)
			}
		})
	}
}
