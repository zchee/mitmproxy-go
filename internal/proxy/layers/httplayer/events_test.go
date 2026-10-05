// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer_test

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/internal/proxy/layers/httplayer"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestEventDirections(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		event   httplayer.Event
		request bool
	}{
		"success: request headers":   {httplayer.RequestHeaders{ID: 42, EndStream: true}, true},
		"success: request data":      {httplayer.RequestData{ID: 42, Data: []byte("body")}, true},
		"success: request trailers":  {httplayer.RequestTrailers{ID: 42}, true},
		"success: request end":       {httplayer.RequestEndOfMessage{ID: 42}, true},
		"success: request error":     {httplayer.RequestProtocolError{ID: 42, Code: httplayer.GenericClientError}, true},
		"success: response headers":  {httplayer.ResponseHeaders{ID: 42, EndStream: true}, false},
		"success: response data":     {httplayer.ResponseData{ID: 42, Data: []byte("body")}, false},
		"success: response trailers": {httplayer.ResponseTrailers{ID: 42}, false},
		"success: response end":      {httplayer.ResponseEndOfMessage{ID: 42}, false},
		"success: response error":    {httplayer.ResponseProtocolError{ID: 42, Code: httplayer.GenericServerError}, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if diff := gocmp.Diff(httplayer.StreamID(42), tt.event.StreamID()); diff != "" {
				t.Errorf("stream identity (-want +got):\n%s", diff)
			}
			_, request := tt.event.(httplayer.RequestEvent)
			_, response := tt.event.(httplayer.ResponseEvent)
			if request != tt.request || response == tt.request {
				t.Errorf("%T directions = (request=%v, response=%v), want request=%v", tt.event, request, response, tt.request)
			}
		})
	}
}

func TestErrorCodeHTTPStatusCode(t *testing.T) {
	t.Parallel()

	// Expected mappings are from mitmproxy/proxy/layers/http/_events.py.
	tests := map[string]struct {
		code   httplayer.ErrorCode
		status int
	}{
		"error: client protocol":       {httplayer.GenericClientError, 400},
		"error: server protocol":       {httplayer.GenericServerError, 502},
		"error: request too large":     {httplayer.RequestTooLarge, 413},
		"error: response too large":    {httplayer.ResponseTooLarge, 502},
		"error: connect failed":        {httplayer.ConnectFailed, 502},
		"success: passthrough close":   {httplayer.PassthroughClose, 0},
		"success: killed":              {httplayer.Kill, 0},
		"success: protocol fallback":   {httplayer.HTTP11Required, 0},
		"error: destination unknown":   {httplayer.DestinationUnknown, 400},
		"success: client disconnected": {httplayer.ClientDisconnected, 0},
		"success: stream cancelled":    {httplayer.Cancel, 0},
		"error: request validation":    {httplayer.RequestValidationFailed, 400},
		"error: response validation":   {httplayer.ResponseValidationFailed, 502},
		"error: unknown code":          {httplayer.ErrorCode(255), 0},
		"error: unset code":            {httplayer.ErrorCode(0), 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			status, ok := tt.code.HTTPStatusCode()
			if diff := gocmp.Diff(tt.status, status); diff != "" {
				t.Errorf("HTTPStatusCode (-want +got):\n%s", diff)
			}
			if ok != (tt.status != 0) {
				t.Errorf("HTTPStatusCode present = %v, want %v", ok, tt.status != 0)
			}
		})
	}
}
