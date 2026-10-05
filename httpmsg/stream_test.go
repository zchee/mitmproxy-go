// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

import (
	"bytes"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow/state"
)

func TestStreamingFields(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		message func() (*Message, func() *Message, func() *state.Map, func(*state.Map) (*Message, error))
	}{
		"success: request": {
			message: func() (*Message, func() *Message, func() *state.Map, func(*state.Map) (*Message, error)) {
				r := tReq()
				return &r.Message, func() *Message { return &r.Clone().Message }, r.GetState, func(s *state.Map) (*Message, error) {
					decoded, err := RequestFromState(s)
					if err != nil {
						return nil, err
					}
					return &decoded.Message, nil
				}
			},
		},
		"success: response": {
			message: func() (*Message, func() *Message, func() *state.Map, func(*state.Map) (*Message, error)) {
				r := tResp()
				return &r.Message, func() *Message { return &r.Clone().Message }, r.GetState, func(s *state.Map) (*Message, error) {
					decoded, err := ResponseFromState(s)
					if err != nil {
						return nil, err
					}
					return &decoded.Message, nil
				}
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			message, clone, getState, decode := tt.message()
			before := getState()
			message.Stream = true
			message.StreamFunc = func(chunk []byte) [][]byte { return [][]byte{bytes.ToUpper(chunk)} }
			copied := clone()
			if !copied.Stream || copied.StreamFunc == nil {
				t.Fatal("Clone lost streaming configuration")
			}
			if diff := gocmp.Diff([][]byte{[]byte("ABC")}, copied.StreamFunc([]byte("abc"))); diff != "" {
				t.Errorf("cloned StreamFunc (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(before, getState()); diff != "" {
				t.Errorf("streaming configuration changed persisted state (-before +after):\n%s", diff)
			}
			decoded, err := decode(getState())
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Stream || decoded.StreamFunc != nil {
				t.Error("decoded message retained non-persistent streaming configuration")
			}
		})
	}
}
