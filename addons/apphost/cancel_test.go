// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package apphost

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/options"
)

func TestCancelledRequestDoesNotPublish(t *testing.T) {
	tests := map[string]struct {
		respond bool
	}{
		"error: cancelled response":        {respond: true},
		"error: cancelled handler failure": {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			manager := addon.NewManager(options.New(), command.NewManager(), addon.Config{})
			defer manager.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			a := New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				cancel()
				if tt.respond {
					w.WriteHeader(http.StatusOK)
				}
			}), "cancel.test", 0)
			f := flow.NewHTTPFlow(nil, nil, true)
			var err error
			f.Request, err = httpmsg.MakeRequest("GET", "http://cancel.test/", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = manager.Do(ctx, func(ctx context.Context) error { return a.Request(ctx, f) })
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Request = %v, want context.Canceled", err)
			}
			if f.Response != nil || f.Error != nil {
				t.Fatal("cancelled app request published flow state")
			}
		})
	}
}
