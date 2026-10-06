// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layer_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestContextPacketFields(t *testing.T) {
	tests := map[string]struct {
		want reflect.Type
	}{
		"ClientPackets": {want: reflect.TypeFor[layer.PacketRecorder]()},
		"ServerPackets": {want: reflect.TypeFor[layer.PacketRecorder]()},
		"RecordPackets": {want: reflect.TypeFor[func(layer.PacketTransport) layer.PacketRecorder]()},
		"OpenPackets":   {want: reflect.TypeFor[func(context.Context, *connection.Server) (layer.PacketTransport, *connection.Server, error)]()},
		"Clock":         {want: reflect.TypeFor[layer.Clock]()},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			field, ok := reflect.TypeFor[layer.Context]().FieldByName(name)
			if !ok {
				t.Fatalf("Context is missing %s", name)
			}
			if field.Type != test.want {
				t.Fatalf("Context.%s type = %v, want %v", name, field.Type, test.want)
			}
		})
	}
}

func TestWallClock(t *testing.T) {
	if layer.WallClock == nil {
		t.Fatal("WallClock must provide a default clock")
	}
	before := time.Now()
	got := layer.WallClock.Now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Fatalf("Now = %v, outside [%v, %v]", got, before, after)
	}
	tests := map[string]struct {
		stopFirst bool
	}{
		"callback fires":         {},
		"stop prevents callback": {stopFirst: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			done := make(chan struct{})
			delay := time.Duration(0)
			if test.stopFirst {
				delay = time.Hour
			}
			stop := layer.WallClock.AfterFunc(delay, func() { close(done) })
			t.Cleanup(func() { stop() })
			if test.stopFirst {
				if diff := cmp.Diff(true, stop()); diff != "" {
					t.Fatalf("stopping pending callback (-want +got):\n%s", diff)
				}
				if stop() {
					t.Fatal("stopping a canceled callback twice succeeded")
				}
				select {
				case <-done:
					t.Fatal("stopped callback ran")
				default:
				}
				return
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("timer callback did not signal completion")
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			}
			if stop() {
				t.Fatal("stopping a completed callback succeeded")
			}
		})
	}
}
