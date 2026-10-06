// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layer

import (
	"errors"
	"reflect"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestPacketBounds(t *testing.T) {
	tests := map[string]struct {
		got  int
		want int
	}{
		"portable UDP payload":   {got: MaxUDPPacketBytes, want: 65507},
		"tuple packet count":     {got: PacketQueueCapacity, want: 64},
		"tuple payload bytes":    {got: PacketQueueBytes, want: 1 << 20},
		"listener packet count":  {got: ListenerPacketQueueCapacity, want: 4096},
		"listener payload bytes": {got: ListenerPacketQueueBytes, want: 64 << 20},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, tt.got); diff != "" {
				t.Fatalf("queue limit (-want +got):\n%s", diff)
			}
		})
	}
	if !errors.Is(errors.Join(errors.New("tuple rejected"), ErrPacketOverflow), ErrPacketOverflow) {
		t.Fatal("overflow sentinel lost through an owning-flow error")
	}
}

func TestPacketInterfaceMethods(t *testing.T) {
	tests := map[string]struct {
		typ  reflect.Type
		want []string
	}{
		"transport": {
			typ:  reflect.TypeFor[PacketTransport](),
			want: []string{"Close", "Context", "LocalAddr", "ReadFrom", "RemoteAddr", "SetDeadline", "SetReadDeadline", "SetWriteDeadline", "WriteTo"},
		},
		"recorder": {
			typ:  reflect.TypeFor[PacketRecorder](),
			want: []string{"BufferedPackets", "Close", "Context", "LocalAddr", "PeekPacket", "ReadFrom", "RemoteAddr", "SetDeadline", "SetReadDeadline", "SetWriteDeadline", "StopRecording", "WriteTo"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var got []string
			for method := range tt.typ.Methods() {
				got = append(got, method.Name)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("packet methods (-want +got):\n%s", diff)
			}
		})
	}
}
