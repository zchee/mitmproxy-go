// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"context"
	"net"
	"reflect"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func TestRedirectorContract(t *testing.T) {
	packetMethods := map[string]reflect.Type{
		"Launch":       reflect.TypeFor[func(context.Context) error](),
		"SetIntercept": reflect.TypeFor[func(context.Context, string) error](),
		"ReadPacket":   reflect.TypeFor[func(context.Context) (*PacketWithMeta, error)](),
		"WritePacket":  reflect.TypeFor[func(context.Context, *Packet) error](),
		"Close":        reflect.TypeFor[func() error](),
	}
	tests := map[string]struct {
		contract reflect.Type
		streams  bool
	}{
		"success: native packet contract": {contract: reflect.TypeFor[Redirector]()},
		"success: native stream supplement": {
			contract: reflect.TypeFor[StreamRedirector](), streams: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			methodCount := len(packetMethods)
			for name, expected := range packetMethods {
				method, ok := test.contract.MethodByName(name)
				if !ok || method.Type != expected {
					t.Fatalf("%s.%s type = %v, want %v", test.contract, name, method.Type, expected)
				}
			}
			if test.streams {
				methodCount += 2
				streamMethods := map[string]reflect.Type{
					"AcceptTCP": reflect.TypeFor[func(context.Context) (net.Conn, *TcpFlow, error)](),
					"AcceptUDP": reflect.TypeFor[func(context.Context) (layer.PacketTransport, *UdpFlow, error)](),
				}
				for name, expected := range streamMethods {
					method, ok := test.contract.MethodByName(name)
					if !ok || method.Type != expected {
						t.Fatalf("%s.%s type = %v, want %v", test.contract, name, method.Type, expected)
					}
				}
			}
			if got := test.contract.NumMethod(); got != methodCount {
				t.Fatalf("%s exposes %d methods, want %d", test.contract, got, methodCount)
			}
		})
	}
}
