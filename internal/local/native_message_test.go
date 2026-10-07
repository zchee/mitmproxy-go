// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestNativePacketWire(t *testing.T) {
	pid, name := uint32(123), "synthetic-redirector"
	packet := &PacketWithMeta{Data: []byte("synthetic IP packet"), TunnelInfo: &TunnelInfo{Pid: &pid, ProcessName: &name}}
	good, err := proto.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		wire    []byte
		wantErr bool
	}{
		"success: raw message preserves metadata": {wire: good},
		"error: IPC envelope overflow":            {wire: make([]byte, maxNativeIPCMessageSize+1), wantErr: true},
		"error: malformed protobuf":               {wire: []byte{0xff}, wantErr: true},
		"error: excessive unknown group nesting":  {wire: append(bytes.Repeat([]byte{0x0b}, 32), bytes.Repeat([]byte{0x0c}, 32)...), wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := decodeNativePacket(test.wire)
			if (err != nil) != test.wantErr {
				t.Fatalf("decodeNativePacket() = %v, %v", got, err)
			}
			if !test.wantErr && !proto.Equal(got, packet) {
				t.Fatalf("packet = %v, want %v", got, packet)
			}
		})
	}
}

func TestNativeGroupBounds(t *testing.T) {
	tests := map[string]struct {
		groups  int
		tunnel  bool
		wantErr bool
	}{
		"success: top-level group depth limit":  {groups: 16},
		"error: top-level group depth overflow": {groups: 17, wantErr: true},
		"success: tunnel group depth limit":     {groups: 15, tunnel: true},
		"error: tunnel group depth overflow":    {groups: 16, tunnel: true, wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var wire []byte
			for range test.groups {
				wire = protowire.AppendTag(wire, 99, protowire.StartGroupType)
			}
			for range test.groups {
				wire = protowire.AppendTag(wire, 99, protowire.EndGroupType)
			}
			if test.tunnel {
				body := wire
				wire = protowire.AppendTag(nil, 2, protowire.BytesType)
				wire = protowire.AppendBytes(wire, body)
			}
			if _, err := decodeNativePacket(wire); (err != nil) != test.wantErr {
				t.Fatalf("group depth %d, tunnel %v: error = %v, want error %v", test.groups, test.tunnel, err, test.wantErr)
			}
		})
	}
}

func TestNativeProxyWire(t *testing.T) {
	tests := map[string]struct {
		message *FromProxy
		wantErr bool
	}{
		"success: packet envelope":             {message: &FromProxy{Message: &FromProxy_Packet{Packet: &Packet{Data: []byte("synthetic packet")}}}},
		"success: disabled intercept envelope": {message: &FromProxy{Message: &FromProxy_InterceptConf{InterceptConf: new(InterceptConf)}}},
		"error: packet overflow":               {message: &FromProxy{Message: &FromProxy_Packet{Packet: &Packet{Data: make([]byte, maxNativePacketSize+1)}}}, wantErr: true},
		"error: intercept envelope overflow":   {message: &FromProxy{Message: &FromProxy_InterceptConf{InterceptConf: &InterceptConf{Actions: []string{string(make([]byte, maxNativeIPCMessageSize))}}}}, wantErr: true},
		"error: missing message":               {message: new(FromProxy), wantErr: true},
		"error: nil message":                   {wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			wire, err := encodeNativeProxy(test.message)
			if (err != nil) != test.wantErr {
				t.Fatalf("encodeNativeProxy() = %d bytes, %v", len(wire), err)
			}
			if test.wantErr {
				if len(wire) != 0 {
					t.Fatal("invalid native envelope produced partial bytes")
				}
				return
			}
			var got FromProxy
			if err := proto.Unmarshal(wire, &got); err != nil || !proto.Equal(&got, test.message) {
				t.Fatalf("raw native message = %v, %v", &got, err)
			}
		})
	}
	if _, err := decodeNativePacket(make([]byte, maxNativeIPCMessageSize+1)); !errors.Is(err, errNativeMessageTooLarge) {
		t.Fatalf("IPC bound error = %v", err)
	}
}
