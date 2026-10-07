// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

// These are protoc encoder vectors, not captures from an installed redirector.
func TestSyntheticIPCDecode(t *testing.T) {
	ipPacket := []byte{0x45, 0, 0, 0x14, 0, 0, 0, 0, 0x40, 1, 0, 0, 0x7f, 0, 0, 1, 0xc0, 0, 2, 1}
	tests := map[string]struct {
		file     string
		framed   bool
		expected proto.Message
	}{
		"synthetic macOS control": {
			file: "intercept.frame", framed: true,
			expected: &InterceptConf{Actions: []string{"curl", "!42"}},
		},
		"synthetic macOS TCP handshake": {
			file: "new_tcp.frame", framed: true,
			expected: &NewFlow{Message: &NewFlow_Tcp{Tcp: &TcpFlow{
				RemoteAddress: &Address{Host: "example.test", Port: 443},
				TunnelInfo:    &TunnelInfo{Pid: proto.Uint32(2242), ProcessName: new("curl")},
			}}},
		},
		"synthetic macOS UDP handshake with present zero values": {
			file: "new_udp.frame", framed: true,
			expected: &NewFlow{Message: &NewFlow_Udp{Udp: &UdpFlow{
				LocalAddress: &Address{Host: "127.0.0.1", Port: 53000},
				TunnelInfo:   &TunnelInfo{Pid: proto.Uint32(0), ProcessName: new("")},
			}}},
		},
		"synthetic macOS UDP packet": {
			file: "udp_packet.frame", framed: true,
			expected: &UdpPacket{
				Data:          []byte{0, 0xff, 'D', 'N', 'S'},
				RemoteAddress: &Address{Host: "::1", Port: 53},
			},
		},
		"synthetic Windows attributed packet": {
			file: "packet_meta.pb",
			expected: &PacketWithMeta{
				Data:       ipPacket,
				TunnelInfo: &TunnelInfo{Pid: proto.Uint32(2242), ProcessName: new("curl.exe")},
			},
		},
		"synthetic Windows control envelope": {
			file: "from_proxy_intercept.pb",
			expected: &FromProxy{Message: &FromProxy_InterceptConf{
				InterceptConf: &InterceptConf{Actions: []string{"curl", "!42"}},
			}},
		},
		"synthetic Windows packet envelope": {
			file: "from_proxy_packet.pb",
			expected: &FromProxy{Message: &FromProxy_Packet{
				Packet: &Packet{Data: []byte{0, 0xff, 'r', 'e', 'p', 'l', 'y'}},
			}},
		},
		"synthetic Linux control datagram without a length prefix": {
			file:     "intercept.pb",
			expected: &InterceptConf{Actions: []string{"curl", "!42"}},
		},
		"synthetic Linux packet datagram without attribution or a length prefix": {
			file:     "linux_packet.pb",
			expected: &PacketWithMeta{Data: ipPacket},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			wire, err := os.ReadFile(filepath.Join("..", "..", "testdata", "local-ipc", "synthetic", test.file))
			if err != nil {
				t.Fatal(err)
			}
			if test.framed {
				if len(wire) < 4 {
					t.Fatalf("frame has %d bytes, missing length prefix", len(wire))
				}
				length := binary.BigEndian.Uint32(wire[:4])
				if uint64(length) != uint64(len(wire)-4) {
					t.Fatalf("frame length = %d, payload bytes = %d", length, len(wire)-4)
				}
				wire = wire[4:]
			}
			actual := test.expected.ProtoReflect().New().Interface()
			if err := proto.Unmarshal(wire, actual); err != nil {
				t.Fatalf("decode %s: %v", test.file, err)
			}
			if diff := gocmp.Diff(test.expected, actual, protocmp.Transform()); diff != "" {
				t.Fatalf("decoded %s (-want +got):\n%s", test.file, diff)
			}
			encoded, err := proto.Marshal(actual)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(wire, encoded); diff != "" {
				t.Fatalf("re-encoded %s (-want +got):\n%s", test.file, diff)
			}
		})
	}
}

func TestSyntheticIPCWireSemantics(t *testing.T) {
	tests := map[string]struct {
		wire     []byte
		expected proto.Message
		wantErr  bool
	}{
		"absent tunnel fields stay absent": {
			wire: []byte{}, expected: &TunnelInfo{},
		},
		"present empty local address stays present": {
			wire: []byte{0x0a, 0}, expected: &UdpFlow{LocalAddress: &Address{}},
		},
		"absent local address stays absent": {
			wire: []byte{}, expected: &UdpFlow{},
		},
		"last oneof variant wins": {
			wire:     []byte{0x0a, 0, 0x12, 0},
			expected: &NewFlow{Message: &NewFlow_Udp{Udp: &UdpFlow{}}},
		},
		"truncated field length": {
			wire: []byte{0x0a, 0x80}, expected: &PacketWithMeta{}, wantErr: true,
		},
		"declared payload exceeds remaining bytes": {
			wire:     []byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f},
			expected: &PacketWithMeta{}, wantErr: true,
		},
		"truncated nested tunnel": {
			wire: []byte{0x12, 2, 0x08}, expected: &PacketWithMeta{}, wantErr: true,
		},
		"invalid wire type": {
			wire: []byte{0x0f}, expected: &PacketWithMeta{}, wantErr: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actual := test.expected.ProtoReflect().New().Interface()
			err := proto.Unmarshal(test.wire, actual)
			if (err != nil) != test.wantErr {
				t.Fatalf("Unmarshal() error = %v, want error = %v", err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			if diff := gocmp.Diff(test.expected, actual, protocmp.Transform()); diff != "" {
				t.Fatalf("decoded message (-want +got):\n%s", diff)
			}
		})
	}
}
