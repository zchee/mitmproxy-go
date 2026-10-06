// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package hookdata

import "testing"

func TestPacketAndWebSocketLayerKinds(t *testing.T) {
	tests := map[string]struct {
		kind LayerKind
		want string
	}{
		"UDP":         {kind: LayerUDP, want: "udp"},
		"WebSocket":   {kind: LayerWebSocket, want: "websocket"},
		"client DTLS": {kind: LayerClientDTLS, want: "clientdtls"},
		"server DTLS": {kind: LayerServerDTLS, want: "serverdtls"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if string(tt.kind) != tt.want {
				t.Fatalf("kind = %q, want %q", tt.kind, tt.want)
			}
		})
	}
	if spec := (LayerSpec{Kind: LayerUDP, Ignore: true}); !spec.Ignore {
		t.Fatal("UDP ignore bypass was not retained in the layer spec")
	}
}
