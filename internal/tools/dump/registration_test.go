// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dump

import (
	"context"
	"net"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/packettransport"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestLayerRegistration(t *testing.T) {
	tests := map[string]struct {
		spec      hookdata.LayerSpec
		proxyMode string
	}{
		"regular":     {spec: hookdata.LayerSpec{Kind: hookdata.LayerRegular}, proxyMode: "regular"},
		"reverse":     {spec: hookdata.LayerSpec{Kind: hookdata.LayerReverse}, proxyMode: "reverse:http://example.test:80"},
		"upstream":    {spec: hookdata.LayerSpec{Kind: hookdata.LayerUpstream}, proxyMode: "upstream:http://example.test:80"},
		"client tls":  {spec: hookdata.LayerSpec{Kind: hookdata.LayerClientTLS}},
		"server tls":  {spec: hookdata.LayerSpec{Kind: hookdata.LayerServerTLS}},
		"http":        {spec: hookdata.LayerSpec{Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeRegular}},
		"tcp":         {spec: hookdata.LayerSpec{Kind: hookdata.LayerTCP}},
		"udp":         {spec: hookdata.LayerSpec{Kind: hookdata.LayerUDP}},
		"client dtls": {spec: hookdata.LayerSpec{Kind: hookdata.LayerClientDTLS}},
		"server dtls": {spec: hookdata.LayerSpec{Kind: hookdata.LayerServerDTLS}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			master := newMaster(t, Config{WithDumper: true})
			client := testflow.TClientConn()
			if tt.proxyMode != "" {
				client.ProxyMode = tt.proxyMode
			}
			c := &layer.Context{
				Data: &hookdata.Context{Client: client, Server: testflow.TServerConn(), Options: master.Options},
				Do:   master.Do,
			}
			if tt.spec.Kind == hookdata.LayerUDP {
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				for _, input := range []*layer.PacketRecorder{&c.ClientPackets, &c.ServerPackets} {
					socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					listener := packettransport.NewListener(ctx, socket)
					t.Cleanup(func() { _ = listener.Close() })
					peer, err := (&net.Dialer{}).DialContext(ctx, "udp4", socket.LocalAddr().String())
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = peer.Close() })
					if _, err := peer.Write([]byte("registration")); err != nil {
						t.Fatal(err)
					}
					tuple, err := listener.Accept(ctx)
					if err != nil {
						t.Fatalf("packet context setup: %v", err)
					}
					*input = proxy.RecordPackets(tuple)
				}
			}
			built, err := layer.Build(t.Context(), c, hookdata.LayerStack{tt.spec})
			if err != nil {
				t.Fatalf("dump assembly cannot build %q: %v", tt.spec.Kind, err)
			}
			if diff := gocmp.Diff(tt.spec.Kind, built.Kind()); diff != "" {
				t.Fatalf("constructed layer (-want +got):\n%s", diff)
			}
			if len(c.Data.Layers) != 1 || c.Data.Layers[0] != built {
				t.Fatalf("constructed %q layer was not published: %v", tt.spec.Kind, c.Data.Layers)
			}
		})
	}
}
