// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dump

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
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
