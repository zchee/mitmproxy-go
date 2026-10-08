// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"errors"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	quiclayer "github.com/zchee/mitmproxy-go/internal/proxy/layers/quic"
)

func init() {
	layer.Register(hookdata.LayerHTTP3, func(_ *layer.Context, _ hookdata.LayerSpec, child layer.Layer) (layer.Layer, error) {
		if child != nil {
			return nil, errors.New("httplayer: HTTP/3 does not accept a byte-stream child")
		}
		consumer := &httpLayer{route: routeConfig{mode: modeTransparent, validateInboundHeaders: true}}
		return &http3Layer{RawQuicLayer: quiclayer.NewRawQuicLayer(consumer)}, nil
	})
}

type http3Layer struct {
	*quiclayer.RawQuicLayer
}

func (*http3Layer) Kind() hookdata.LayerKind { return hookdata.LayerHTTP3 }

var _ quiclayer.ConnectionConsumer = (*httpLayer)(nil)
