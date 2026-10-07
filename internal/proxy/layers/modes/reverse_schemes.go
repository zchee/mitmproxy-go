// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modes

import (
	"fmt"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

// reverseScheme describes destination metadata without importing protocol
// implementations. Both selects the accepted client's transport. Secure schemes
// set destination SNI unless keep_host_header is enabled. Eager connection applies
// only to TCP destinations; datagram protocols establish their own transports.
// Protocol extension files in this package replace their entry during init only.
// application is the innermost kind selected by the scheme's next-layer branch.
type reverseScheme struct {
	transport   modespec.TransportProtocol
	setSNI      bool
	eager       bool
	application hookdata.LayerKind
}

var reverseSchemes = map[string]reverseScheme{
	"http":  {transport: modespec.TCP, eager: true, application: hookdata.LayerHTTP},
	"https": {transport: modespec.Both, setSNI: true, eager: true, application: hookdata.LayerHTTP},
	"tcp":   {transport: modespec.TCP, eager: true, application: hookdata.LayerTCP},
	"tls":   {transport: modespec.TCP, setSNI: true, eager: true, application: hookdata.LayerTCP},
	"udp":   {transport: modespec.UDP, application: hookdata.LayerUDP},
	"dtls":  {transport: modespec.UDP, setSNI: true, application: hookdata.LayerUDP},
	"dns":   {transport: modespec.Both, eager: true, application: "dns"},
	"quic":  {transport: modespec.UDP, setSNI: true, application: "quic"},
	"http3": {transport: modespec.UDP, setSNI: true, application: hookdata.LayerHTTP},
}

func configureReverse(c *layer.Context) (reverseScheme, error) {
	parsed, err := modespec.Parse(c.Data.Client.ProxyMode)
	if err != nil {
		return reverseScheme{}, err
	}
	reverse, ok := parsed.(modespec.ReverseMode)
	if !ok {
		return reverseScheme{}, fmt.Errorf("modes: reverse layer requires a reverse proxy mode")
	}
	entry, ok := reverseSchemes[reverse.Scheme]
	if !ok {
		return reverseScheme{}, fmt.Errorf("modes: unsupported reverse scheme %q", reverse.Scheme)
	}
	switch entry.transport {
	case modespec.Both:
		c.Data.Server.TransportProtocol = c.Data.Client.TransportProtocol
	case modespec.UDP:
		c.Data.Server.TransportProtocol = connection.UDP
	case modespec.TCP:
		c.Data.Server.TransportProtocol = connection.TCP
	}
	c.Data.Server.Address = &connection.Address{Host: reverse.Address.Host, Port: reverse.Address.Port}
	if entry.setSNI && !c.Data.Options.Bool("keep_host_header") {
		c.Data.Server.SNI = new(reverse.Address.Host)
	}
	return entry, nil
}

func (s reverseScheme) connectEagerly(c *layer.Context) bool {
	return s.eager && c.Data.Options.Str("connection_strategy") == "eager" && c.Data.Server.Address != nil && c.Data.Server.TransportProtocol == connection.TCP
}
