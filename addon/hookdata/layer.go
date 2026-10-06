// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package hookdata

// LayerKind names a protocol layer type. A next_layer handler describes the
// layers that should handle a connection by their kinds (see [LayerSpec] and
// [LayerStack]); the proxy builds the layers from the description.
//
// [LayerRegular], [LayerReverse] and [LayerUpstream] are the proxy modes'
// top layers: the connection handler builds one of them as the first layer
// of every connection, as mitmproxy's mode servers do with make_top_layer
// (py:mitmproxy/proxy/mode_servers.py). next_layer handlers never return
// them, as mitmproxy's never create a mode layer from next_layer.
type LayerKind string

// Layer kinds supported by the proxy.
const (
	// LayerRegular is the top layer of a regular (explicit HTTP) proxy
	// (py:mitmproxy/proxy/layers/modes.py HttpProxy).
	LayerRegular LayerKind = "regular"
	// LayerReverse is the top layer of a reverse proxy
	// (py:mitmproxy/proxy/layers/modes.py ReverseProxy).
	LayerReverse LayerKind = "reverse"
	// LayerUpstream is the top layer of an upstream (explicit proxy
	// chaining) proxy (py:mitmproxy/proxy/layers/modes.py
	// HttpUpstreamProxy).
	LayerUpstream LayerKind = "upstream"
	// LayerClientTLS terminates TLS with the client
	// (py:mitmproxy/proxy/layers/tls.py ClientTLSLayer).
	LayerClientTLS LayerKind = "clienttls"
	// LayerServerTLS establishes TLS with the server
	// (py:mitmproxy/proxy/layers/tls.py ServerTLSLayer).
	LayerServerTLS LayerKind = "servertls"
	// LayerHTTP handles HTTP requests and responses
	// (py:mitmproxy/proxy/layers/http HttpLayer). A spec with this kind
	// carries the [HTTPMode].
	LayerHTTP LayerKind = "http"
	// LayerTCP relays raw TCP with message capture
	// (py:mitmproxy/proxy/layers/tcp.py TCPLayer). A spec with this kind
	// may carry Ignore.
	LayerTCP LayerKind = "tcp"
	// LayerUDP relays raw datagrams with message capture or Ignore bypass.
	LayerUDP LayerKind = "udp"
	// LayerWebSocket relays messages after an HTTP upgrade.
	LayerWebSocket LayerKind = "websocket"
	// LayerClientDTLS terminates DTLS with the client over packet transport.
	LayerClientDTLS LayerKind = "clientdtls"
	// LayerServerDTLS establishes DTLS with the server over packet transport.
	LayerServerDTLS LayerKind = "serverdtls"
)

// HTTPMode says how an HTTP layer interprets request targets
// (py:mitmproxy/proxy/layers/http HTTPMode). It is set on a [LayerSpec]
// whose Kind is [LayerHTTP] and empty on every other spec.
type HTTPMode string

// The HTTP modes.
const (
	// HTTPModeRegular expects explicit-proxy requests: absolute-form
	// targets and CONNECT.
	HTTPModeRegular HTTPMode = "regular"
	// HTTPModeTransparent expects origin-form targets; the destination
	// comes from the connection. Reverse proxies use it too.
	HTTPModeTransparent HTTPMode = "transparent"
	// HTTPModeUpstream forwards explicit-proxy requests to another proxy.
	HTTPModeUpstream HTTPMode = "upstream"
)

// LayerSpec describes one layer of a [LayerStack].
type LayerSpec struct {
	// Kind is the layer type.
	Kind LayerKind
	// HTTPMode is the HTTP layer's mode. It is set only when Kind is
	// [LayerHTTP].
	HTTPMode HTTPMode
	// Ignore makes a [LayerTCP] or [LayerUDP] relay without creating a flow
	// or firing hooks, as mitmproxy's TCPLayer/UDPLayer(ignore=True).
	// It is set only for those two kinds.
	Ignore bool
}

// LayerStack is an ordered description of the layers that should handle a
// connection, outermost first. A next_layer handler sets a whole stack
// rather than one layer at a time, because mitmproxy's next_layer addon
// decides on pre-built stacks (server TLS over client TLS, client TLS over
// HTTP, the reverse-proxy stacks, py:mitmproxy/addons/next_layer.py), and
// re-asking after each single layer would decide differently: its
// stack_match compares the whole layer stack.
type LayerStack []LayerSpec
