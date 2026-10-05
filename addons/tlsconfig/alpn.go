// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"bytes"
	"slices"
)

// The application protocols the proxy treats as HTTP, in upstream's order
// (py:mitmproxy/proxy/layers/tls.py HTTP_ALPNS, HTTP1_ALPNS).
var (
	http1ALPNs = [][]byte{[]byte("http/1.1"), []byte("http/1.0"), []byte("http/0.9")}
	httpALPNs  = append([][]byte{[]byte("h3"), []byte("h2")}, http1ALPNs...)
)

// alpnSelect picks the application protocol the proxy offers the client, from
// the protocols the client offered in its ClientHello. It is the port of
// upstream's alpn_select_callback (py:mitmproxy/addons/tlsconfig.py:92-114),
// with the same nil conventions as the connection fields it reads:
//
//   - clientALPN is the preset protocol: the client connection's negotiated
//     protocol when an addon or an earlier handshake set one, or the forced
//     "http/1.1" of a secure web proxy. Nil means no preset. A non-nil preset
//     is returned when the client offers it; otherwise no protocol is chosen,
//     so an empty non-nil preset always selects nothing.
//   - serverALPN is the server connection's negotiated protocol. Nil means
//     there is no server handshake to mirror; empty but non-nil means the
//     server refused to negotiate a protocol, which is mirrored by selecting
//     nothing.
//   - Otherwise the client's first offer that is an HTTP protocol wins,
//     honouring the client's preference order. http2 reports whether "h2"
//     (and "h3") count as HTTP protocols.
//
// It returns nil when no protocol is selected.
func alpnSelect(clientALPN, serverALPN []byte, offers [][]byte, http2 bool) []byte {
	offered := func(proto []byte) bool {
		return slices.ContainsFunc(offers, func(o []byte) bool { return bytes.Equal(o, proto) })
	}
	if clientALPN != nil {
		if len(clientALPN) > 0 && offered(clientALPN) {
			return clientALPN
		}
		return nil
	}
	if len(serverALPN) > 0 && offered(serverALPN) {
		return serverALPN
	}
	if serverALPN != nil && len(serverALPN) == 0 {
		return nil
	}
	alpns := http1ALPNs
	if http2 {
		alpns = httpALPNs
	}
	for _, offer := range offers {
		if slices.ContainsFunc(alpns, func(p []byte) bool { return bytes.Equal(p, offer) }) {
			return offer
		}
	}
	return nil
}

// serverALPNOffers returns the protocols to offer the upstream server when no
// addon has set any: the client's offers, without "h2" when http2 is off, so
// that both sides stay on the same protocol version
// (py:mitmproxy/addons/tlsconfig.py:293-310). A client that offered nothing,
// or that did not use TLS, yields nil, so no ALPN extension is sent upstream.
func serverALPNOffers(clientOffers [][]byte, http2 bool) [][]byte {
	if len(clientOffers) == 0 {
		return nil
	}
	if http2 {
		return slices.Clone(clientOffers)
	}
	var offers [][]byte
	for _, offer := range clientOffers {
		if !bytes.Equal(offer, []byte("h2")) {
			offers = append(offers, offer)
		}
	}
	return offers
}
