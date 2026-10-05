// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlslayer

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
)

func TestClientTLSNestedSessions(t *testing.T) {
	outerConfig, outerPeerConfig := tlsConfigs(t)
	innerConfig, innerPeerConfig := tlsConfigs(t)
	outerConfig.MinVersion, outerConfig.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	outerConfig.NextProtos, outerPeerConfig.NextProtos = []string{"outer"}, []string{"outer"}
	innerConfig.NextProtos, innerPeerConfig.NextProtos = []string{"inner"}, []string{"inner"}
	innerPeerConfig.ServerName = ""
	innerPeerConfig.InsecureSkipVerify = true // The no-SNI case verifies metadata reset, not certificate validation.
	var hellos int
	observer := &clientObserver{config: outerConfig}
	observer.hello = func(data *hookdata.ClientHello) {
		hellos++
		client := data.Context.Client
		if hellos == 2 {
			if client.ALPN != nil || client.Cipher != nil || client.SNI != nil || client.TLSEstablished() || client.TLSVersion != "" || len(client.CertificateList) != 0 || client.MitmCert != nil || len(client.CipherList) != 0 {
				t.Errorf("inner hello retained outer TLS metadata: %#v", client)
			}
			if diff := gocmp.Diff([][]byte{[]byte("inner")}, client.ALPNOffers); diff != "" {
				t.Error(diff)
			}
			observer.config = innerConfig
		}
	}
	s := newClientSession(t, observer)
	done := startClientLayer(t, s, &clientTLS{child: &clientTLS{child: lowerEcho()}})
	outer := &tlsConn{Conn: tls.Client(s.clientPeer, outerPeerConfig), raw: s.clientPeer}
	if err := outer.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	inner := tls.Client(outer, innerPeerConfig)
	if err := inner.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := inner.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(inner, reply[:]); err != nil || string(reply[:]) != "ping" {
		t.Fatalf("inner reply = %q, %v", reply, err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	client := s.c.Data.Client
	if hellos != 2 || client.TLSVersion != "TLSv1.3" || string(client.ALPN) != "inner" {
		t.Fatalf("inner result: hellos=%d, version=%s, ALPN=%q", hellos, client.TLSVersion, client.ALPN)
	}
	cert, _ := pem.Decode(client.MitmCert)
	if cert == nil || !bytes.Equal(cert.Bytes, innerConfig.Certificates[0].Certificate[0]) {
		t.Fatal("inner MitmCert still identifies the outer session")
	}
}

func TestClientTLSResumedCertificate(t *testing.T) {
	tests := map[string]struct{ addonCertificate bool }{
		"no addon certificate":       {},
		"addon supplies certificate": {addonCertificate: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			config, peerConfig := tlsConfigs(t)
			peerConfig.ClientSessionCache = tls.NewLRUClientSessionCache(1)
			for attempt := range 2 {
				observer := &clientObserver{config: config}
				provided := []byte("certificate selected by the config addon")
				observer.check = func(event string, data *hookdata.TLS) {
					if event == "tls_start_client" && tt.addonCertificate {
						data.Context.Client.MitmCert = bytes.Clone(provided)
					}
				}
				s := newClientSession(t, observer)
				done := startClientLayer(t, s, &clientTLS{child: lowerEcho()})
				peer := tls.Client(s.clientPeer, peerConfig)
				if err := peer.HandshakeContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				if peer.ConnectionState().DidResume != (attempt == 1) {
					t.Fatalf("attempt %d: resumed=%t", attempt, peer.ConnectionState().DidResume)
				}
				if _, err := peer.Write([]byte("PING")); err != nil {
					t.Fatal(err)
				}
				var reply [4]byte
				if _, err := io.ReadFull(peer, reply[:]); err != nil {
					t.Fatal(err)
				}
				if err := await(t, done); err != nil {
					t.Fatal(err)
				}
				got := s.c.Data.Client.MitmCert
				if attempt == 0 {
					block, _ := pem.Decode(got)
					if block == nil || !bytes.Equal(block.Bytes, config.Certificates[0].Certificate[0]) {
						t.Fatal("full handshake did not publish the presented leaf")
					}
				} else if tt.addonCertificate {
					if diff := gocmp.Diff(provided, got); diff != "" {
						t.Error(diff)
					}
				} else if got != nil {
					t.Fatalf("resumed handshake fabricated a certificate: %q", got)
				}
			}
		})
	}
}
