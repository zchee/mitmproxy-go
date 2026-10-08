// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package quic

import (
	"crypto"
	"io"
	"sync/atomic"
	"testing"

	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/flow"
)

type opaqueSigner struct {
	crypto.Signer
	signatures atomic.Uint64
}

func (s *opaqueSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.signatures.Add(1)
	return s.Signer.Sign(random, digest, opts)
}

func TestQUICWireOpaqueSigner(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	tests := map[string]struct{}{"opaque signer handshake and relay": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			observer := &wireObserver{ended: make(chan *flow.TCPFlow, 1), preserveSettings: true}
			var signer *opaqueSigner
			observer.hello = func(*hookdata.ClientHello) {
				key, ok := observer.clientSettings.CertificatePrivateKey.(crypto.Signer)
				if !ok {
					t.Fatal("fixture private key is not a signer")
				}
				signer = &opaqueSigner{Signer: key}
				observer.clientSettings.CertificatePrivateKey = signer
			}
			session := newWireSession(t, nil, observer)
			if signer == nil || signer.signatures.Load() == 0 {
				t.Fatal("QUIC handshake did not use the installed opaque signer")
			}
			stream, err := session.client.OpenStreamSync(session.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Write([]byte("opaque signer")); err != nil {
				t.Fatal(err)
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			peer, err := session.origin.AcceptStream(session.ctx)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(peer)
			if err != nil || string(data) != "OPAQUE SIGNER" {
				t.Fatalf("opaque-signer relay payload=%q, error=%v", data, err)
			}
			if err := peer.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(stream); err != nil {
				t.Fatal(err)
			}
			if finished := wireAwait(t, observer.ended); finished.Error != nil {
				t.Fatalf("opaque-signer flow error=%v", finished.Error)
			}
		})
	}
}
