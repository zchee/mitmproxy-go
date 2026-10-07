// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsconfig

import (
	"context"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/options"
)

type quicSettingsOverride struct {
	settings *hookdata.QUICTLSSettings
}

// Name supplies a distinct name for the test addon.
func (*quicSettingsOverride) Name() string { return "quicsettingsoverride" }

// QUICStartClient simulates an addon that provides client-facing settings first.
func (a *quicSettingsOverride) QUICStartClient(_ context.Context, d *hookdata.QUICTLS) error {
	d.Settings = a.settings
	return nil
}

// QUICStartServer simulates an addon that provides origin-facing settings first.
func (a *quicSettingsOverride) QUICStartServer(_ context.Context, d *hookdata.QUICTLS) error {
	d.Settings = a.settings
	return nil
}

func TestQUICSettingsOverride(t *testing.T) {
	// py:test/mitmproxy/addons/test_tlsconfig.py:test_quic_start_client and
	// test_quic_start_server_verify_ok assert preservation of supplied settings.
	// The override runs before the real addon in the dispatch chain.
	tests := map[string]struct {
		client bool
	}{
		"success: earlier client addon preserved": {client: true},
		"success: earlier server addon preserved": {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opts := options.New()
			manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
			t.Cleanup(func() {
				if err := manager.Clear(t.Context()); err != nil {
					t.Error(err)
				}
				manager.Close()
			})
			settings := &hookdata.QUICTLSSettings{ALPNProtocols: []string{"custom"}, CAFile: new("provided.pem")}
			if err := manager.Add(t.Context(), &quicSettingsOverride{settings: settings}, New(opts)); err != nil {
				t.Fatal(err)
			}
			c := testContext(opts)
			d := &hookdata.QUICTLS{Context: c, Conn: &c.Server.Connection}
			var hook addon.Hook = addon.QUICStartServerHook{Data: d}
			if tt.client {
				d.Conn = &c.Client.Connection
				hook = addon.QUICStartClientHook{Data: d}
			}
			// No store is initialized and no server address exists: preservation
			// must return before the default certificate or SNI paths are touched.
			if err := manager.Hook(t.Context(), hook); err != nil {
				t.Fatal(err)
			}
			if err := manager.Do(t.Context(), func(context.Context) error {
				if d.Settings != settings || len(d.Settings.ALPNProtocols) != 1 || d.Settings.ALPNProtocols[0] != "custom" || d.Settings.CAFile == nil || *d.Settings.CAFile != "provided.pem" {
					t.Fatal("supplied settings were replaced or mutated")
				}
				if c.Server.SNI != nil || len(c.Server.ALPNOffers) != 0 || len(c.Client.CipherList) != 0 {
					t.Error("default hook mutated connection fields despite existing settings")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
