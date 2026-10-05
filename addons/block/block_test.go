// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package block

import (
	"context"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/options"
)

// TestBlockGlobal ports every address and policy in upstream test_block_global.
func TestBlockGlobal(t *testing.T) {
	tests := map[string]struct{ private, global bool }{
		"127.0.0.1": {}, "::1": {},
		"10.0.0.1": {private: true}, "172.20.0.1": {private: true}, "192.168.1.1": {private: true},
		"::ffff:10.0.0.1": {private: true}, "::ffff:172.20.0.1": {private: true}, "::ffff:192.168.1.1": {private: true},
		"::ffff:192.168.1.1%scope": {private: true}, "fe80::": {private: true},
		"1.1.1.1": {global: true}, "8.8.8.8": {global: true}, "216.58.207.174": {global: true},
		"::ffff:1.1.1.1": {global: true}, "::ffff:8.8.8.8": {global: true}, "::ffff:216.58.207.174": {global: true},
		"::ffff:216.58.207.174%scope": {global: true}, "2001:4860:4860::8888": {global: true}, "2001:4860:4860::8888%scope": {global: true},
		"0.0.0.0": {private: true}, "192.0.0.8": {private: true}, "192.0.0.9": {global: true}, "192.0.0.10": {global: true},
		"192.0.2.1": {private: true}, "198.51.100.1": {private: true}, "203.0.113.1": {private: true},
		"240.0.0.1": {private: true}, "255.255.255.255": {private: true}, "224.0.0.1": {global: true},
		"100.64.0.1": {}, "100.127.255.255": {}, "::": {private: true}, "64:ff9b:1::1": {private: true},
		"2001:db8::1": {private: true}, "2001:1::1": {global: true}, "2001:3::1": {global: true}, "3fff::1": {private: true},
		"2002::1": {private: true}, "ff02::1": {global: true},
	}
	for address, tt := range tests {
		t.Run(address, func(t *testing.T) {
			for _, private := range []bool{false, true} {
				opts := options.New()
				b := New(opts)
				m := addon.NewManager(opts, command.NewManager(), addon.Config{})
				t.Cleanup(m.Close)
				if err := m.Add(t.Context(), b); err != nil {
					t.Fatal(err)
				}
				if err := m.Do(t.Context(), func(ctx context.Context) error {
					return opts.Update(ctx, map[string]any{"block_global": !private, "block_private": private})
				}); err != nil {
					t.Fatal(err)
				}
				c := connection.NewClient(connection.Address{Host: address}, connection.Address{}, 0)
				if err := m.Hook(t.Context(), addon.ClientConnectedHook{Client: c}); err != nil {
					t.Fatal(err)
				}
				want := tt.global
				if private {
					want = tt.private
				}
				if diff := gocmp.Diff(want, c.Error != nil); diff != "" {
					t.Errorf("private=%v: %s", private, diff)
				}
			}
		})
	}
}

func TestIgnoreLocalMode(t *testing.T) {
	opts := options.New()
	b := New(opts)
	m := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(m.Close)
	if err := m.Add(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if err := opts.Update(t.Context(), map[string]any{"block_private": true}); err != nil {
		t.Fatal(err)
	}
	c := connection.NewClient(connection.Address{Host: "192.168.1.1"}, connection.Address{}, 0)
	c.ProxyMode = "local"
	if err := m.Hook(t.Context(), addon.ClientConnectedHook{Client: c}); err != nil {
		t.Fatal(err)
	}
	if c.Error != nil {
		t.Fatal(*c.Error)
	}
}

func TestOptions(t *testing.T) {
	opts := options.New()
	m := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(m.Close)
	if err := m.Add(t.Context(), New(opts)); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		value bool
		help  string
	}{
		"block_global":  {true, "Block connections from public IP addresses."},
		"block_private": {false, "Block connections from local (private) IP addresses. This option does not affect loopback addresses (connections from the local machine), which are always permitted."},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opt, ok := opts.Lookup(name)
			if !ok {
				t.Fatal("missing option")
			}
			if opt.Type() != options.TypeBool || opt.Default() != tt.value || opt.Help() != tt.help {
				t.Fatalf("option mismatch: %v, %v, %q", opt.Type(), opt.Default(), opt.Help())
			}
		})
	}
}
