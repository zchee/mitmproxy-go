// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver_test

import (
	"io"
	"testing"

	"github.com/zchee/mitmproxy-go/addons/dnsresolver"
	"github.com/zchee/mitmproxy-go/internal/tools/dump"
	"github.com/zchee/mitmproxy-go/options"
)

func TestDefaultSetRegistration(t *testing.T) {
	opts := options.New()
	if err := opts.Update(t.Context(), map[string]any{"confdir": t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	m, err := dump.New(t.Context(), dump.Config{Options: opts, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := m.Close(t.Context()); err != nil {
			t.Error(err)
		}
	}()
	if m.Addons.Get("dnsresolver") == nil {
		if err := m.Addons.Add(t.Context(), dnsresolver.New(opts, nil)); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := m.Addons.Get("dnsresolver").(*dnsresolver.DnsResolver); !ok {
		t.Fatal("upstream addon name did not resolve to DNS resolver")
	}
}
