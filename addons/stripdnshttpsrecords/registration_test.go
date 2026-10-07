// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package stripdnshttpsrecords_test

import (
	"io"
	"testing"

	"github.com/zchee/mitmproxy-go/addons/stripdnshttpsrecords"
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
	if m.Addons.Get("stripdnshttpsrecords") == nil {
		if err := m.Addons.Add(t.Context(), stripdnshttpsrecords.New(opts)); err != nil {
			t.Fatalf("load alongside default addon set: %v", err)
		}
	}
	if _, ok := m.Addons.Get("stripdnshttpsrecords").(*stripdnshttpsrecords.StripDNSHTTPSRecords); !ok {
		t.Fatal("upstream addon name did not resolve to stripping addon")
	}
}
