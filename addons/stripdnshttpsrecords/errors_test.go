// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package stripdnshttpsrecords

import (
	"context"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

func TestMalformedRecord(t *testing.T) {
	tests := map[string]struct {
		stripECH bool
		http3    bool
		wantErr  bool
	}{
		"ECH enabled":    {stripECH: true, http3: true, wantErr: true},
		"HTTP3 disabled": {wantErr: true},
		"no stripping":   {http3: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opts := options.New()
			mgr := addon.NewManager(opts, command.NewManager(), addon.Config{})
			t.Cleanup(mgr.Close)
			a := New(opts)
			if err := mgr.Add(t.Context(), a); err != nil {
				t.Fatal(err)
			}
			f := flow.NewDNSFlow(nil, nil, true)
			f.Response = &dns.Message{Answers: []dns.ResourceRecord{{Type: dns.TypeHTTPS, Data: []byte{0}}}}
			before := f.Response.Clone()
			err := mgr.Do(t.Context(), func(ctx context.Context) error {
				if err := opts.Update(ctx, map[string]any{"strip_ech": tt.stripECH, "http3": tt.http3}); err != nil {
					return err
				}
				return a.DNSResponse(ctx, f)
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("DNSResponse error = %v; want error %v", err, tt.wantErr)
			}
			if diff := gocmp.Diff(before, f.Response); diff != "" {
				t.Fatalf("malformed record modified:\n%s", diff)
			}
		})
	}
}
