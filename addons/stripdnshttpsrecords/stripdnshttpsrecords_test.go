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

func TestStripRecords(t *testing.T) {
	// Ports test_strip_dns_https_records.py::test_strip_ech/test_strip_alpn.
	tests := map[string]struct {
		stripECH bool
		http3    bool
		alpn     [][]byte
		wantALPN [][]byte
	}{
		"HTTP3 untouched":     {stripECH: true, http3: true, alpn: [][]byte{[]byte("h2"), []byte("h3")}, wantALPN: [][]byte{[]byte("h2"), []byte("h3")}},
		"remove HTTP3 drafts": {stripECH: true, alpn: [][]byte{[]byte("h2"), []byte("h3"), []byte("h3-29"), []byte("h3foo")}, wantALPN: [][]byte{[]byte("h2"), []byte("h3foo")}},
		"remove empty ALPN":   {stripECH: true, alpn: [][]byte{[]byte("h3")}},
		"preserve ECH":        {http3: false, alpn: [][]byte{[]byte("h3")}},
		"absent ALPN":         {stripECH: true, http3: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opts := options.New()
			mgr := addon.NewManager(opts, command.NewManager(), addon.Config{})
			t.Cleanup(mgr.Close)
			if err := mgr.Add(t.Context(), New(opts)); err != nil {
				t.Fatal(err)
			}
			if err := mgr.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{"strip_ech": tt.stripECH, "http3": tt.http3})
			}); err != nil {
				t.Fatal(err)
			}
			data, err := dns.PackHTTPS(dns.HTTPSRecord{Priority: 1, TargetName: "example.com", Params: []dns.HTTPSParam{{Key: 3, Value: []byte{1, 187}}, {Key: 5, Value: []byte("testbytes")}, {Key: 111, Value: []byte{0, 255}}}})
			if err != nil {
				t.Fatal(err)
			}
			r := dns.ResourceRecord{Name: "dns.google", Type: dns.TypeHTTPS, Class: dns.ClassIN, TTL: 32, Data: data}
			if err := r.SetHTTPSALPN(tt.alpn); err != nil {
				t.Fatal(err)
			}
			noECH := r.Clone()
			if err := noECH.SetHTTPSECH(nil); err != nil {
				t.Fatal(err)
			}
			address := dns.ResourceRecord{Name: "dns.google", Type: dns.TypeA, Class: dns.ClassIN, TTL: 32, Data: []byte{8, 8, 8, 8}}
			svcb := r.Clone()
			svcb.Type = dns.TypeSVCB
			f := flow.NewDNSFlow(nil, nil, true)
			f.Response = &dns.Message{Answers: []dns.ResourceRecord{address, r, noECH, svcb}, Authorities: []dns.ResourceRecord{r.Clone()}, Additionals: []dns.ResourceRecord{r.Clone()}}
			before := f.Response.Clone()
			if err := mgr.Hook(t.Context(), addon.DNSResponseHook{Flow: f}); err != nil {
				t.Fatal(err)
			}
			if len(f.Response.Answers) != 4 {
				t.Fatalf("records removed: got %d answers", len(f.Response.Answers))
			}
			for _, index := range []int{1, 2} {
				got := &f.Response.Answers[index]
				alpn, err := got.HTTPSALPN()
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(tt.wantALPN, alpn); diff != "" {
					t.Fatalf("ALPN record %d (-want +got):\n%s", index, diff)
				}
				ech, err := got.HTTPSECH()
				if err != nil || tt.stripECH && ech != nil || !tt.stripECH && index == 1 && ech == nil {
					t.Fatalf("ECH record %d = %v, %v", index, ech, err)
				}
				view, err := dns.UnpackHTTPS(got.Data)
				if err != nil {
					t.Fatal(err)
				}
				if view.Priority != 1 || view.TargetName != "example.com" || got.TTL != 32 || got.Name != "dns.google" {
					t.Fatalf("record metadata modified: %+v / %+v", got, view)
				}
				var other []dns.HTTPSParam
				for _, param := range view.Params {
					if param.Key != 1 && param.Key != 5 {
						other = append(other, param)
					}
				}
				if diff := gocmp.Diff([]dns.HTTPSParam{{Key: 3, Value: []byte{1, 187}}, {Key: 111, Value: []byte{0, 255}}}, other); diff != "" {
					t.Fatalf("unrelated parameters changed:\n%s", diff)
				}
			}
			if diff := gocmp.Diff(before.Answers[0], f.Response.Answers[0]); diff != "" {
				t.Fatalf("A record modified:\n%s", diff)
			}
			if diff := gocmp.Diff(before.Answers[3], f.Response.Answers[3]); diff != "" {
				t.Fatalf("SVCB record modified:\n%s", diff)
			}
			if diff := gocmp.Diff(before.Authorities, f.Response.Authorities); diff != "" {
				t.Fatal(diff)
			}
			if diff := gocmp.Diff(before.Additionals, f.Response.Additionals); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestOptionsAndCommands(t *testing.T) {
	opts := options.New()
	cmds := command.NewManager()
	mgr := addon.NewManager(opts, cmds, addon.Config{})
	t.Cleanup(mgr.Close)
	a := New(opts)
	if err := mgr.Add(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		typ  options.Type
		def  any
		help string
	}{"strip_ech": {options.TypeBool, true, "Strip Encrypted ClientHello (ECH) data from DNS HTTPS records so that mitmproxy can generate matching certificates."}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			option, ok := opts.Lookup(name)
			if !ok {
				t.Fatal("missing option")
			}
			if diff := gocmp.Diff([]any{tt.typ, tt.def, tt.help}, []any{option.Type(), option.Default(), option.Help()}); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	for name := range cmds.Commands() {
		t.Errorf("unexpected command %s; upstream declares none", name)
	}
	if a.Name() != "stripdnshttpsrecords" {
		t.Fatal(a.Name())
	}
}
