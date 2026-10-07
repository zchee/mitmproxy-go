// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package stripdnshttpsrecords removes ECH and disabled HTTP/3 advertisements
// from HTTPS answers while retaining records and unrelated service parameters.
package stripdnshttpsrecords

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/options"
)

// StripDNSHTTPSRecords edits HTTPS answers according to strip_ech and http3.
// Options and flow state are accessed only under addon dispatch.
type StripDNSHTTPSRecords struct{ options *options.Manager }

// New returns an HTTPS record stripping addon using opts.
func New(opts *options.Manager) *StripDNSHTTPSRecords { return &StripDNSHTTPSRecords{options: opts} }

// Name returns the upstream addon name.
func (*StripDNSHTTPSRecords) Name() string { return "stripdnshttpsrecords" }

// Load registers the upstream strip_ech option.
func (*StripDNSHTTPSRecords) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "strip_ech", options.TypeBool, true, "Strip Encrypted ClientHello (ECH) data from DNS HTTPS records so that mitmproxy can generate matching certificates.")
}

// DNSResponse strips ECH when enabled and HTTP/3 ALPNs when HTTP/3 is disabled.
// Malformed HTTPS RDATA returns an error; changes made before the error remain,
// as in the upstream hook. No records, other sections or SVCB answers are removed.
func (a *StripDNSHTTPSRecords) DNSResponse(_ context.Context, f *flow.DNSFlow) error {
	if f == nil || f.Response == nil {
		return errors.New("DNS flow has no response")
	}
	if a.options.Bool("strip_ech") {
		for i := range f.Response.Answers {
			answer := &f.Response.Answers[i]
			if answer.Type == dns.TypeHTTPS {
				if err := answer.SetHTTPSECH(nil); err != nil {
					return fmt.Errorf("strip ECH from answer %d: %w", i, err)
				}
			}
		}
	}
	if a.options.Bool("http3") {
		return nil
	}
	for i := range f.Response.Answers {
		answer := &f.Response.Answers[i]
		if answer.Type != dns.TypeHTTPS {
			continue
		}
		protocols, err := answer.HTTPSALPN()
		if err != nil {
			return fmt.Errorf("read ALPN from answer %d: %w", i, err)
		}
		kept := protocols[:0]
		for _, protocol := range protocols {
			if !bytes.Equal(protocol, []byte("h3")) && !bytes.HasPrefix(protocol, []byte("h3-")) {
				kept = append(kept, protocol)
			}
		}
		if len(kept) == len(protocols) {
			continue
		}
		if len(kept) == 0 {
			kept = nil
		}
		if err := answer.SetHTTPSALPN(kept); err != nil {
			return fmt.Errorf("strip HTTP/3 ALPN from answer %d: %w", i, err)
		}
	}
	return nil
}

var (
	_ addon.LoadHandler        = (*StripDNSHTTPSRecords)(nil)
	_ addon.DNSResponseHandler = (*StripDNSHTTPSRecords)(nil)
)
