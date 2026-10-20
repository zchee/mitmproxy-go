// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowview

import (
	"cmp"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

// Detail returns styled metadata, connection, certificate and timing rows.
// f is a detached snapshot; the result never retains it.
func Detail(f flow.Flow, palette style.Palette) []string {
	if f == nil {
		return nil
	}
	base := f.Common()
	var lines []string
	heading := func(text string) { lines = append(lines, palette.Render("head", text)) }
	field := func(name, value string) {
		lines = append(lines, "    "+palette.Render("header", name+":")+" "+palette.Render("text", value))
	}
	if base.Comment != "" {
		heading("Comment: " + base.Comment)
	}
	if base.Metadata != nil && base.Metadata.Len() > 0 {
		heading("Metadata:")
		for key, value := range base.Metadata.All() {
			field(key, pyrepr.Value(value))
		}
	}
	var req *httpmsg.Request
	var resp *httpmsg.Response
	if h, ok := f.(*flow.HTTPFlow); ok {
		req, resp = h.Request, h.Response
	}
	sc, cc := base.ServerConn, base.ClientConn
	if sc != nil && sc.Peername != nil {
		heading("Server Connection:")
		if sc.Address != nil {
			field("Address", sc.Address.String())
		}
		field("Resolved Address", sc.Peername.String())
		if resp != nil {
			field("HTTP Version", resp.HTTPVersion)
		}
		if len(sc.ALPN) > 0 {
			field("ALPN", strutil.BytesToEscapedStr(sc.ALPN, false, false))
		}
		if len(sc.CertificateList) > 0 {
			raw := sc.CertificateList[0]
			if block, _ := pem.Decode(raw); block != nil {
				raw = block.Bytes
			}
			cert, err := x509.ParseCertificate(raw)
			heading("Server Certificate:")
			if err != nil {
				field("Error", err.Error())
			} else {
				field("Type", fmt.Sprintf("%s, %d bits", cert.PublicKeyAlgorithm, certificateBits(cert)))
				digest := sha256.Sum256(raw)
				field("SHA256 digest", fmt.Sprintf("% x", digest))
				field("Valid from", cert.NotBefore.String())
				field("Valid to", cert.NotAfter.String())
				field("Serial", cert.SerialNumber.String())
				field("Subject", cert.Subject.String())
				field("Issuer", cert.Issuer.String())
				names := slices.Clone(cert.DNSNames)
				for _, ip := range cert.IPAddresses {
					names = append(names, ip.String())
				}
				if len(names) > 0 {
					field("Alt names", strings.Join(names, ", "))
				}
			}
		}
	}
	if cc != nil {
		heading("Client Connection:")
		if cc.Peername != nil {
			field("Address", cc.Peername.String())
		} else {
			field("Address", "<no address>")
		}
		if req != nil {
			field("HTTP Version", req.HTTPVersion)
		}
		if cc.TLSVersion != "" {
			field("TLS Version", string(cc.TLSVersion))
		}
		if cc.SNI != nil {
			field("Server Name Indication", *cc.SNI)
		}
		if cc.Cipher != nil {
			field("Cipher Name", *cc.Cipher)
		}
		if len(cc.ALPN) > 0 {
			field("ALPN", strutil.BytesToEscapedStr(cc.ALPN, false, false))
		}
	}
	type timing struct{ name, value string }
	var timings []timing
	add := func(name string, ts *float64) {
		value := "–"
		if ts != nil && *ts != 0 {
			value = time.Unix(0, int64(*ts*1e9)).UTC().Format("2006-01-02 15:04:05.000")
		}
		timings = append(timings, timing{name, value})
	}
	conn := func(c *connection.Connection, prefix string) {
		if c.TimestampStart != nil && *c.TimestampStart != 0 {
			add(prefix+" established", c.TimestampStart)
			if c.TLSEstablished() {
				add(prefix+" TLS handshake", c.TimestampTLSSetup)
			}
			add(prefix+" closed", c.TimestampEnd)
		}
	}
	if cc != nil {
		conn(&cc.Connection, "Client conn.")
	}
	if sc != nil && sc.TimestampStart != nil && *sc.TimestampStart != 0 {
		add("Server conn. initiated", sc.TimestampStart)
		add("Server conn. TCP handshake", sc.TimestampTCPSetup)
		if sc.TLSEstablished() {
			add("Server conn. TLS handshake", sc.TimestampTLSSetup)
		}
		add("Server conn. closed", sc.TimestampEnd)
	}
	if req != nil && req.TimestampStart != 0 {
		add("First request byte", &req.TimestampStart)
		add("Request complete", req.TimestampEnd)
	}
	if resp != nil && resp.TimestampStart != 0 {
		add("First response byte", &resp.TimestampStart)
		add("Response complete", resp.TimestampEnd)
	}
	if len(timings) > 0 {
		slices.SortStableFunc(timings, func(a, b timing) int { return cmp.Compare(a.value, b.value) })
		heading("Timing:")
		for _, entry := range timings {
			field(entry.name, entry.value)
		}
	}
	return lines
}

func certificateBits(cert *x509.Certificate) int {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return len(key) * 8
	}
	return 0
}
