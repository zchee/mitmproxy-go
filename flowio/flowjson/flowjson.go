// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package flowjson builds the content-free, insertion-ordered flow objects
// exposed by mitmweb, as mitmproxy/tools/web/app.py flow_to_json does.
package flowjson

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/emoji"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/omap"
)

// Flow returns f's mitmweb representation without HTTP bodies, message payloads
// or certificate bytes. Object keys follow upstream's insertion order. Numbers
// that represent Python floats are jsontext.Values to preserve Python's repr.
// Callers must synchronise access to f with mutations, as for Flow.GetState.
// Nil flows, unsupported types, missing HTTP or DNS requests and invalid
// certificates return errors.
func Flow(f flow.Flow) (*omap.Map[any], error) {
	if f == nil {
		return nil, errors.New("flowjson: nil flow")
	}
	switch f.(type) {
	case *flow.DNSFlow, *flow.HTTPFlow, *flow.TCPFlow, *flow.UDPFlow:
	default:
		return nil, fmt.Errorf("flowjson: unsupported flow type %q", f.Type())
	}
	b := f.Common()
	if b == nil {
		return nil, errors.New("flowjson: nil flow")
	}
	m := omap.NewWithCapacity[any](14)
	m.Set("id", b.ID)
	m.Set("intercepted", b.Intercepted())
	m.Set("is_replay", b.IsReplay)
	m.Set("type", f.Type())
	m.Set("modified", f.Modified())
	marked := ""
	if b.Marked != "" {
		var ok bool
		marked, ok = emoji.Char(b.Marked)
		if !ok {
			marked = "🔴"
		}
	}
	m.Set("marked", marked)
	m.Set("comment", text(b.Comment))
	m.Set("timestamp_created", number(b.TimestampCreated))
	if b.ClientConn != nil {
		c, err := conn(&b.ClientConn.Connection, nil)
		if err != nil {
			return nil, err
		}
		m.Set("client_conn", c)
	}
	if b.ServerConn != nil {
		c, err := conn(&b.ServerConn.Connection, b.ServerConn)
		if err != nil {
			return nil, err
		}
		m.Set("server_conn", c)
	}
	if b.Error != nil {
		e := omap.NewWithCapacity[any](2)
		e.Set("msg", text(b.Error.Msg))
		e.Set("timestamp", number(b.Error.Timestamp))
		m.Set("error", e)
	}
	switch f := f.(type) {
	case *flow.DNSFlow:
		if f.Request == nil {
			return nil, errors.New("flowjson: DNS flow has no request")
		}
		request := f.Request.ToJSON()
		if f.Request.Timestamp != nil && *f.Request.Timestamp != 0 {
			request.Set("timestamp", number(*f.Request.Timestamp))
		}
		m.Set("request", request)
		if f.Response != nil {
			response := f.Response.ToJSON()
			if f.Response.Timestamp != nil && *f.Response.Timestamp != 0 {
				response.Set("timestamp", number(*f.Response.Timestamp))
			}
			m.Set("response", response)
		}
	case *flow.HTTPFlow:
		if f.Request == nil {
			return nil, errors.New("flowjson: HTTP flow has no request")
		}
		r := f.Request
		req := omap.NewWithCapacity[any](12)
		// Uppercase valid text without replacing surrogateescaped wire bytes.
		var method strings.Builder
		start := 0
		for i := 0; i < len(r.Method); {
			v, n := utf8.DecodeRuneInString(r.Method[i:])
			if v == utf8.RuneError && n == 1 {
				method.WriteString(strings.ToUpper(r.Method[start:i]))
				method.WriteByte(r.Method[i])
				start = i + 1
			}
			i += n
		}
		method.WriteString(strings.ToUpper(r.Method[start:]))
		req.Set("method", text(method.String()))
		req.Set("scheme", text(r.Scheme))
		req.Set("host", text(r.Host))
		req.Set("port", r.Port)
		req.Set("path", text(r.Path))
		req.Set("http_version", text(r.HTTPVersion))
		message(req, &r.Message)
		req.Set("pretty_host", text(r.PrettyHost()))
		m.Set("request", req)
		if r := f.Response; r != nil {
			resp := omap.NewWithCapacity[any](9)
			resp.Set("http_version", text(r.HTTPVersion))
			resp.Set("status_code", r.StatusCode)
			// Reason is stored as wire bytes, whereas Python exposes Latin-1 text.
			reason := make([]rune, len(r.Reason))
			for i := range len(r.Reason) {
				reason[i] = rune(r.Reason[i])
			}
			resp.Set("reason", string(reason))
			message(resp, &r.Message)
			if len(r.Trailers) != 0 {
				resp.Set("trailers", headers(r.Trailers))
			}
			m.Set("response", resp)
		}
		if w := f.WebSocket; w != nil {
			length := 0
			var last *float64
			for _, msg := range w.Messages {
				length += len(msg.Content)
				last = &msg.Timestamp
			}
			ws := omap.NewWithCapacity[any](5)
			ws.Set("messages_meta", messages(length, len(w.Messages), last))
			ws.Set("closed_by_client", w.ClosedByClient)
			ws.Set("close_code", w.CloseCode)
			ws.Set("close_reason", optionalText(w.CloseReason))
			ws.Set("timestamp_end", optionalNumber(w.TimestampEnd))
			m.Set("websocket", ws)
		}
	case *flow.TCPFlow:
		length := 0
		var last *float64
		for _, msg := range f.Messages {
			length += len(msg.Content)
			last = &msg.Timestamp
		}
		m.Set("messages_meta", messages(length, len(f.Messages), last))
	case *flow.UDPFlow:
		length := 0
		var last *float64
		for _, msg := range f.Messages {
			length += len(msg.Content)
			last = &msg.Timestamp
		}
		m.Set("messages_meta", messages(length, len(f.Messages), last))
	}
	return m, nil
}

func number(v float64) jsontext.Value { return jsontext.Value(pyrepr.Value(v)) }
func optionalNumber(v *float64) any {
	if v == nil {
		return nil
	}
	return number(*v)
}

func messages(length, count int, last *float64) *omap.Map[any] {
	m := omap.NewWithCapacity[any](3)
	m.Set("contentLength", length)
	m.Set("count", count)
	m.Set("timestamp_last", optionalNumber(last))
	return m
}

func message(m *omap.Map[any], msg *httpmsg.Message) {
	m.Set("headers", headers(msg.Headers))
	var length, hash any
	if msg.RawContent != nil {
		length = len(msg.RawContent)
		sum := sha256.Sum256(msg.RawContent)
		hash = hex.EncodeToString(sum[:])
	}
	m.Set("contentLength", length)
	m.Set("contentHash", hash)
	m.Set("timestamp_start", number(msg.TimestampStart))
	m.Set("timestamp_end", optionalNumber(msg.TimestampEnd))
}

func headers(h httpmsg.Headers) [][2]any {
	pairs := make([][2]any, len(h))
	for i, field := range h {
		pairs[i] = [2]any{text(string(field.Name)), text(string(field.Value))}
	}
	return pairs
}

func optionalText(s *string) any {
	if s == nil {
		return nil
	}
	return text(*s)
}

func text(s string) any {
	if utf8.ValidString(s) {
		return s
	}
	return surrogateText(s)
}

// surrogateText preserves the lone surrogate code points Python's
// surrogateescape assigns to undecodable wire bytes. Only this raw string
// enables invalid Unicode; ordinary map values keep JSON v2's validation.
type surrogateText string

// MarshalJSONTo encodes text with Python surrogate escapes for undecodable wire bytes.
func (s surrogateText) MarshalJSONTo(enc *jsontext.Encoder) error {
	raw := []byte{'"'}
	for len(s) != 0 {
		r, n := utf8.DecodeRuneInString(string(s))
		if r == utf8.RuneError && n == 1 {
			raw = fmt.Appendf(raw, "\\%sdc%02x", "u", s[0])
		} else {
			part, err := json.Marshal(string(s[:n]))
			if err != nil {
				return err
			}
			raw = append(raw, part[1:len(part)-1]...)
		}
		s = s[n:]
	}
	raw = append(raw, '"')
	return json.MarshalEncode(enc, jsontext.Value(raw), jsontext.AllowInvalidUTF8(true), jsontext.PreserveRawStrings(true))
}

func address(a *connection.Address) any {
	if a == nil {
		return nil
	}
	if a.Scope != nil {
		return []any{text(a.Host), a.Port, a.Scope.FlowInfo, a.Scope.ScopeID}
	}
	return []any{text(a.Host), a.Port}
}

func conn(c *connection.Connection, server *connection.Server) (*omap.Map[any], error) {
	cert, err := certificate(c.CertificateList)
	if err != nil {
		return nil, err
	}
	m := omap.NewWithCapacity[any](14)
	m.Set("id", c.ID)
	m.Set("peername", address(c.Peername))
	m.Set("sockname", address(c.Sockname))
	if server != nil {
		m.Set("address", address(server.Address))
	}
	m.Set("tls_established", c.TLSEstablished())
	m.Set("cert", cert)
	m.Set("sni", optionalText(c.SNI))
	m.Set("cipher", optionalText(c.Cipher))
	var alpn any
	if c.ALPN != nil {
		var text strings.Builder
		for _, b := range c.ALPN {
			if b < 128 {
				text.WriteByte(b)
			} else {
				fmt.Fprintf(&text, "\\x%02x", b)
			}
		}
		alpn = text.String()
	}
	m.Set("alpn", alpn)
	var version any
	if c.TLSVersion != "" {
		version = string(c.TLSVersion)
	}
	m.Set("tls_version", version)
	m.Set("timestamp_start", optionalNumber(c.TimestampStart))
	if server != nil {
		m.Set("timestamp_tcp_setup", optionalNumber(server.TimestampTCPSetup))
	}
	m.Set("timestamp_tls_setup", optionalNumber(c.TimestampTLSSetup))
	m.Set("timestamp_end", optionalNumber(c.TimestampEnd))
	return m, nil
}

func certificate(chain [][]byte) (*omap.Map[any], error) {
	if len(chain) == 0 {
		return nil, nil
	}
	c, err := certs.ParseCert(chain[0])
	if err != nil {
		return nil, fmt.Errorf("flowjson: certificate: %w", err)
	}
	m := omap.NewWithCapacity[any](8)
	kind, size := c.KeyInfo()
	m.Set("keyinfo", []any{kind, size})
	sum := c.Fingerprint()
	m.Set("sha256", hex.EncodeToString(sum[:]))
	m.Set("notbefore", c.NotBefore().Unix())
	m.Set("notafter", c.NotAfter().Unix())
	m.Set("serial", c.Serial().String())
	for _, field := range []struct {
		name   string
		values []certs.KeyVal
	}{{"subject", c.Subject()}, {"issuer", c.Issuer()}} {
		pairs := make([][2]string, len(field.values))
		for i, v := range field.values {
			pairs[i] = [2]string{v.Key, v.Value}
		}
		m.Set(field.name, pairs)
	}
	names := c.AltNames()
	alt := make([]string, len(names))
	for i, n := range names {
		alt[i] = n.String()
	}
	m.Set("altnames", alt)
	return m, nil
}
