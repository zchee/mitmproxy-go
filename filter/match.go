// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package filter

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

// MatchAll matches every flow, like upstream's flowfilter.match_all.
var MatchAll Expr = &Unary{Token: TokenAll}

// Match reports whether f matches e. A nil e matches every flow, as
// upstream's flowfilter.match does for a filter of None.
func Match(e Expr, f flow.Flow) bool {
	if e == nil {
		return true
	}
	return e.Match(f)
}

// Match reports whether every operand matches f.
func (a *And) Match(f flow.Flow) bool {
	for _, e := range a.Exprs {
		if !e.Match(f) {
			return false
		}
	}
	return true
}

// Match reports whether any operand matches f.
func (o *Or) Match(f flow.Flow) bool {
	for _, e := range o.Exprs {
		if e.Match(f) {
			return true
		}
	}
	return false
}

// Match reports whether the operand does not match f.
func (n *Not) Match(f flow.Flow) bool { return !n.Expr.Match(f) }

// Match reports whether f has the property the operator names. Operators
// that only apply to some flow types, such as ~q for HTTP and DNS flows, do
// not match other flow types.
func (u *Unary) Match(f flow.Flow) bool {
	if f == nil {
		return false
	}
	b := f.Common()
	switch u.Token {
	case TokenAll:
		return true
	case TokenError:
		return b.Error != nil
	case TokenMarked:
		return b.Marked != ""
	case TokenReplay:
		return b.IsReplay != nil
	case TokenReplayRequest:
		return b.IsReplay != nil && *b.IsReplay == "request"
	case TokenReplayResponse:
		return b.IsReplay != nil && *b.IsReplay == "response"
	case TokenHTTP:
		_, ok := f.(*flow.HTTPFlow)
		return ok
	case TokenWebSocket:
		hf, ok := f.(*flow.HTTPFlow)
		return ok && hf.WebSocket != nil
	case TokenTCP:
		_, ok := f.(*flow.TCPFlow)
		return ok
	case TokenUDP:
		_, ok := f.(*flow.UDPFlow)
		return ok
	case TokenDNS:
		_, ok := f.(*flow.DNSFlow)
		return ok
	case TokenRequest, TokenResponse:
		has, ok := hasResponse(f)
		return ok && has == (u.Token == TokenResponse)
	case TokenAsset:
		hf, ok := f.(*flow.HTTPFlow)
		if !ok || hf.Response == nil {
			return false
		}
		for _, re := range assetTypes {
			if contentTypeMatches(re.Match, hf.Response.Headers) {
				return true
			}
		}
	}
	return false
}

// hasResponse reports whether an HTTP or DNS flow has a response; ok is
// false for other flow types.
func hasResponse(f flow.Flow) (has, ok bool) {
	switch f := f.(type) {
	case *flow.HTTPFlow:
		return f.Response != nil, true
	case *flow.DNSFlow:
		return f.Response != nil, true
	}
	return false, false
}

// assetTypes are upstream's FAsset.ASSET_TYPES. They are compiled without
// flags, so unlike filter patterns they are case-sensitive.
var assetTypes = []*regexp.Regexp{
	regexp.MustCompile(`text/javascript`),
	regexp.MustCompile(`application/x-javascript`),
	regexp.MustCompile(`application/javascript`),
	regexp.MustCompile(`text/css`),
	regexp.MustCompile(`image/.*`),
	regexp.MustCompile(`font/.*`),
	regexp.MustCompile(`application/font.*`),
}

// contentTypeMatches reports whether any Content-Type field of h, with the
// name compared case-insensitively over ASCII, has a value that match
// accepts.
func contentTypeMatches(match func([]byte) bool, h httpmsg.Headers) bool {
	for _, field := range h {
		if strings.EqualFold(string(field.Name), "content-type") && match(field.Value) {
			return true
		}
	}
	return false
}

// Match reports whether the operator's pattern occurs in the part of f the
// operator names. Operators that only apply to some flow types, such as ~h
// for HTTP flows, do not match other flow types.
func (r *Rex) Match(f flow.Flow) bool {
	if f == nil || r.re == nil {
		return false
	}
	re := r.re
	b := f.Common()
	switch r.Token {
	case TokenSrc:
		return addressMatches(re.MatchString, peername(b.ClientConn))
	case TokenDst:
		var addr *connection.Address
		if b.ServerConn != nil {
			addr = b.ServerConn.Address
		}
		return addressMatches(re.MatchString, addr)
	case TokenMeta:
		var lines []string
		if b.Metadata != nil {
			for k, v := range b.Metadata.All() {
				lines = append(lines, k+": "+pyStr(v))
			}
		}
		return re.MatchString(strings.Join(lines, "\n"))
	case TokenMarker:
		return re.MatchString(b.Marked)
	case TokenComment:
		return re.MatchString(b.Comment)
	case TokenBody, TokenBodyRequest, TokenBodyResponse:
		return r.matchBody(f)
	case TokenURL:
		switch f := f.(type) {
		case *flow.HTTPFlow:
			return f.Request != nil && re.MatchString(f.Request.PrettyURL())
		case *flow.DNSFlow:
			return f.Request != nil && len(f.Request.Questions) > 0 && re.MatchString(f.Request.Questions[0].Name)
		}
		return false
	}

	hf, ok := f.(*flow.HTTPFlow)
	if !ok || hf.Request == nil {
		return false
	}
	switch r.Token {
	case TokenContentType:
		return contentTypeMatches(re.Match, hf.Request.Headers) ||
			hf.Response != nil && contentTypeMatches(re.Match, hf.Response.Headers)
	case TokenContentTypeRequest:
		return contentTypeMatches(re.Match, hf.Request.Headers)
	case TokenContentTypeResponse:
		return hf.Response != nil && contentTypeMatches(re.Match, hf.Response.Headers)
	case TokenHeader:
		return re.Match(hf.Request.Headers.Bytes()) ||
			hf.Response != nil && re.Match(hf.Response.Headers.Bytes())
	case TokenHeaderRequest:
		return re.Match(hf.Request.Headers.Bytes())
	case TokenHeaderResponse:
		return hf.Response != nil && re.Match(hf.Response.Headers.Bytes())
	case TokenMethod:
		return re.MatchString(hf.Request.Method)
	case TokenDomain:
		return re.MatchString(hf.Request.Host) || re.MatchString(hf.Request.PrettyHost())
	}
	return false
}

// matchBody implements ~b, ~bq and ~bs: HTTP bodies after removing their
// Content-Encoding (the raw body when that fails, like upstream's
// get_content(strict=False)), WebSocket, TCP and UDP messages from the
// matching side, and the text form of DNS messages.
func (r *Rex) matchBody(f flow.Flow) bool {
	re := r.re
	request := r.Token != TokenBodyResponse
	response := r.Token != TokenBodyRequest
	fromSide := func(fromClient bool) bool {
		return fromClient && request || !fromClient && response
	}
	switch f := f.(type) {
	case *flow.HTTPFlow:
		// A missing body (nil RawContent) is skipped; a present one is
		// searched even when it decodes to nothing.
		if request && f.Request != nil && f.Request.RawContent != nil && re.Match(f.Request.ContentOrRaw()) {
			return true
		}
		if response && f.Response != nil && f.Response.RawContent != nil && re.Match(f.Response.ContentOrRaw()) {
			return true
		}
		if f.WebSocket != nil {
			for _, m := range f.WebSocket.Messages {
				if fromSide(m.FromClient) && re.Match(m.Content) {
					return true
				}
			}
		}
	case *flow.TCPFlow:
		for _, m := range f.Messages {
			if fromSide(m.FromClient) && re.Match(m.Content) {
				return true
			}
		}
	case *flow.UDPFlow:
		for _, m := range f.Messages {
			if fromSide(m.FromClient) && re.Match(m.Content) {
				return true
			}
		}
	case *flow.DNSFlow:
		if request && f.Request != nil && re.MatchString(f.Request.String()) {
			return true
		}
		if response && f.Response != nil && re.MatchString(f.Response.String()) {
			return true
		}
	}
	return false
}

func peername(c *connection.Client) *connection.Address {
	if c == nil {
		return nil
	}
	return c.Peername
}

// addressMatches matches "host:port" as upstream formats it for ~src and
// ~dst: the host as stored, without brackets even for IPv6.
func addressMatches(match func(string) bool, addr *connection.Address) bool {
	if addr == nil {
		return false
	}
	return match(addr.Host + ":" + strconv.Itoa(addr.Port))
}

// Match reports whether f is an HTTP flow whose response has the status code.
func (n *Int) Match(f flow.Flow) bool {
	hf, ok := f.(*flow.HTTPFlow)
	return ok && hf.Response != nil && strconv.Itoa(hf.Response.StatusCode) == n.Value
}
