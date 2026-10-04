// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package filter

import (
	"slices"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/filter/regex"
)

// Token identifies one of the 32 filter operators, such as ~q or ~h.
type Token uint8

// The filter operators, in the order mitmproxy declares them: first the
// operators without an argument, then those that take a regex, then ~c.
const (
	TokenAsset               Token = iota + 1 // ~a
	TokenError                                // ~e
	TokenHTTP                                 // ~http
	TokenMarked                               // ~marked
	TokenReplay                               // ~replay
	TokenReplayRequest                        // ~replayq
	TokenReplayResponse                       // ~replays
	TokenRequest                              // ~q
	TokenResponse                             // ~s
	TokenTCP                                  // ~tcp
	TokenUDP                                  // ~udp
	TokenDNS                                  // ~dns
	TokenWebSocket                            // ~websocket
	TokenAll                                  // ~all
	TokenBody                                 // ~b
	TokenBodyRequest                          // ~bq
	TokenBodyResponse                         // ~bs
	TokenContentType                          // ~t
	TokenContentTypeRequest                   // ~tq
	TokenContentTypeResponse                  // ~ts
	TokenDomain                               // ~d
	TokenDst                                  // ~dst
	TokenHeader                               // ~h
	TokenHeaderRequest                        // ~hq
	TokenHeaderResponse                       // ~hs
	TokenMethod                               // ~m
	TokenSrc                                  // ~src
	TokenURL                                  // ~u
	TokenMeta                                 // ~meta
	TokenMarker                               // ~marker
	TokenComment                              // ~comment
	TokenCode                                 // ~c

	tokenEnd
)

// Arity says what argument an operator takes.
type Arity uint8

const (
	// ArityNone is an operator without an argument, such as ~q.
	ArityNone Arity = iota
	// ArityRegex is an operator followed by a regular expression, such as ~h.
	ArityRegex
	// ArityInt is an operator followed by a decimal integer, which is only ~c.
	ArityInt
)

type tokenInfo struct {
	code  string
	class string // upstream class name, printed by Dump
	help  string
	arity Arity
	flags regex.Flags // re flags besides the case-insensitivity default
	// describe is the upstream __str__ text; for operators with an
	// argument it is a format with one %s verb.
	describe string
}

var tokens = [tokenEnd]tokenInfo{
	TokenAsset:               {code: "a", class: "FAsset", help: "Match asset in response: CSS, JavaScript, images, fonts.", describe: "is asset"},
	TokenError:               {code: "e", class: "FErr", help: "Match error", describe: "has error"},
	TokenHTTP:                {code: "http", class: "FHTTP", help: "Match HTTP flows", describe: "is an HTTP Flow"},
	TokenMarked:              {code: "marked", class: "FMarked", help: "Match marked flows", describe: "is marked"},
	TokenReplay:              {code: "replay", class: "FReplay", help: "Match replayed flows", describe: "flow has been replayed"},
	TokenReplayRequest:       {code: "replayq", class: "FReplayClient", help: "Match replayed client request", describe: "request has been replayed"},
	TokenReplayResponse:      {code: "replays", class: "FReplayServer", help: "Match replayed server response", describe: "response has been replayed"},
	TokenRequest:             {code: "q", class: "FReq", help: "Match request with no response", describe: "has no response"},
	TokenResponse:            {code: "s", class: "FResp", help: "Match response", describe: "has response"},
	TokenTCP:                 {code: "tcp", class: "FTCP", help: "Match TCP flows", describe: "is a TCP Flow"},
	TokenUDP:                 {code: "udp", class: "FUDP", help: "Match UDP flows", describe: "is a UDP Flow"},
	TokenDNS:                 {code: "dns", class: "FDNS", help: "Match DNS flows", describe: "is a DNS Flow"},
	TokenWebSocket:           {code: "websocket", class: "FWebSocket", help: "Match WebSocket flows", describe: "is a Websocket Flow"},
	TokenAll:                 {code: "all", class: "FAll", help: "Match all flows", describe: "all flows"},
	TokenBody:                {code: "b", class: "FBod", help: "Body", arity: ArityRegex, flags: regex.DotAll, describe: "body matches %s"},
	TokenBodyRequest:         {code: "bq", class: "FBodRequest", help: "Request body", arity: ArityRegex, flags: regex.DotAll, describe: "body request matches %s"},
	TokenBodyResponse:        {code: "bs", class: "FBodResponse", help: "Response body", arity: ArityRegex, flags: regex.DotAll, describe: "body response matches %s"},
	TokenContentType:         {code: "t", class: "FContentType", help: "Content-type header", arity: ArityRegex, describe: "content type matches %s"},
	TokenContentTypeRequest:  {code: "tq", class: "FContentTypeRequest", help: "Request Content-Type header", arity: ArityRegex, describe: "req. content type matches %s"},
	TokenContentTypeResponse: {code: "ts", class: "FContentTypeResponse", help: "Response Content-Type header", arity: ArityRegex, describe: "resp. content type matches %s"},
	TokenDomain:              {code: "d", class: "FDomain", help: "Domain", arity: ArityRegex, describe: "domain matches %s"},
	TokenDst:                 {code: "dst", class: "FDst", help: "Match destination address", arity: ArityRegex, describe: "destination address matches %s"},
	TokenHeader:              {code: "h", class: "FHead", help: "Header", arity: ArityRegex, flags: regex.Multiline, describe: "header matches %s"},
	TokenHeaderRequest:       {code: "hq", class: "FHeadRequest", help: "Request header", arity: ArityRegex, flags: regex.Multiline, describe: "req. header matches %s"},
	TokenHeaderResponse:      {code: "hs", class: "FHeadResponse", help: "Response header", arity: ArityRegex, flags: regex.Multiline, describe: "resp. header matches %s"},
	TokenMethod:              {code: "m", class: "FMethod", help: "Method", arity: ArityRegex, describe: "method matches %s"},
	TokenSrc:                 {code: "src", class: "FSrc", help: "Match source address", arity: ArityRegex, describe: "source address matches %s"},
	TokenURL:                 {code: "u", class: "FUrl", help: "URL", arity: ArityRegex, describe: "url matches %s"},
	TokenMeta:                {code: "meta", class: "FMeta", help: "Flow metadata", arity: ArityRegex, flags: regex.Multiline, describe: "flow metadata matches %s"},
	TokenMarker:              {code: "marker", class: "FMarker", help: "Match marked flows with specified marker", arity: ArityRegex, describe: "marker matches %s"},
	TokenComment:             {code: "comment", class: "FComment", help: "Flow comment", arity: ArityRegex, flags: regex.Multiline, describe: "comment matches %s"},
	TokenCode:                {code: "c", class: "FCode", help: "HTTP response code", arity: ArityInt, describe: "response code is %s"},
}

// tokenByCode maps an operator's code, without the leading ~, to its Token.
var tokenByCode = func() map[string]Token {
	m := make(map[string]Token, len(tokens))
	for t := TokenAsset; t < tokenEnd; t++ {
		m[tokens[t].code] = t
	}
	return m
}()

// Tokens returns every filter operator in upstream declaration order.
func Tokens() []Token {
	ts := make([]Token, 0, tokenEnd-1)
	for t := TokenAsset; t < tokenEnd; t++ {
		ts = append(ts, t)
	}
	return ts
}

func (t Token) valid() bool { return t >= TokenAsset && t < tokenEnd }

// Code returns the operator's name without the leading ~, such as "hq".
func (t Token) Code() string {
	if !t.valid() {
		return ""
	}
	return tokens[t].code
}

// String returns the operator as it is written in a filter, such as "~hq".
func (t Token) String() string {
	if !t.valid() {
		return "Token(" + strconv.Itoa(int(t)) + ")"
	}
	return "~" + tokens[t].code
}

// Arity returns the kind of argument the operator takes.
func (t Token) Arity() Arity {
	if !t.valid() {
		return ArityNone
	}
	return tokens[t].arity
}

// Help returns the operator's one-line description from the upstream help table.
func (t Token) Help() string {
	if !t.valid() {
		return ""
	}
	return tokens[t].help
}

// RegexFlags returns the flags the operator compiles its pattern with,
// apart from the case-insensitivity that applies to every operator unless
// MITMPROXY_CASE_SENSITIVE_FILTERS=1: Multiline for ~h, ~hq, ~hs, ~meta and
// ~comment, DotAll for ~b, ~bq and ~bs.
func (t Token) RegexFlags() regex.Flags {
	if !t.valid() {
		return 0
	}
	return tokens[t].flags
}

// HelpEntry is one row of the filter help table.
type HelpEntry struct {
	// Expr is the syntax, such as "~h regex" or "!".
	Expr string
	// Help describes what the syntax matches.
	Help string
}

var helpTable = func() []HelpEntry {
	h := make([]HelpEntry, 0, tokenEnd+3)
	for t := TokenAsset; t < tokenEnd; t++ {
		expr := t.String()
		switch t.Arity() {
		case ArityRegex:
			expr += " regex"
		case ArityInt:
			expr += " int"
		}
		h = append(h, HelpEntry{Expr: expr, Help: t.Help()})
	}
	slices.SortFunc(h, func(a, b HelpEntry) int { return strings.Compare(a.Expr, b.Expr) })
	return append(h,
		HelpEntry{Expr: "!", Help: "unary not"},
		HelpEntry{Expr: "&", Help: "and"},
		HelpEntry{Expr: "|", Help: "or"},
		HelpEntry{Expr: "(...)", Help: "grouping"},
	)
}()

// Help returns the filter help table in the order mitmproxy shows it: the
// operators sorted by their syntax, then !, &, | and grouping.
func Help() []HelpEntry {
	return slices.Clone(helpTable)
}
