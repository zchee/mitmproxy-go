// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package http1 reads and assembles bounded HTTP/1 messages without using net/http.
// Readers consume only their message; callers retain the buffered reader for the
// next body, pipelined request, or protocol handover.
package http1

import (
	"errors"
	"sync/atomic"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

const (
	// MaxHeadBytes bounds an entire head or trailer block, including delimiters.
	MaxHeadBytes = 1 << 20
	// MaxLineBytes bounds a physical head or trailer line, including its newline.
	MaxLineBytes = 64 << 10
	// MaxHeaderFields bounds logical fields in a head or trailer block.
	MaxHeaderFields = 10000
	// MaxChunkLineBytes bounds a chunk-size line, including extensions and CRLF.
	MaxChunkLineBytes = 4096
)

var (
	// ErrInvalidHead identifies malformed request lines, status lines or headers.
	ErrInvalidHead = errors.New("invalid HTTP head")
	// ErrHeadTooLarge identifies a head or trailer block exceeding MaxHeadBytes.
	ErrHeadTooLarge = errors.New("HTTP head exceeds byte limit")
	// ErrLineTooLong identifies a head or trailer line exceeding MaxLineBytes.
	ErrLineTooLong = errors.New("HTTP line exceeds byte limit")
	// ErrTooManyHeaders identifies more than MaxHeaderFields logical fields.
	ErrTooManyHeaders = errors.New("HTTP head exceeds field limit")
	// ErrChunkLineTooLong identifies a chunk-size line exceeding MaxChunkLineBytes.
	ErrChunkLineTooLong = errors.New("HTTP chunk line exceeds byte limit")
)

// RequestHead retains a parsed request and the exact bytes consumed to read it.
// Target is the unmodified request target. Raw and Target are owned by the head;
// callers may modify Request, but must not modify Raw or Target while assembling.
// Consumed includes skipped leading blank lines. Request.RawContent is nil.
// The private snapshot lets assembly distinguish proxy edits from wire spelling.
type RequestHead struct {
	Request  *httpmsg.Request
	Raw      []byte
	Consumed int
	Target   []byte
	wire     wireHead
}

// ResponseHead retains a parsed response and the exact bytes consumed to read it.
// Raw is owned by the head and must not be modified while assembling.
// Response.RawContent is nil; the body remains in the caller's buffered reader.
type ResponseHead struct {
	Response *httpmsg.Response
	Raw      []byte
	Consumed int
	wire     wireHead
}

// BodyMode specifies the delimiter used to read or write a message body.
type BodyMode uint8

const (
	// BodyNone means that no body bytes belong to the message.
	BodyNone BodyMode = iota
	// BodyLength means that exactly BodySize.Length bytes belong to the message.
	BodyLength
	// BodyChunked means HTTP/1 chunk framing with optional trailers.
	BodyChunked
	// BodyUntilClose means the body ends when the transport reaches EOF.
	BodyUntilClose
)

// BodySize describes body framing. Length is meaningful only for BodyLength and
// must be nonnegative. A zero BodySize denotes a message without a body.
type BodySize struct {
	Mode   BodyMode
	Length int64
}

// FidelityCounter counts proxy-originated wire normalizations at emission time.
// Its zero value is ready for use. It is safe for concurrent use, must not be
// copied after use, and belongs to one proxy instance, not the process.
// A nil counter disables accounting.
type FidelityCounter struct{ count atomic.Uint64 }

// Add records delta emitted normalization sites. A nil receiver is a no-op.
func (c *FidelityCounter) Add(delta uint64) {
	if c != nil {
		c.count.Add(delta)
	}
}

// Load returns the number of emitted normalization sites, or zero for nil.
func (c *FidelityCounter) Load() uint64 {
	if c == nil {
		return 0
	}
	return c.count.Load()
}

type wireField struct {
	field      httpmsg.Field
	raw        []byte
	normalized []byte
	folds      uint64
}

type wireHead struct {
	line          []byte
	canonicalLine []byte
	fields        []wireField
	end           []byte
}
