// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"errors"
	"io"
	"log/slog"
	"strconv"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// Config is copied by New; Client selects the upstream-facing endpoint role.
type Config struct {
	// Descriptor is immutable endpoint and connection metadata.
	Descriptor layer.EndpointDescriptor
	// Client opens request streams instead of accepting them.
	Client bool
	// ValidateInboundHeaders enables HTTP field-name and pseudo-header validation.
	ValidateInboundHeaders bool
	// Logger receives local diagnostics, never peer-visible close reasons.
	Logger *slog.Logger
}

// EventKind identifies an ordered HTTP/3 stream or connection event.
type EventKind uint8

const (
	// Headers carries the initial request or final response field section.
	Headers EventKind = iota
	// Informational carries an interim response field section.
	Informational
	// Data carries bytes borrowed until Receipt settles.
	Data
	// Trailers carries the terminal field section.
	Trailers
	// Reset reports unsuccessful stream termination.
	Reset
	// GoAway carries the first rejected request or push identifier.
	GoAway
)

// Event transfers received fields and borrows DATA until its receipt settles.
// Send borrows outgoing slices only until it returns.
type Event struct {
	// Kind identifies the event.
	Kind EventKind
	// Identity scopes the wire stream to its receiving endpoint.
	Identity layer.StreamIdentity
	// Headers preserves field order, duplicates and original name/value bytes.
	Headers []HeaderField
	// Data holds the original received bytes.
	Data []byte
	// Receipt accounts for original bytes independently of transformed output.
	Receipt layer.ConsumptionReceipt
	// EndStream identifies the end of this direction's message.
	EndStream bool
	// Code preserves the HTTP/3 application error code.
	Code ErrorCode
	// LastStreamID is the first rejected identifier, unlike HTTP/2's inclusive ID.
	LastStreamID uint64
	// Err retains the typed diagnostic for a failure.
	Err error
}

// ErrorCode is an HTTP/3 or QPACK application error code.
type ErrorCode uint64

const (
	// ErrCodeNoError indicates graceful shutdown.
	ErrCodeNoError ErrorCode = 0x100
	// ErrCodeGeneralProtocol indicates an otherwise unspecified protocol violation.
	ErrCodeGeneralProtocol ErrorCode = 0x101
	// ErrCodeInternal indicates an endpoint implementation failure.
	ErrCodeInternal ErrorCode = 0x102
	// ErrCodeStreamCreation indicates a prohibited or duplicate stream.
	ErrCodeStreamCreation ErrorCode = 0x103
	// ErrCodeClosedCriticalStream indicates termination of a critical stream.
	ErrCodeClosedCriticalStream ErrorCode = 0x104
	// ErrCodeFrameUnexpected indicates a frame in an invalid context.
	ErrCodeFrameUnexpected ErrorCode = 0x105
	// ErrCodeFrameError indicates a malformed frame payload.
	ErrCodeFrameError ErrorCode = 0x106
	// ErrCodeExcessiveLoad indicates a local resource limit violation.
	ErrCodeExcessiveLoad ErrorCode = 0x107
	// ErrCodeIDError indicates an invalid stream or push identifier.
	ErrCodeIDError ErrorCode = 0x108
	// ErrCodeSettingsError indicates invalid SETTINGS values.
	ErrCodeSettingsError ErrorCode = 0x109
	// ErrCodeMissingSettings indicates a control stream without initial SETTINGS.
	ErrCodeMissingSettings ErrorCode = 0x10a
	// ErrCodeRequestRejected indicates an unprocessed request.
	ErrCodeRequestRejected ErrorCode = 0x10b
	// ErrCodeRequestCancelled indicates cancellation of a request.
	ErrCodeRequestCancelled ErrorCode = 0x10c
	// ErrCodeRequestIncomplete indicates premature termination of a request.
	ErrCodeRequestIncomplete ErrorCode = 0x10d
	// ErrCodeMessageError indicates an invalid HTTP message.
	ErrCodeMessageError ErrorCode = 0x10e
	// ErrCodeConnectError indicates failure of a CONNECT tunnel.
	ErrCodeConnectError ErrorCode = 0x10f
	// ErrCodeVersionFallback indicates that another HTTP version is required.
	ErrCodeVersionFallback ErrorCode = 0x110
	// ErrCodeQPACKDecompressionFailed indicates an invalid field section.
	ErrCodeQPACKDecompressionFailed ErrorCode = 0x200
	// ErrCodeQPACKEncoderStreamError indicates an invalid encoder instruction.
	ErrCodeQPACKEncoderStreamError ErrorCode = 0x201
	// ErrCodeQPACKDecoderStreamError indicates an invalid decoder instruction.
	ErrCodeQPACKDecoderStreamError ErrorCode = 0x202
)

// String returns the RFC error name, or a decimal value for an unknown code.
func (code ErrorCode) String() string {
	names := [...]string{"H3_NO_ERROR", "H3_GENERAL_PROTOCOL_ERROR", "H3_INTERNAL_ERROR", "H3_STREAM_CREATION_ERROR", "H3_CLOSED_CRITICAL_STREAM", "H3_FRAME_UNEXPECTED", "H3_FRAME_ERROR", "H3_EXCESSIVE_LOAD", "H3_ID_ERROR", "H3_SETTINGS_ERROR", "H3_MISSING_SETTINGS", "H3_REQUEST_REJECTED", "H3_REQUEST_CANCELLED", "H3_REQUEST_INCOMPLETE", "H3_MESSAGE_ERROR", "H3_CONNECT_ERROR", "H3_VERSION_FALLBACK"}
	if code >= ErrCodeNoError && code <= ErrCodeVersionFallback {
		return names[code-ErrCodeNoError]
	}
	switch code {
	case ErrCodeQPACKDecompressionFailed:
		return "QPACK_DECOMPRESSION_FAILED"
	case ErrCodeQPACKEncoderStreamError:
		return "QPACK_ENCODER_STREAM_ERROR"
	case ErrCodeQPACKDecoderStreamError:
		return "QPACK_DECODER_STREAM_ERROR"
	default:
		return strconv.FormatUint(uint64(code), 10)
	}
}

// StreamError reports a reset or rejection scoped to its receiving endpoint.
type StreamError struct {
	// Identity identifies the failed wire stream.
	Identity layer.StreamIdentity
	// Code preserves the application's error code.
	Code ErrorCode
	// Message is the local diagnostic.
	Message string
}

// Error returns the stream diagnostic.
func (err *StreamError) Error() string { return "h3: " + err.Code.String() + ": " + err.Message }

// Unwrap identifies a closed stream independently of its application error code.
func (err *StreamError) Unwrap() error { return io.ErrClosedPipe }

// ConnectionError reports an HTTP/3 connection failure with its wire code.
type ConnectionError struct {
	// Code is the application error code.
	Code ErrorCode
	// Message is the local diagnostic.
	Message string
}

// Error returns the connection diagnostic.
func (err *ConnectionError) Error() string { return "h3: " + err.Code.String() + ": " + err.Message }

// ErrDraining indicates that GOAWAY prevents admitting another request.
var ErrDraining = errors.New("h3: endpoint draining")

const (
	// ChunkSize is the maximum capacity of an engine-owned DATA chunk.
	ChunkSize = 64 << 10
	// ReceiveQueueBytes includes queued DATA and the borrowed outstanding chunk.
	ReceiveQueueBytes = 4 * ChunkSize
	// MaxHeaderBytes bounds encoded and RFC-accounted decoded field sections.
	MaxHeaderBytes = 128 << 10
	// MaxConcurrentStreams bounds active request state per endpoint.
	MaxConcurrentStreams = 100
	// MaxQueuedEvents bounds pending events on one request stream.
	MaxQueuedEvents = 8
)
