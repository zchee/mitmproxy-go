// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layer

import "net"

// InjectionDirection is the peer direction specified independently of a message.
type InjectionDirection uint8

const (
	// DirectionUnspecified derives the direction from Message.FromClient.
	DirectionUnspecified InjectionDirection = iota
	// DirectionFromClient sends toward the server and requires FromClient true.
	DirectionFromClient
	// DirectionFromServer sends toward the client and requires FromClient false.
	DirectionFromServer
)

const (
	// InjectionCapacity bounds queued messages per handled connection.
	InjectionCapacity = 64
	// MaxInjectionBytes bounds one cloned injection payload.
	MaxInjectionBytes = 128 << 10
)

// InjectionReason classifies a rejected injection without parsing its text.
type InjectionReason uint8

const (
	// InjectionFull means the owner has not drained its bounded queue.
	InjectionFull InjectionReason = iota + 1
	// InjectionSize means the payload exceeds its protocol's bound.
	InjectionSize
	// InjectionType means the message and flow types are not compatible.
	InjectionType
	// InjectionIdentity means the explicit flow identity does not match.
	InjectionIdentity
	// InjectionDirectionMismatch means the explicit direction is invalid or differs from the message.
	InjectionDirectionMismatch
	// InjectionClosed means the flow or its connection is no longer live.
	InjectionClosed
)

// InjectionError is a typed rejection of a nonblocking injection request.
// Errors match another InjectionError with the same Reason through errors.Is.
// Closed rejections also match net.ErrClosed; Handler adds ErrFlowNotLive.
type InjectionError struct {
	// Reason identifies the violated injection constraint.
	Reason InjectionReason
}

// Error describes why the injection was rejected.
func (e *InjectionError) Error() string {
	switch e.Reason {
	case InjectionFull:
		return "proxy: injection queue is full"
	case InjectionSize:
		return "proxy: injected message exceeds size limit"
	case InjectionType:
		return "proxy: injection requires a compatible protocol message"
	case InjectionIdentity:
		return "proxy: injection flow identity mismatch"
	case InjectionDirectionMismatch:
		return "proxy: injection direction mismatch"
	case InjectionClosed:
		return "proxy: injected flow is not live"
	default:
		return "proxy: invalid injection"
	}
}

// Is matches the rejection reason rather than the particular error instance.
func (e *InjectionError) Is(target error) bool {
	other, ok := target.(*InjectionError)
	return ok && other != nil && e.Reason == other.Reason
}

// Unwrap makes a closed injection match the standard closed-transport error.
func (e *InjectionError) Unwrap() error {
	if e.Reason == InjectionClosed {
		return net.ErrClosed
	}
	return nil
}

var (
	// ErrInjectionFull is a bounded-queue rejection.
	ErrInjectionFull = &InjectionError{Reason: InjectionFull}
	// ErrInjectionSize is a protocol payload-size rejection.
	ErrInjectionSize = &InjectionError{Reason: InjectionSize}
	// ErrInjectionType is an incompatible message/flow rejection.
	ErrInjectionType = &InjectionError{Reason: InjectionType}
	// ErrInjectionIdentity is a flow-identity rejection.
	ErrInjectionIdentity = &InjectionError{Reason: InjectionIdentity}
	// ErrInjectionDirection is an explicit-direction rejection.
	ErrInjectionDirection = &InjectionError{Reason: InjectionDirectionMismatch}
	// ErrInjectionClosed is an ended-flow or connection rejection.
	ErrInjectionClosed = &InjectionError{Reason: InjectionClosed}
)
