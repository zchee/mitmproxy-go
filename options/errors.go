// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package options

import (
	"fmt"
	"strings"
)

// OptionsError is mitmproxy's OptionsError: a malformed option value, a
// configuration file that cannot be parsed, or a rejection raised by a
// [Manager.Subscribe] callback.
//
// A subscriber that returns an *OptionsError (directly or wrapped) makes the
// [Manager] roll the update back. Any other error is passed to the caller
// without a rollback, as upstream lets exceptions other than OptionsError
// propagate.
type OptionsError struct { //nolint:revive // Named after mitmproxy's OptionsError, which addon authors know.
	// Msg is the message shown to the user.
	Msg string
	// Err is the underlying cause, if any.
	Err error
}

// Errorf returns an *OptionsError whose message is formatted from format and
// args.
func Errorf(format string, args ...any) *OptionsError {
	return &OptionsError{Msg: fmt.Sprintf(format, args...)}
}

// Error implements error.
func (e *OptionsError) Error() string {
	switch {
	case e.Msg != "":
		return e.Msg
	case e.Err != nil:
		return e.Err.Error()
	default:
		return ""
	}
}

// Unwrap returns the underlying cause.
func (e *OptionsError) Unwrap() error { return e.Err }

// TypeError reports a value whose Go type does not fit the option type. It
// corresponds to the TypeError mitmproxy's typecheck raises.
type TypeError struct {
	// Name is the option name.
	Name string
	// Type is the option type.
	Type Type
	// Value is the rejected value.
	Value any
}

// Error implements error.
func (e *TypeError) Error() string {
	return fmt.Sprintf("Expected %s for %s, but got %T.", e.Type, e.Name, e.Value)
}

// UnknownOptionError reports updates naming options that are not registered.
// It corresponds to the KeyError mitmproxy's OptManager.update raises.
type UnknownOptionError struct {
	// Names lists the unknown option names.
	Names []string
}

// Error implements error.
func (e *UnknownOptionError) Error() string {
	return "Unknown options: " + strings.Join(e.Names, ", ")
}
