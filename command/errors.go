// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command

import "errors"

// Errors returned by [Manager]. Every error the Manager produces itself wraps
// exactly one of these sentinels, so callers can classify it with
// [errors.Is]; an error returned by a command function is passed through
// unchanged.
var (
	// ErrUnknownCommand reports a call to a name no command is registered
	// under.
	ErrUnknownCommand = errors.New("unknown command")

	// ErrSignature reports a function whose parameter or result types cannot
	// be expressed with the command type identities, or a registration option
	// that does not fit the function.
	ErrSignature = errors.New("invalid command signature")

	// ErrDuplicateCommand reports a registration under a name that is already
	// taken.
	ErrDuplicateCommand = errors.New("duplicate command")

	// ErrArgumentMismatch reports a call whose arguments do not match the
	// command's parameters in number or type.
	ErrArgumentMismatch = errors.New("command argument mismatch")

	// ErrRunnerSet reports a call to [Manager.SetRunner] on a Manager that
	// already has a Runner.
	ErrRunnerSet = errors.New("command runner already set")
)
