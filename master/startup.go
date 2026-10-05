// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package master

import "context"

// ErrorCheck is the startup contract of the addon registered as "errorcheck".
// Run calls its methods outside dispatch so pending logs can be flushed.
// Implementations synchronize their addon state through Master.Do.
type ErrorCheck interface {
	// ShutdownIfErrored waits for pending log delivery and returns an ExitError
	// if an error was logged during startup.
	ShutdownIfErrored(context.Context) error
	// Finish stops collecting startup errors after the final successful check.
	Finish(context.Context) error
}

// ServerSetup is the startup contract of the addon registered as "proxyserver".
// Run calls SetupServers on its own goroutine, outside dispatch. It must honor
// context cancellation and return when setup is complete, rather than running
// the accept loops itself. The context remains live until Run exits; on shutdown
// during setup, Run cancels it and joins the setup goroutine outside dispatch.
type ServerSetup interface {
	SetupServers(context.Context) error
}

// ExitError requests a failing process exit without terminating the caller.
// Frontends find it with errors.As and use ExitCode as their process status.
type ExitError struct {
	// Err is the underlying cause. Nil uses the startup-error summary.
	Err error
}

// Error returns the cause's message or the startup-error summary.
func (e *ExitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return "Error logged during startup, exiting..."
}

// Unwrap returns the underlying cause.
func (e *ExitError) Unwrap() error { return e.Err }

// ExitCode returns the failure status, 1.
func (*ExitError) ExitCode() int { return 1 }
