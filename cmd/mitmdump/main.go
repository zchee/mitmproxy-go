// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Mitmdump proxies traffic and prints flows to the terminal, as
// mitmproxy's mitmdump entry point does.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/zchee/mitmproxy-go/internal/tools/cmdline"
	"github.com/zchee/mitmproxy-go/internal/tools/dump"
	"github.com/zchee/mitmproxy-go/internal/version"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run builds the master and the command line, executes them and returns
// the process exit status.
func run(ctx context.Context, args []string, stdin io.ReadCloser, stdout, stderr io.Writer) int {
	opts := options.New()
	m, err := dump.New(ctx, dump.Config{
		Options:     opts,
		Stdout:      stdout,
		Stderr:      stderr,
		Stdin:       stdin,
		WithTermlog: true,
		WithDumper:  true,
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	previousLogger := slog.Default()
	defer slog.SetDefault(previousLogger)
	defer func() { _ = m.Close(context.WithoutCancel(ctx)) }()
	slog.SetDefault(m.Logger())

	cmd := cmdline.New(opts, version.Version)
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		if err := cmdline.Apply(ctx, c, opts, m.Do); err != nil {
			return err
		}
		flags := c.Flags()
		if show, _ := flags.GetBool("options"); show {
			text, err := opts.Dump()
			if err != nil {
				return err
			}
			_, err = io.WriteString(stdout, text)
			return err
		}
		if show, _ := flags.GetBool("commands"); show {
			return m.Commands.Dump(stdout)
		}
		stop := cmdline.Signals(m.Shutdown)
		defer stop()
		return m.Run(ctx)
	}
	if err := cmd.ExecuteContext(ctx); err != nil {
		return exitStatus(err, stderr)
	}
	return 0
}

// exitStatus maps a command error to the process status. An options error
// is printed as mitmproxy's entry point prints it; an exit error was
// already reported by whichever addon recorded it.
func exitStatus(err error, stderr io.Writer) int {
	if exit, ok := errors.AsType[*master.ExitError](err); ok {
		return exit.ExitCode()
	}
	if optErr, ok := errors.AsType[*options.OptionsError](err); ok {
		_, _ = fmt.Fprintf(stderr, "%s: %s\n", os.Args[0], optErr)
		return 1
	}
	_, _ = fmt.Fprintln(stderr, err)
	return 1
}
