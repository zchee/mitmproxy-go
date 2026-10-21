// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Mitmproxy runs the proxy with the interactive terminal frontend.
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
	"github.com/zchee/mitmproxy-go/internal/tools/console"
	"github.com/zchee/mitmproxy-go/internal/version"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(ctx context.Context, args []string, stdin io.ReadCloser, stdout, stderr io.Writer) (code int) {
	opts := options.New()
	m, err := console.New(ctx, console.Config{Options: opts, Stdin: stdin, Stdout: stdout, Stderr: stderr})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	previousLogger := slog.Default()
	defer slog.SetDefault(previousLogger)
	defer func() {
		if err := m.Close(context.WithoutCancel(ctx)); err != nil && code == 0 {
			_, _ = fmt.Fprintln(stderr, err)
			code = 1
		}
	}()
	slog.SetDefault(m.Logger())
	cmd := cmdline.NewConsole(opts, version.Version)
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		if err := cmdline.Apply(ctx, c, opts, m.Do); err != nil {
			return err
		}
		if show, _ := c.Flags().GetBool("options"); show {
			text, err := opts.Dump()
			if err != nil {
				return err
			}
			_, err = io.WriteString(stdout, text)
			return err
		}
		if show, _ := c.Flags().GetBool("commands"); show {
			return m.Commands.Dump(stdout)
		}
		if _, err := m.NewProgram(); err != nil {
			return err
		}
		stop := cmdline.Signals(m.Shutdown)
		defer stop()
		return m.Run(ctx)
	}
	if err := cmd.ExecuteContext(ctx); err != nil {
		if exit, ok := errors.AsType[*master.ExitError](err); ok {
			return exit.ExitCode()
		}
		if optErr, ok := errors.AsType[*options.OptionsError](err); ok {
			_, _ = fmt.Fprintf(stderr, "%s: %s\n", os.Args[0], optErr)
		} else {
			_, _ = fmt.Fprintln(stderr, err)
		}
		return 1
	}
	return 0
}
