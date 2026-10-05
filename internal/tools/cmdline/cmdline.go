// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package cmdline builds mitmdump's flags from its registered options.
package cmdline

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/zchee/mitmproxy-go/options"
)

// New constructs the mitmdump command with the registered subset of the flags
// in mitmproxy/tools/cmdline.py. The caller installs RunE to call Apply, handle
// --options and --commands, and start the master. Help, version and shell
// completion do not run that handler. Construct a fresh command for each parse;
// Cobra commands and their flag values are not safe for concurrent execution.
func New(opts *options.Manager, version string) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "mitmdump [options] [filter]",
		Short:                 "An interactive, SSL/TLS-capable intercepting proxy",
		Version:               version,
		Args:                  cobra.ArbitraryArgs,
		DisableFlagsInUseLine: true,
		RunE:                  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.SetVersionTemplate(fmt.Sprintf("Mitmproxy-go: {{.Version}}\nGo: %s\nPlatform: %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH))
	flags := cmd.Flags()
	// argparse.REMAINDER makes every token after the first filter part of it.
	flags.SetInterspersed(false)
	flags.Bool("options", false, "Show all options and their default values")
	flags.Bool("commands", false, "Show all commands and their signatures")
	var setSpecs []string
	flags.StringArrayVar(&setSpecs, "set", nil, "Set an `option[=value]`. When the value is omitted, booleans are set to true, strings and integers are set to None (if permitted), and sequences are emptied. Boolean values can be true, false or toggle. Sequences are set using multiple invocations to set for the same option.")
	flags.BoolP("quiet", "q", false, "Quiet.")
	flags.BoolP("verbose", "v", false, "Increase log verbosity.")
	for _, spec := range flagSpecs {
		if option, ok := opts.Lookup(spec.name); ok {
			addFlag(flags, opts, option, spec.short, spec.metavar)
		}
	}
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		var output strings.Builder
		fmt.Fprintf(&output, "Usage:\n  %s\n\nFlags:\n", cmd.UseLine())
		table := tabwriter.NewWriter(&output, 0, 4, 2, ' ', 0)
		cmd.Flags().VisitAll(func(flag *pflag.Flag) {
			if flag.Hidden {
				return
			}
			metavar, help := pflag.UnquoteUsage(flag)
			// Upstream help may contain backticks as prose, not pflag metavars.
			switch value := flag.Value.(type) {
			case *optionValue:
				metavar, help = value.metavar, flag.Usage
				if value.option.Type() == options.TypeBool {
					metavar = ""
				}
			case *sequenceValue:
				metavar, help = value.metavar, flag.Usage
			}
			name := "    --" + flag.Name
			if flag.Shorthand != "" {
				name = "-" + flag.Shorthand + ", --" + flag.Name
			}
			if metavar != "" {
				name += " " + metavar
			}
			_, _ = fmt.Fprintf(table, "  %s\t%s\n", name, help)
		})
		_ = table.Flush()
		if commands := cmd.Commands(); len(commands) != 0 {
			output.WriteString("\nCommands:\n")
			for _, child := range commands {
				if child.IsAvailableCommand() {
					fmt.Fprintf(&output, "  %s\t%s\n", child.Name(), child.Short)
				}
			}
		}
		_, err := fmt.Fprint(cmd.OutOrStdout(), output.String())
		return err
	})
	cmd.InitDefaultHelpFlag()
	cmd.InitDefaultVersionFlag()
	cmd.InitDefaultCompletionCmd()
	return cmd
}

// Apply loads --set, configuration files, and explicitly supplied flags, in
// that order, inside do's dispatch hold. Pass Master.Do as do; the context it
// gives the callback is also passed to option subscribers. Positional filters
// are applied last, except when --options or --commands requests an early exit.
// The command must have been parsed and built by New with opts.
func Apply(ctx context.Context, cmd *cobra.Command, opts *options.Manager, do func(context.Context, func(context.Context) error) error) error {
	flags := cmd.Flags()
	passed := make(map[string]any)
	flags.Visit(func(flag *pflag.Flag) {
		switch value := flag.Value.(type) {
		case *optionValue:
			passed[value.option.Name()] = value.value
		case *sequenceValue:
			passed[value.option.Name()] = slices.Clone(value.value.([]string))
		}
	})
	quiet, _ := flags.GetBool("quiet")
	verbose, _ := flags.GetBool("verbose")
	dumpOptions, _ := flags.GetBool("options")
	dumpCommands, _ := flags.GetBool("commands")
	if quiet || dumpOptions || dumpCommands {
		passed["termlog_verbosity"], passed["flow_detail"] = "error", 0
	}
	if verbose {
		passed["termlog_verbosity"], passed["flow_detail"] = "debug", 2
	}
	setSpecs, _ := flags.GetStringArray("set")
	return do(ctx, func(ctx context.Context) error {
		if err := opts.LoadAll(ctx, setSpecs, "", passed); err != nil {
			return err
		}
		if args := flags.Args(); len(args) != 0 && !dumpOptions && !dumpCommands {
			filter := strings.Join(args, " ")
			values := make(map[string]any, 3)
			for _, name := range []string{"save_stream_filter", "readfile_filter", "dumper_filter"} {
				if opts.Has(name) {
					values[name] = filter
				}
			}
			return opts.Update(ctx, values)
		}
		return nil
	})
}

// flagSpecs is the dedicated-flag allowlist, not the entire option registry.
// Other registered options remain available through --set and configuration.
var flagSpecs = []struct{ name, short, metavar string }{
	{"mode", "m", ""},
	{"anticache", "", ""},
	{"showhost", "", ""},
	{"show_ignored_hosts", "", ""},
	{"rfile", "r", "PATH"},
	{"scripts", "s", "SCRIPT"},
	{"stickycookie", "", "FILTER"},
	{"stickyauth", "", "FILTER"},
	{"save_stream_file", "w", "PATH"},
	{"anticomp", "", ""},
	{"listen_host", "", "HOST"},
	{"listen_port", "p", "PORT"},
	{"server", "n", ""},
	{"ignore_hosts", "", "HOST"},
	{"allow_hosts", "", "HOST"},
	{"tcp_hosts", "", "HOST"},
	{"upstream_auth", "", "USER:PASS"},
	{"proxyauth", "", "SPEC"},
	{"store_streamed_bodies", "", ""},
	{"rawtcp", "", ""},
	{"http2", "", ""},
	{"certs", "", "SPEC"},
	{"cert_passphrase", "", "PASS"},
	{"ssl_insecure", "k", ""},
	{"client_replay", "C", "PATH"},
	{"server_replay", "S", "PATH"},
	{"server_replay_kill_extra", "", ""},
	{"server_replay_extra", "", ""},
	{"server_replay_reuse", "", ""},
	{"server_replay_refresh", "", ""},
	{"map_remote", "M", "PATTERN"},
	{"map_local", "", "PATTERN"},
	{"modify_body", "B", "PATTERN"},
	{"modify_headers", "H", "PATTERN"},
	{"flow_detail", "", "LEVEL"},
}

func addFlag(flags *pflag.FlagSet, opts *options.Manager, option options.Option, short, metavar string) {
	name := strings.ReplaceAll(option.Name(), "_", "-")
	value := &optionValue{manager: opts, option: option, metavar: metavar}
	if metavar == "" {
		value.metavar = strings.ToUpper(option.Name())
	}
	usage := option.Help()
	if option.Type() == options.TypeBool {
		value.metavar, value.enabled = "bool", true
		negative := &optionValue{manager: opts, option: option, metavar: "bool", opposite: value}
		value.opposite = negative
		onShort, offShort := short, ""
		if option.Default().(bool) {
			onShort, offShort = "", short
		}
		flags.VarP(value, name, onShort, usage)
		flags.VarP(negative, "no-"+name, offShort, "")
		flags.Lookup(name).NoOptDefVal = "true"
		flags.Lookup("no-" + name).NoOptDefVal = "true"
		return
	}
	if choices := option.Choices(); len(choices) != 0 && metavar == "" {
		value.metavar = "{" + strings.Join(choices, ",") + "}"
	}
	if option.Type() == options.TypeSeq {
		flags.VarP(&sequenceValue{value}, name, short, usage+" May be passed multiple times.")
		return
	}
	flags.VarP(value, name, short, usage)
}

type optionValue struct {
	manager  *options.Manager
	option   options.Option
	metavar  string
	value    any
	enabled  bool
	opposite *optionValue
}

func (v *optionValue) String() string {
	switch value := v.value.(type) {
	case nil:
		return ""
	case *int:
		return fmt.Sprint(*value)
	case *string:
		return *value
	default:
		return fmt.Sprint(value)
	}
}

func (v *optionValue) Type() string { return v.metavar }

func (v *optionValue) Set(text string) error {
	if v.option.Type() == options.TypeBool {
		if text != "true" {
			return fmt.Errorf("%s does not accept a value; use its positive or negative flag", v.option.Name())
		}
		if v.opposite.value != nil {
			return fmt.Errorf("--%s and --no-%s are mutually exclusive", strings.ReplaceAll(v.option.Name(), "_", "-"), strings.ReplaceAll(v.option.Name(), "_", "-"))
		}
		v.value = v.enabled
		return nil
	}
	if choices := v.option.Choices(); len(choices) != 0 && (v.option.Type() == options.TypeStr || v.option.Type() == options.TypeOptStr || v.option.Type() == options.TypeSeq) && !slices.Contains(choices, text) {
		return fmt.Errorf("invalid choice %q (choose from %s)", text, strings.Join(choices, ", "))
	}
	if v.option.Type() == options.TypeSeq {
		values, _ := v.value.([]string)
		v.value = append(values, text)
		return nil
	}
	if text == "" && (v.option.Type() == options.TypeInt || v.option.Type() == options.TypeOptInt) {
		return fmt.Errorf("%s requires an integer", v.option.Name())
	}
	value, err := v.manager.ParseSetVal(v.option.Name(), []string{text})
	if err == nil {
		v.value = value
	}
	return err
}

// Cobra uses SliceValue to keep repeatable flags available in completions.
type sequenceValue struct{ *optionValue }

func (v *sequenceValue) Append(text string) error { return v.Set(text) }
func (v *sequenceValue) Replace(values []string) error {
	previous := v.value
	v.value = []string{}
	for _, value := range values {
		if err := v.Set(value); err != nil {
			v.value = previous
			return err
		}
	}
	return nil
}

func (v *sequenceValue) GetSlice() []string {
	values, _ := v.value.([]string)
	return slices.Clone(values)
}
