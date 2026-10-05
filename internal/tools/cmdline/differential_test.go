// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package cmdline

import (
	json "encoding/json/v2"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/pflag"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/options"
)

type flagRow struct {
	Option        string `json:"option"`
	Short         string `json:"short"`
	Metavar       string `json:"metavar"`
	Help          string `json:"help"`
	Default       any    `json:"default"`
	ParsedDefault any    `json:"parsed_default"`
}

type optionRow struct {
	Type    string   `json:"type"`
	Default any      `json:"default"`
	Help    string   `json:"help"`
	Choices []string `json:"choices"`
}

func TestDifferentialFlagTable(t *testing.T) {
	var reference struct {
		Options map[string]optionRow `json:"options"`
		Core    map[string]flagRow   `json:"core"`
		All     map[string]flagRow   `json:"all"`
	}
	if err := json.Unmarshal(difftest.Python(t, flagTableReference, nil), &reference); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		full bool
		want map[string]flagRow
	}{
		"success: core registered options":      {false, reference.Core},
		"success: all registered addon options": {true, reference.All},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opts := options.New()
			if tt.full {
				opts = options.NewManager()
				for name, row := range reference.Options {
					typ := map[string]options.Type{"bool": options.TypeBool, "int": options.TypeInt, "str": options.TypeStr, "optional int": options.TypeOptInt, "optional str": options.TypeOptStr, "sequence of str": options.TypeSeq}[row.Type]
					def := row.Default
					if n, ok := def.(float64); ok {
						def = int(n)
					}
					if err := opts.Add(t.Context(), name, typ, def, row.Help, options.WithChoices(row.Choices...)); err != nil {
						t.Fatal(err)
					}
				}
			}
			cmd := New(opts, "test")
			got := make(map[string]flagRow)
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				var value *optionValue
				switch v := flag.Value.(type) {
				case *optionValue:
					value = v
				case *sequenceValue:
					value = v.optionValue
				default:
					return
				}
				metavar := value.metavar
				if value.option.Type() == options.TypeBool {
					metavar = ""
				}
				got["--"+flag.Name] = flagRow{value.option.Name(), flag.Shorthand, metavar, flag.Usage, value.option.Default(), value.value}
			})
			// Decode both sides into the same JSON number representation.
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			got = nil
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("flag table (-Python +Go):\n%s", diff)
			}
			if len(got) == 0 {
				t.Fatal("reference produced no flags")
			}
		})
	}
}

// The reference derives flag names and display metavars from the actual
// argparse parser that produces mitmdump --help, not from a copied flag list.
const flagTableReference = `
import asyncio
import json
import re
from mitmproxy import options, optmanager
from mitmproxy.tools import cmdline
from mitmproxy.tools.dump import DumpMaster

def table(opts):
    parser = cmdline.mitmdump(opts)
    result = {}
    formatter = parser._get_formatter()
    for action in parser._actions:
        if action.dest not in opts:
            continue
        option = opts._options[action.dest]
        metavar = "" if action.nargs == 0 else formatter._format_args(action, action.dest.upper())
        for flag in action.option_strings:
            if flag.startswith("--"):
                result[flag] = dict(option=action.dest,
                    short=next((s[1:] for s in action.option_strings if not s.startswith("--")), ""),
                    metavar=metavar, help=action.help or "", default=option.default,
                    parsed_default=action.default)
    help_flags = set()
    for line in parser.format_help().splitlines():
        if line.lstrip().startswith('-'):
            invocation = re.split(r' {2,}', line.strip())[0]
            help_flags.update(re.findall(r'--[a-z][a-z0-9-]*', invocation))
    common_flags = {'--help', '--version', '--options', '--commands', '--set', '--quiet', '--verbose'}
    assert help_flags - common_flags == set(result), (help_flags, result)
    return result

async def collect():
    opts = options.Options()
    core = table(opts)
    master = DumpMaster(opts)
    result = dict(options=optmanager.dump_dicts(opts), core=core, all=table(opts))
    await master.done()
    print(json.dumps(result))

asyncio.run(collect())
`

func TestDifferentialParsing(t *testing.T) {
	tests := map[string]struct {
		args              []string
		consumesDelimiter bool
	}{
		"success: defaults":             {args: []string{}},
		"success: disable server":       {args: []string{"-n"}},
		"success: booleans":             {args: []string{"--no-rawtcp", "--ssl-insecure"}},
		"success: optional string":      {args: []string{"--cert-passphrase", ""}},
		"success: decimal integer":      {args: []string{"--listen-port", " +1_024 "}},
		"success: repeated integer":     {args: []string{"-p", "1", "-p", "2"}},
		"success: sequence punctuation": {args: []string{"--ignore-hosts", "a,b", "--ignore-hosts", "\"quoted\""}},
		"success: filter remainder":     {args: []string{"~u", "host", "--no-server"}},
		"success: quiet and verbose":    {args: []string{"-q", "-v"}},
		"success: quiet":                {args: []string{"--quiet"}},
		"success: verbose":              {args: []string{"--verbose"}},
		"success: dump options":         {args: []string{"--options"}},
		"success: dump commands":        {args: []string{"--commands"}},
		"success: set punctuation":      {args: []string{"--set", "ignore_hosts=a,b", "--set", "ignore_hosts=\"quoted\"", "--set", "ssl_insecure"}},
		"success: end of options":       {args: []string{"--", "--no-server"}, consumesDelimiter: true},
		"error: conflicting boolean":    {args: []string{"--rawtcp", "--no-rawtcp"}},
		"error: unknown option":         {args: []string{"--nonesuch"}},
		"error: missing integer":        {args: []string{"-p"}},
		"error: malformed integer":      {args: []string{"-p", "invalid"}},
		"error: empty integer":          {args: []string{"-p", ""}},
	}
	input := make(map[string][]string, len(tests))
	for name, tt := range tests {
		input[name] = tt.args
	}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	type commonArgs struct {
		Quiet    bool     `json:"quiet"`
		Verbose  bool     `json:"verbose"`
		Options  bool     `json:"options"`
		Commands bool     `json:"commands"`
		Set      []string `json:"set"`
	}
	var reference map[string]struct {
		Error  bool           `json:"error"`
		Values map[string]any `json:"values"`
		Filter []string       `json:"filter"`
		Common commonArgs     `json:"common"`
	}
	if err := json.Unmarshal(difftest.Python(t, parseReference, data), &reference); err != nil {
		t.Fatal(err)
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opts := options.New()
			cmd := New(opts, "test")
			err := cmd.ParseFlags(tt.args)
			want := reference[name]
			if (err != nil) != want.Error {
				t.Fatalf("ParseFlags(%q): %v; Python error=%v", tt.args, err, want.Error)
			}
			if want.Error {
				return
			}
			got := make(map[string]any)
			cmd.Flags().Visit(func(flag *pflag.Flag) {
				switch value := flag.Value.(type) {
				case *optionValue:
					got[value.option.Name()] = value.value
				case *sequenceValue:
					got[value.option.Name()] = value.value
				}
			})
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			got = nil
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(want.Values, got); diff != "" {
				t.Fatalf("values (-Python +Go):\n%s", diff)
			}
			if tt.consumesDelimiter {
				// argparse.REMAINDER keeps -- as filter text; GNU parsing consumes
				// it. This intentional difference is listed in docs/compat.md.
				if diff := cmp.Diff(tt.args, want.Filter); diff != "" {
					t.Fatalf("Python delimiter behavior changed:\n%s", diff)
				}
				want.Filter = want.Filter[1:]
			}
			if diff := cmp.Diff(strings.Join(want.Filter, " "), strings.Join(cmd.Flags().Args(), " ")); diff != "" {
				t.Fatal(diff)
			}
			var common commonArgs
			common.Quiet, _ = cmd.Flags().GetBool("quiet")
			common.Verbose, _ = cmd.Flags().GetBool("verbose")
			common.Options, _ = cmd.Flags().GetBool("options")
			common.Commands, _ = cmd.Flags().GetBool("commands")
			common.Set, _ = cmd.Flags().GetStringArray("set")
			if diff := cmp.Diff(want.Common, common); diff != "" {
				t.Fatalf("common arguments (-Python +Go):\n%s", diff)
			}
		})
	}
}

const parseReference = `
import contextlib
import io
import json
import sys
from mitmproxy import options
from mitmproxy.tools import cmdline

result = {}
for name, argv in json.load(sys.stdin).items():
    opts = options.Options()
    parser = cmdline.mitmdump(opts)
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            args = parser.parse_args(argv)
        result[name] = dict(error=False, values={k:v for k,v in vars(args).items() if k in opts and v is not None}, filter=args.filter_args,
            common=dict(quiet=args.quiet, verbose=bool(args.verbose), options=args.options, commands=args.commands, set=args.setoptions))
    except SystemExit:
        result[name] = dict(error=True, values={}, filter=[])
print(json.dumps(result))
`
