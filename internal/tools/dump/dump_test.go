// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Upstream test/mitmproxy/tools/test_dump.py maps onto this file as
// follows:
//
//	TestDumpMaster.test_addons_termlog -> TestAddonsTermLog
//	TestDumpMaster.test_addons_dumper  -> TestAddonsDumper
//
// Upstream test/mitmproxy/tools/test_main.py maps as follows:
//
//	test_mitmweb                        -> not applicable: the web frontend
//	                                       is a different binary, not built
//	                                       yet.
//	test_mitmdump                       -> the shutdown addon script it
//	                                       loads needs the scripts option,
//	                                       which no ported addon registers;
//	                                       the signal shutdown path is
//	                                       covered in cmd/mitmdump.
//	test_options_includes_addon_options -> not applicable: addon scripts
//	                                       need the scripts option, which no
//	                                       ported addon registers.
//	test_options_without_scripts        -> covered in cmd/mitmdump, which
//	                                       owns the --options output.
package dump

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

// newMaster returns a Master that is closed with the test.
func newMaster(t *testing.T, cfg Config) *Master {
	t.Helper()
	m, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return m
}

func TestAddonsTermLog(t *testing.T) {
	tests := map[string]struct {
		withTermlog bool
	}{
		"success: registered":     {withTermlog: true},
		"success: not registered": {withTermlog: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := newMaster(t, Config{WithTermlog: tt.withTermlog})
			if got := m.Addons.Get("termlog") != nil; got != tt.withTermlog {
				t.Fatalf("Addons.Get(termlog) != nil = %t, want %t", got, tt.withTermlog)
			}
		})
	}
}

func TestAddonsDumper(t *testing.T) {
	tests := map[string]struct {
		withDumper bool
	}{
		"success: registered":     {withDumper: true},
		"success: not registered": {withDumper: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := newMaster(t, Config{WithDumper: tt.withDumper})
			if got := m.Addons.Get("dumper") != nil; got != tt.withDumper {
				t.Fatalf("Addons.Get(dumper) != nil = %t, want %t", got, tt.withDumper)
			}
		})
	}
}

// TestAddonOrder pins the registration order: termlog first, as upstream's
// Master registers it before anything else, then the ported subset of
// upstream's default_addons in upstream's order, then the dumper and the
// three addons mitmproxy's tools/dump.py appends.
func TestAddonOrder(t *testing.T) {
	m := newMaster(t, Config{WithTermlog: true, WithDumper: true})
	want := []string{
		"*termlog.TermLog",
		"*core.Core",
		"*browser.Browser",
		"*block.Block",
		"*blocklist.BlockList",
		"*anticache.AntiCache",
		"*anticomp.AntiComp",
		"*clientplayback.ClientPlayback",
		"*commandhistory.Addon",
		"*comment.Comment",
		"*cut.Addon",
		"*disableh2c.DisableH2C",
		"*export.Addon",
		"*onboarding.Onboarding",
		"*proxyauth.ProxyAuth",
		"*proxyserver.ProxyServer",
		"*nextlayer.NextLayer",
		"*serverplayback.ServerPlayback",
		"*mapremote.MapRemote",
		"*maplocal.MapLocal",
		"*modifybody.ModifyBody",
		"*modifyheaders.ModifyHeaders",
		"*stickyauth.StickyAuth",
		"*stickycookie.StickyCookie",
		"*save.Save",
		"*savehar.Addon",
		"*tlsconfig.TLSConfig",
		"*upstreamauth.UpstreamAuth",
		"*updatealtsvc.UpdateAltSvc",
		"*dumper.Dumper",
		"*keepserving.KeepServing",
		"*readfile.ReadFile",
		"*errorcheck.ErrorCheck",
	}
	chain := m.Addons.Chain()
	got := make([]string, len(chain))
	for i, a := range chain {
		got[i] = fmt.Sprintf("%T", a)
	}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Fatalf("addon chain (-want +got):\n%s", diff)
	}
}

// optionRow is one line of the option list fixtures: name, type as
// upstream's typespec_to_str renders it, default (decoded from JSON) and
// the help text.
type optionRow struct {
	Type    string
	Default any
}

// fixtureOptions reads testdata/options-upstream.txt and
// testdata/options-go-only.txt into one name-keyed table.
func fixtureOptions(t *testing.T) map[string]optionRow {
	t.Helper()
	rows := make(map[string]optionRow)
	for _, rel := range []string{"options-upstream.txt", "options-go-only.txt"} {
		for n, line := range strings.Split(strings.TrimSuffix(string(testutil.Fixture(t, rel)), "\n"), "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) != 4 {
				t.Fatalf("%s:%d: %d tab-separated fields, want 4", rel, n+1, len(fields))
			}
			var def any
			if err := json.Unmarshal([]byte(fields[2]), &def); err != nil {
				t.Fatalf("%s:%d: default %s: %v", rel, n+1, fields[2], err)
			}
			rows[fields[0]] = optionRow{Type: fields[1], Default: def}
		}
	}
	return rows
}

// jsonValue converts an option value to the shape a JSON decoder produces
// for the same value, so it can be compared with the fixture default.
func jsonValue(v any) any {
	switch x := v.(type) {
	case int:
		return float64(x)
	case *int:
		if x == nil {
			return nil
		}
		return float64(*x)
	case *string:
		if x == nil {
			return nil
		}
		return *x
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	}
	return v
}

// TestOptionTable checks every option the assembled addon set registers
// against the upstream and Go-only option lists: the name must exist and
// the type and default must be equal. The table is built from the live
// registry, not from a hand-written list.
func TestOptionTable(t *testing.T) {
	fixture := fixtureOptions(t)
	m := newMaster(t, Config{WithTermlog: true, WithDumper: true})
	items := m.Options.Items()
	if len(items) == 0 {
		t.Fatal("the assembled master registers no options")
	}
	for _, o := range items {
		t.Run(o.Name(), func(t *testing.T) {
			row, ok := fixture[o.Name()]
			if !ok {
				t.Fatalf("option %s is in neither options-upstream.txt nor options-go-only.txt", o.Name())
			}
			if got := o.Type().String(); got != row.Type {
				t.Errorf("type = %s, want %s", got, row.Type)
			}
			if diff := gocmp.Diff(row.Default, jsonValue(o.Default())); diff != "" {
				t.Errorf("default (-fixture +registered):\n%s", diff)
			}
		})
	}
}

// TestLoggerFanout checks the composed logger: a record reaches the
// terminal log output, and an error-level record trips the startup error
// check, as the composition of master, errorcheck and termlog handlers
// must deliver every record to each.
func TestLoggerFanout(t *testing.T) {
	var out, errOut strings.Builder
	m := newMaster(t, Config{Stdout: &out, Stderr: &errOut, WithTermlog: true})
	m.Logger().Error("fanout probe")
	if !strings.Contains(out.String(), "fanout probe") {
		t.Errorf("terminal output %q does not contain the record", out.String())
	}
	ec, ok := m.Addons.Get("errorcheck").(master.ErrorCheck)
	if !ok {
		t.Fatal("errorcheck addon does not implement master.ErrorCheck")
	}
	err := ec.ShutdownIfErrored(t.Context())
	var exit *master.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("ShutdownIfErrored = %v, want a *master.ExitError", err)
	}
	if exit.ExitCode() != 1 {
		t.Fatalf("ExitCode = %d, want 1", exit.ExitCode())
	}
}

// failWriter fails every write, the way a closed terminal does.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("terminal gone") }

// TestTermLogFatalShutdown checks the fatal seam: a terminal write failure
// must end Run with exit status 1 through Master.ShutdownWithError, not
// through os.Exit.
func TestTermLogFatalShutdown(t *testing.T) {
	opts := options.New()
	m := newMaster(t, Config{Options: opts, Stdout: failWriter{}, WithTermlog: true})
	err := m.Do(t.Context(), func(ctx context.Context) error {
		return opts.Update(ctx, map[string]any{"server": false})
	})
	if err != nil {
		t.Fatal(err)
	}
	// Below the error level, so the startup check cannot be what fails Run.
	m.Logger().Info("write me to the broken terminal")
	runErr := m.Run(t.Context())
	var exit *master.ExitError
	if !errors.As(runErr, &exit) {
		t.Fatalf("Run = %v, want a *master.ExitError", runErr)
	}
	if exit.ExitCode() != 1 {
		t.Fatalf("ExitCode = %d, want 1", exit.ExitCode())
	}
}

// TestLoggerWithoutTermlog checks that the composed logger still serves
// the startup error check when the terminal logger is not registered.
func TestLoggerWithoutTermlog(t *testing.T) {
	var errOut strings.Builder
	m := newMaster(t, Config{Stderr: &errOut})
	m.Logger().Error("startup failure probe")
	ec, ok := m.Addons.Get("errorcheck").(master.ErrorCheck)
	if !ok {
		t.Fatal("errorcheck addon does not implement master.ErrorCheck")
	}
	if err := ec.ShutdownIfErrored(t.Context()); err == nil {
		t.Fatal("ShutdownIfErrored = nil, want the startup failure")
	}
}

var _ slog.Handler = (*fanoutHandler)(nil)
