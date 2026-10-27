// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyserver

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/local"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func TestLocalRedirectorOption(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"metadata":                    {run: localOptionMetadata},
			"constructors_receive_path":   {run: localOptionConstructors},
			"empty_default":               {run: localOptionEmptyDefault},
			"next_daemon_only":            {run: localOptionNextDaemon},
			"launch_validation_preserved": {run: localOptionLaunchValidation},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func localOptionMetadata(t *testing.T) {
	m, _, _, _ := fixture(t, false)
	item, ok := m.Options.Lookup("local_redirector_path")
	if !ok {
		t.Fatal("local_redirector_path is not registered")
	}
	var want []string
	for line := range strings.Lines(string(testutil.Fixture(t, "options-go-only.txt"))) {
		fields := strings.Split(strings.TrimSuffix(line, "\n"), "\t")
		if fields[0] == "local_redirector_path" {
			want = fields
		}
	}
	if len(want) != 4 {
		t.Fatal("manifest does not contain exactly four local redirector metadata fields")
	}
	if diff := gocmp.Diff(want, []string{item.Name(), item.Type().String(), `""`, item.Help()}); diff != "" {
		t.Fatalf("registered metadata (-manifest +actual):\n%s", diff)
	}
	if item.Type() != options.TypeStr || item.Default() != "" {
		t.Fatalf("local redirector type/default = %v/%v, want str/empty", item.Type(), item.Default())
	}
}

func localOptionConstructors(t *testing.T) {
	m, ps, _, _ := fixture(t, false)
	dir := t.TempDir()
	path := filepath.Join(dir, "redirector")
	if err := os.WriteFile(path, []byte("inert redirector fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		constructor := ps.localRedirectors[goos]
		var received []string
		ps.localRedirectors[goos] = func(dir, path string) local.Redirector {
			received = []string{dir, path}
			return constructor(dir, path)
		}
		r, err := ps.newLocalRedirector(goos, dir, path)
		if err != nil {
			t.Fatalf("%s constructor: %v", goos, err)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("%s inert close: %v", goos, err)
		}
		if diff := gocmp.Diff([]string{dir, path}, received); diff != "" {
			t.Fatalf("%s constructor arguments (-want +got):\n%s", goos, diff)
		}
		ps.localRedirectors[goos] = constructor
	}
	constructor := ps.localRedirectors[runtime.GOOS]
	var received []string
	ps.localRedirectors[runtime.GOOS] = func(dir, path string) local.Redirector {
		received = []string{dir, path}
		return constructor(dir, path)
	}
	update(t, m, map[string]any{"server": false, "confdir": dir, "local_redirector_path": path, "mode": []string{"local"}})
	if diff := gocmp.Diff([]string{dir, path}, received); diff != "" {
		t.Fatalf("configured constructor arguments (-want +got):\n%s", diff)
	}
	if ps.localDaemon.redirector == nil || len(ps.ListenAddrs()) != 0 {
		t.Fatal("configuration must create an inert daemon without opening listeners")
	}
	if err := ps.localDaemon.redirector.Close(); err != nil {
		t.Fatal(err)
	}
}

func localOptionEmptyDefault(t *testing.T) {
	m, ps, _, _ := fixture(t, false)
	if got := m.Options.Str("local_redirector_path"); got != "" {
		t.Fatalf("default override = %q, want empty", got)
	}
	constructor := ps.localRedirectors[runtime.GOOS]
	var received []string
	ps.localRedirectors[runtime.GOOS] = func(dir, path string) local.Redirector {
		received = append(received, path)
		return constructor(dir, path)
	}
	update(t, m, map[string]any{"server": false, "confdir": t.TempDir(), "mode": []string{"local"}})
	if diff := gocmp.Diff([]string{""}, received); diff != "" {
		t.Fatalf("default constructor override (-want +got):\n%s", diff)
	}
	if err := ps.localDaemon.redirector.Close(); err != nil {
		t.Fatal(err)
	}
}

func localOptionNextDaemon(t *testing.T) {
	m, ps, _, _ := fixture(t, false)
	dir := t.TempDir()
	firstPath, nextPath := filepath.Join(dir, "first"), filepath.Join(dir, "next")
	for _, path := range []string{firstPath, nextPath} {
		if err := os.WriteFile(path, []byte("inert redirector fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	constructor := ps.localRedirectors[runtime.GOOS]
	var paths []string
	ps.localRedirectors[runtime.GOOS] = func(dir, path string) local.Redirector {
		paths = append(paths, path)
		return constructor(dir, path)
	}
	update(t, m, map[string]any{"server": false, "confdir": dir, "local_redirector_path": firstPath, "mode": []string{"local"}})
	first := ps.localDaemon.redirector
	update(t, m, map[string]any{"local_redirector_path": nextPath})
	update(t, m, map[string]any{"mode": []string{"regular"}})
	update(t, m, map[string]any{"mode": []string{"local:curl"}})
	if ps.localDaemon.redirector != first {
		t.Fatal("changing the override or mode replaced the process-lifetime daemon")
	}
	if diff := gocmp.Diff([]string{firstPath}, paths); diff != "" {
		t.Fatalf("existing daemon constructor calls (-want +got):\n%s", diff)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	next := master.New(master.Config{})
	t.Cleanup(func() {
		if err := next.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	nextPS, err := New(proxy.Config{Manager: next.Addons, Options: next.Options, Connections: new(proxy.Connections)})
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Addons.Add(t.Context(), nextPS); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := next.Do(context.WithoutCancel(t.Context()), nextPS.Done); err != nil {
			t.Error(err)
		}
	})
	nextPS.localRedirectors[runtime.GOOS] = ps.localRedirectors[runtime.GOOS]
	update(t, next, map[string]any{"server": false, "confdir": dir, "local_redirector_path": nextPath, "mode": []string{"local"}})
	if diff := gocmp.Diff([]string{firstPath, nextPath}, paths); diff != "" {
		t.Fatalf("next daemon constructor calls (-want +got):\n%s", diff)
	}
	if err := nextPS.localDaemon.redirector.Close(); err != nil {
		t.Fatal(err)
	}
}

func localOptionLaunchValidation(t *testing.T) {
	m, ps, _, _ := fixture(t, false)
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	update(t, m, map[string]any{"server": false, "confdir": dir, "local_redirector_path": missing, "mode": []string{"local"}})
	if ps.localDaemon.redirector == nil {
		t.Fatal("deferred validation must not reject inert constructor configuration")
	}
	if _, err := local.AcquireArtifact(t.Context(), dir, missing, runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("unchanged launch-time artifact validation accepted a missing override")
	}
	if err := ps.localDaemon.redirector.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("invalid override acquired or created artifacts: entries=%v err=%v", entries, err)
	}
}
