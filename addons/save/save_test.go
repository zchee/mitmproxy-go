// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Upstream test/mitmproxy/addons/test_save.py maps onto this file as
// follows:
//
//	test_configure     -> TestConfigure
//	test_simple        -> TestProtocols/http, TestFilterAndAppend
//	test_tcp           -> TestProtocols/tcp
//	test_udp           -> TestProtocols/udp
//	test_dns           -> TestProtocols/dns
//	test_websocket     -> TestProtocols/websocket,
//	                      TestWebSocketNotSavedAtResponse
//	test_save_command  -> TestSaveCommand; its "@shown" part is not
//	                      applicable here: flow-specification resolution
//	                      is the view addon's contract (see the comment at
//	                      the end of this file).
//	test_rotate_stream -> TestRotateStream
//	test_disk_full     -> TestDiskFull
package save

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

func setup(t *testing.T, fatal func(error)) (*Save, *addon.Manager) {
	t.Helper()
	opts := options.New()
	s := New(opts, fatal)
	m := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(func() {
		if err := s.Done(t.Context()); err != nil {
			t.Error(err)
		}
		m.Close()
	})
	if err := m.Add(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	return s, m
}

func configure(t *testing.T, m *addon.Manager, values map[string]any) error {
	t.Helper()
	return m.Do(t.Context(), func(ctx context.Context) error { return m.Options().Update(ctx, values) })
}

func readFlows(t *testing.T, path string) []flow.Flow {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var flows []flow.Flow
	for f, err := range flowio.NewReader(file).All() {
		if err != nil {
			t.Fatal(err)
		}
		flows = append(flows, f)
	}
	return flows
}

func TestConfigure(t *testing.T) {
	s, m := setup(t, nil)
	if err := configure(t, m, map[string]any{"save_stream_file": new(t.TempDir())}); err == nil {
		t.Fatal("directory accepted as output")
	}
	if err := configure(t, m, map[string]any{"save_stream_file": new(filepath.Join(t.TempDir(), "foo")), "save_stream_filter": new("~~")}); err == nil {
		t.Fatal("invalid filter accepted")
	}
	if err := configure(t, m, map[string]any{"save_stream_filter": new("foo")}); err != nil {
		t.Fatal(err)
	}
	if s.filter == nil {
		t.Fatal("filter missing")
	}
	if err := configure(t, m, map[string]any{"save_stream_filter": nil}); err != nil {
		t.Fatal(err)
	}
	if s.filter != nil {
		t.Fatal("filter not cleared")
	}
}

// TestProtocols ports test_tcp, test_udp, test_dns, test_websocket, and
// test_simple: completed and failed flows, plus flushing an active flow.
func TestProtocols(t *testing.T) {
	tests := map[string]struct {
		build              func(bool) flow.Flow
		start, end, failed func(flow.Flow) addon.Hook
	}{
		"http": {
			build: func(failed bool) flow.Flow {
				if failed {
					return testflow.TFlow(testflow.WithError)
				}
				return testflow.TFlow(testflow.WithResponse)
			},
			start:  func(f flow.Flow) addon.Hook { return addon.RequestHook{Flow: f.(*flow.HTTPFlow)} },
			end:    func(f flow.Flow) addon.Hook { return addon.ResponseHook{Flow: f.(*flow.HTTPFlow)} },
			failed: func(f flow.Flow) addon.Hook { return addon.ErrorHook{Flow: f.(*flow.HTTPFlow)} },
		},
		"tcp": {
			build: func(failed bool) flow.Flow {
				if failed {
					return testflow.TTCPFlow(testflow.WithError)
				}
				return testflow.TTCPFlow()
			},
			start:  func(f flow.Flow) addon.Hook { return addon.TCPStartHook{Flow: f.(*flow.TCPFlow)} },
			end:    func(f flow.Flow) addon.Hook { return addon.TCPEndHook{Flow: f.(*flow.TCPFlow)} },
			failed: func(f flow.Flow) addon.Hook { return addon.TCPErrorHook{Flow: f.(*flow.TCPFlow)} },
		},
		"udp": {
			build: func(failed bool) flow.Flow {
				if failed {
					return testflow.TUDPFlow(testflow.WithError)
				}
				return testflow.TUDPFlow()
			},
			start:  func(f flow.Flow) addon.Hook { return addon.UDPStartHook{Flow: f.(*flow.UDPFlow)} },
			end:    func(f flow.Flow) addon.Hook { return addon.UDPEndHook{Flow: f.(*flow.UDPFlow)} },
			failed: func(f flow.Flow) addon.Hook { return addon.UDPErrorHook{Flow: f.(*flow.UDPFlow)} },
		},
		"dns": {
			build: func(failed bool) flow.Flow {
				if failed {
					return testflow.TDNSFlow(testflow.WithError)
				}
				return testflow.TDNSFlow(testflow.WithResponse)
			},
			start:  func(f flow.Flow) addon.Hook { return addon.DNSRequestHook{Flow: f.(*flow.DNSFlow)} },
			end:    func(f flow.Flow) addon.Hook { return addon.DNSResponseHook{Flow: f.(*flow.DNSFlow)} },
			failed: func(f flow.Flow) addon.Hook { return addon.DNSErrorHook{Flow: f.(*flow.DNSFlow)} },
		},
		"websocket": {
			build: func(failed bool) flow.Flow {
				if failed {
					return testflow.TWebSocketFlow(testflow.WithError)
				}
				return testflow.TWebSocketFlow()
			},
			start:  func(f flow.Flow) addon.Hook { return addon.RequestHook{Flow: f.(*flow.HTTPFlow)} },
			end:    func(f flow.Flow) addon.Hook { return addon.WebSocketEndHook{Flow: f.(*flow.HTTPFlow)} },
			failed: func(f flow.Flow) addon.Hook { return addon.WebSocketEndHook{Flow: f.(*flow.HTTPFlow)} },
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, m := setup(t, nil)
			path := filepath.Join(t.TempDir(), "flows.mitm")
			if err := configure(t, m, map[string]any{"save_stream_file": new(path)}); err != nil {
				t.Fatal(err)
			}
			completed, failed, active := tt.build(false), tt.build(true), tt.build(false)
			for _, hook := range []addon.Hook{tt.start(completed), tt.end(completed), tt.start(failed), tt.failed(failed), tt.start(active)} {
				if err := m.Hook(t.Context(), hook); err != nil {
					t.Fatal(err)
				}
			}
			if err := configure(t, m, map[string]any{"save_stream_file": nil}); err != nil {
				t.Fatal(err)
			}
			got := readFlows(t, path)
			if len(got) != 3 {
				t.Fatalf("saved %d flows, want 3", len(got))
			}
			for i, want := range []flow.Flow{completed, failed, active} {
				if got[i].Common().ID != want.Common().ID {
					t.Fatalf("flow %d: got %s, want %s", i, got[i].Common().ID, want.Common().ID)
				}
			}
			if err := m.Hook(t.Context(), tt.end(active)); err != nil {
				t.Fatal(err)
			}
			if n := len(readFlows(t, path)); n != 3 {
				t.Fatalf("disabled output has %d flows", n)
			}
		})
	}
}

func TestSaveCommand(t *testing.T) {
	_, m := setup(t, nil)
	path := filepath.Join(t.TempDir(), "foo")
	flows := []flow.Flow{testflow.TFlow(testflow.WithResponse)}
	tests := map[string]struct {
		paths   []string
		count   int
		wantErr bool
	}{
		"overwrite": {paths: []string{path, path}, count: 1},
		"append":    {paths: []string{path, "+" + path}, count: 2},
		"error":     {paths: []string{t.TempDir()}, wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for _, path := range tt.paths {
				_, err := m.Call(t.Context(), "save.file", flows, command.Path(path))
				if (err != nil) != tt.wantErr {
					t.Fatalf("error=%v, wantErr=%v", err, tt.wantErr)
				}
				if tt.wantErr {
					// Upstream raises a CommandError for an unwritable path.
					if _, ok := errors.AsType[*command.Error](err); !ok {
						t.Fatalf("got %v, want a command error", err)
					}
				}
			}
			if !tt.wantErr {
				if n := len(readFlows(t, path)); n != tt.count {
					t.Fatalf("saved %d, want %d", n, tt.count)
				}
			}
		})
	}
}

func TestRotateStream(t *testing.T) {
	_, m := setup(t, nil)
	first, second := filepath.Join(t.TempDir(), "a.txt"), filepath.Join(t.TempDir(), "b.txt")
	if err := configure(t, m, map[string]any{"save_stream_file": new(first)}); err != nil {
		t.Fatal(err)
	}
	f1, f2 := testflow.TFlow(testflow.WithResponse), testflow.TFlow(testflow.WithResponse)
	for _, hook := range []addon.Hook{addon.RequestHook{Flow: f1}, addon.ResponseHook{Flow: f1}, addon.RequestHook{Flow: f2}} {
		if err := m.Hook(t.Context(), hook); err != nil {
			t.Fatal(err)
		}
	}
	if err := configure(t, m, map[string]any{"save_stream_file": new(second)}); err != nil {
		t.Fatal(err)
	}
	if err := m.Hook(t.Context(), addon.ResponseHook{Flow: f2}); err != nil {
		t.Fatal(err)
	}
	if err := configure(t, m, map[string]any{"save_stream_file": nil}); err != nil {
		t.Fatal(err)
	}
	if n := len(readFlows(t, first)); n != 1 {
		t.Fatalf("first: %d", n)
	}
	if n := len(readFlows(t, second)); n != 1 {
		t.Fatalf("second: %d", n)
	}
}

// TestStrftimeRotation drives the clock behind the strftime path: each tick
// changes the formatted name, so the addon closes the finished file, creates
// the dated directory and opens the next file, as the option help promises.
func TestStrftimeRotation(t *testing.T) {
	s, m := setup(t, nil)
	clock := time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC)
	s.clock = func() time.Time { return clock }
	root := t.TempDir()
	if err := configure(t, m, map[string]any{"save_stream_file": new(filepath.Join(root, "%Y-%m-%d", "%H-%M-%S.mitm"))}); err != nil {
		t.Fatal(err)
	}
	f := testflow.TFlow(testflow.WithResponse)
	if err := s.Response(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Second)
	if err := s.Response(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if err := s.Done(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"03-04-05.mitm", "03-04-06.mitm"} {
		if n := len(readFlows(t, filepath.Join(root, "2000-01-02", name))); n != 1 {
			t.Fatalf("%s: %d flows", name, n)
		}
	}
}

// TestStrftimeSamePathKeepsFile writes twice within the same formatted name;
// the file stays open and holds both flows.
func TestStrftimeSamePathKeepsFile(t *testing.T) {
	s, m := setup(t, nil)
	clock := time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC)
	s.clock = func() time.Time { return clock }
	root := t.TempDir()
	if err := configure(t, m, map[string]any{"save_stream_file": new(filepath.Join(root, "%Y-%m-%d.mitm"))}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Response(t.Context(), testflow.TFlow(testflow.WithResponse)); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(time.Second)
	}
	if err := s.Done(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := len(readFlows(t, filepath.Join(root, "2000-01-02.mitm"))); n != 2 {
		t.Fatalf("got %d flows, want 2", n)
	}
}

func TestStrftimePath(t *testing.T) {
	tests := map[string]struct {
		format string
		want   string
	}{
		"local wall clock":      {format: "%Y-%m-%d_%H-%M-%S", want: "2000-01-02_03-04-05"},
		"microseconds":          {format: "%f", want: "123456"},
		"naive timezone":        {format: "a%zb%Zc", want: "abc"},
		"escaped percent":       {format: "%%", want: "%"},
		"escaped timezone":      {format: "%%z_%%Z", want: "%z_%Z"},
		"odd percent count":     {format: "%%%z_%%%Z", want: "%_%"},
		"even percent count":    {format: "%%%%z_%%%%Z", want: "%%z_%%Z"},
		"mixed directives":      {format: "%Y%%z%z%%Z%Z%f", want: "2000%z%Z123456"},
		"unsupported modifiers": {format: "%EC_%Ey_%EY_%Od_%Om", want: "%EC_%Ey_%EY_%Od_%Om"},
		"unsupported directive": {format: "%q", want: "%q"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, m := setup(t, nil)
			s.clock = func() time.Time {
				return time.Date(2000, 1, 2, 3, 4, 5, 123456000, time.FixedZone("local", 9*60*60))
			}
			root := t.TempDir()
			if err := configure(t, m, map[string]any{"save_stream_file": new(filepath.Join(root, tt.format+".mitm"))}); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(filepath.Join(root, tt.want+".mitm"), s.currentPath); diff != "" {
				t.Fatalf("formatted stream path (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDiskFull(t *testing.T) {
	var (
		calls int
		got   error
	)
	s, m := setup(t, func(err error) { calls++; got = err })
	var stderr bytes.Buffer
	s.stderr = &stderr
	if err := configure(t, m, map[string]any{"save_stream_file": new(filepath.Join(t.TempDir(), "foo.txt"))}); err != nil {
		t.Fatal(err)
	}
	if err := s.file.Close(); err != nil {
		t.Fatal(err)
	}
	err := s.Response(t.Context(), testflow.TFlow(testflow.WithResponse))
	exit, ok := errors.AsType[*master.ExitError](err)
	if !ok || exit.ExitCode() != 1 {
		t.Fatalf("got %v, want exit 1", err)
	}
	if !strings.Contains(stderr.String(), "Error while writing to ") {
		t.Fatal(stderr.String())
	}
	if calls != 1 {
		t.Fatalf("fatal was called %d times, want once", calls)
	}
	fatalExit, ok := errors.AsType[*master.ExitError](got)
	if !ok || fatalExit.ExitCode() != 1 {
		t.Fatalf("fatal received %v, want exit 1", got)
	}
}

// TestDiskFullNilFatal drops the notification without a callback; the write
// failure is still returned to the dispatcher.
func TestDiskFullNilFatal(t *testing.T) {
	s, m := setup(t, nil)
	s.stderr = new(bytes.Buffer)
	if err := configure(t, m, map[string]any{"save_stream_file": new(filepath.Join(t.TempDir(), "foo.txt"))}); err != nil {
		t.Fatal(err)
	}
	if err := s.file.Close(); err != nil {
		t.Fatal(err)
	}
	err := s.Response(t.Context(), testflow.TFlow(testflow.WithResponse))
	if _, ok := errors.AsType[*master.ExitError](err); !ok {
		t.Fatalf("got %v, want an ExitError", err)
	}
}

func TestFilterAndAppend(t *testing.T) {
	_, m := setup(t, nil)
	path := filepath.Join(t.TempDir(), "flows.mitm")
	if err := configure(t, m, map[string]any{"save_stream_file": new(path), "save_stream_filter": new("~c 201")}); err != nil {
		t.Fatal(err)
	}
	if err := m.Hook(t.Context(), addon.ResponseHook{Flow: testflow.TFlow(testflow.WithResponse)}); err != nil {
		t.Fatal(err)
	}
	if err := configure(t, m, map[string]any{"save_stream_filter": nil}); err != nil {
		t.Fatal(err)
	}
	if err := m.Hook(t.Context(), addon.ResponseHook{Flow: testflow.TFlow(testflow.WithResponse)}); err != nil {
		t.Fatal(err)
	}
	if err := configure(t, m, map[string]any{"save_stream_file": nil}); err != nil {
		t.Fatal(err)
	}
	if err := configure(t, m, map[string]any{"save_stream_file": new("+" + path)}); err != nil {
		t.Fatal(err)
	}
	if err := m.Hook(t.Context(), addon.ResponseHook{Flow: testflow.TFlow(testflow.WithResponse)}); err != nil {
		t.Fatal(err)
	}
	if err := configure(t, m, map[string]any{"save_stream_file": nil}); err != nil {
		t.Fatal(err)
	}
	if n := len(readFlows(t, path)); n != 2 {
		t.Fatalf("saved %d flows, want 2", n)
	}
}

func TestWebSocketNotSavedAtResponse(t *testing.T) {
	_, m := setup(t, nil)
	path := filepath.Join(t.TempDir(), "flows.mitm")
	if err := configure(t, m, map[string]any{"save_stream_file": new(path)}); err != nil {
		t.Fatal(err)
	}
	f := testflow.TWebSocketFlow()
	if err := m.Hook(t.Context(), addon.RequestHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if err := m.Hook(t.Context(), addon.ResponseHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if n := len(readFlows(t, path)); n != 0 {
		t.Fatalf("response saved %d websocket flows prematurely", n)
	}
	if err := m.Hook(t.Context(), addon.WebSocketEndHook{Flow: f}); err != nil {
		t.Fatal(err)
	}
	if n := len(readFlows(t, path)); n != 1 {
		t.Fatalf("websocket end saved %d flows", n)
	}
}

func TestOptions(t *testing.T) {
	_, m := setup(t, nil)
	tests := map[string]struct{}{"save_stream_file": {}, "save_stream_filter": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			o, ok := m.Options().Lookup(name)
			if !ok {
				t.Fatal("option missing")
			}
			if o.Type() != options.TypeOptStr {
				t.Fatal(o.Type())
			}
			if diff := gocmp.Diff((*string)(nil), o.Default()); diff != "" {
				t.Fatal(diff)
			}
			for line := range strings.SplitSeq(string(testutil.Fixture(t, "options-upstream.txt")), "\n") {
				if strings.HasPrefix(line, name+"\t") {
					if diff := gocmp.Diff(strings.Split(line, "\t")[3], o.Help()); diff != "" {
						t.Fatal(diff)
					}
				}
			}
		})
	}
}

// Upstream test_save_command also resolves @shown through the view addon. The
// command registration and typed flow-slice invocation are tested above; flow
// specification resolution remains the view addon's contract.
