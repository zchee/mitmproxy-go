// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxytest

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/errorcheck"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

type logBoundaryFixture struct {
	before bool
}

const boundaryLogEntry = "error collection fixture entry"

func (*logBoundaryFixture) Name() string { return "logboundaryfixture" }

func (f *logBoundaryFixture) Running(context.Context) error {
	if f.before {
		return errors.New(boundaryLogEntry)
	}
	return nil
}

func (*logBoundaryFixture) Request(context.Context, *flow.HTTPFlow) error {
	return errors.New(boundaryLogEntry)
}

func TestStartErrorLogBoundary(t *testing.T) {
	if phase := os.Getenv("PROXYTEST_LOG_PHASE"); phase != "" {
		p := Start(t, WithAddons(&logBoundaryFixture{before: phase == "before"}))
		if phase == "before" {
			t.Fatal("startup accepted a logged error")
		}
		if err := p.Master.Addons.Trigger(t.Context(), addon.RequestHook{Flow: testflow.TFlow()}); err != nil {
			t.Fatal(err)
		}
		return
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		phase       string
		wantFailure bool
	}{
		"error: before running includes logged entry": {phase: "before", wantFailure: true},
		"success: request error after running":        {phase: "after"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, "-test.run=^TestStartErrorLogBoundary$", "-test.timeout=45s")
			command.Env = append(os.Environ(), "PROXYTEST_LOG_PHASE="+test.phase)
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("log boundary subprocess hung: %v\n%s", ctx.Err(), output)
			}
			if !test.wantFailure {
				if err != nil {
					t.Fatalf("request error stopped a running proxy: %v\n%s", err, output)
				}
				return
			}
			exit, ok := errors.AsType[*exec.ExitError](err)
			if !ok || exit.ExitCode() != 1 {
				t.Fatalf("startup log subprocess = %v\n%s", err, output)
			}
			if !strings.Contains(string(output), boundaryLogEntry) {
				t.Fatalf("startup failure omitted the logged entry:\n%s", output)
			}
		})
	}
}

func TestStartupErrorCollectionBoundary(t *testing.T) {
	tests := map[string]struct {
		before  bool
		after   bool
		wantErr bool
	}{
		"error: before running includes entry":  {before: true, wantErr: true},
		"success: after running is not startup": {after: true},
		"success: empty startup collection":     {},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			check := errorcheck.New(errorcheck.Config{Stderr: &output, RepeatErrorsOnStderr: true})
			logger := slog.New(check.LogHandler())
			const entry = "connection failed in error collection boundary test"
			if test.before {
				logger.ErrorContext(t.Context(), entry)
			}
			ready := &startup{ready: make(chan struct{}), check: check}
			if err := ready.Running(t.Context()); err != nil {
				t.Fatal(err)
			}
			select {
			case <-ready.ready:
			default:
				t.Fatal("running did not publish readiness")
			}
			if test.after {
				logger.ErrorContext(t.Context(), entry)
			}
			err := check.ShutdownIfErrored(t.Context())
			if (err != nil) != test.wantErr {
				t.Fatalf("startup error = %v, want error %t; collected entries:\n%s", err, test.wantErr, output.String())
			}
			if test.wantErr && !strings.Contains(output.String(), entry) {
				t.Fatalf("startup failure omitted collected entry:\n%s", output.String())
			}
			if !test.wantErr && output.Len() != 0 {
				t.Fatalf("successful startup emitted a failure:\n%s", output.String())
			}
		})
	}
}

func TestStartReportsBindError(t *testing.T) {
	if address := os.Getenv("PROXYTEST_OCCUPIED_ADDRESS"); address != "" {
		mode := "regular"
		if os.Getenv("PROXYTEST_OCCUPIED_NETWORK") == "udp4" {
			mode = "reverse:udp://127.0.0.1:9"
		}
		Start(t, WithOptions(map[string]any{"mode": []string{mode + "@" + address}}))
		t.Fatal("startup accepted an occupied listener")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ network string }{
		"occupied TCP listener": {network: "tcp4"},
		"occupied UDP listener": {network: "udp4"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var address string
			var bindErr error
			if test.network == "tcp4" {
				listener, err := net.Listen(test.network, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				address = listener.Addr().String()
				probe, err := net.Listen(test.network, address)
				if err == nil {
					_ = probe.Close()
					t.Fatal("second TCP bind unexpectedly succeeded")
				}
				bindErr = err
			} else {
				listener, err := net.ListenPacket(test.network, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				address = listener.LocalAddr().String()
				probe, err := net.ListenPacket(test.network, address)
				if err == nil {
					_ = probe.Close()
					t.Fatal("second UDP bind unexpectedly succeeded")
				}
				bindErr = err
			}
			op, ok := errors.AsType[*net.OpError](bindErr)
			if !ok {
				t.Fatalf("bind failure has no socket cause: %v", bindErr)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, "-test.run=^TestStartReportsBindError$", "-test.timeout=45s")
			command.Env = append(os.Environ(), "PROXYTEST_OCCUPIED_ADDRESS="+address, "PROXYTEST_OCCUPIED_NETWORK="+test.network)
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("startup subprocess hung: %v\n%s", ctx.Err(), output)
			}
			exit, ok := errors.AsType[*exec.ExitError](err)
			if !ok || exit.ExitCode() != 1 {
				t.Fatalf("startup subprocess = %v\n%s", err, output)
			}
			if !strings.Contains(string(output), op.Err.Error()) || !strings.Contains(string(output), address) {
				t.Fatalf("startup lost the bind cause %q for %s:\n%s", op.Err.Error(), address, output)
			}
			if strings.Contains(string(output), "proxytest: no listening address") {
				t.Fatalf("startup hid its error behind a missing address:\n%s", output)
			}
		})
	}
}
