// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/master"
)

func testWebEarlyShutdown(t *testing.T) {
	fatal := errors.New("fatal startup stop")
	tests := map[string]struct{ beforeRun, suspended, fatal bool }{
		"before_run":        {beforeRun: true},
		"immediate":         {},
		"suspended_startup": {suspended: true},
		"fatal_startup":     {suspended: true, fatal: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := newWebMaster(t)
			var reader *io.PipeReader
			if tt.suspended {
				r, w := io.Pipe()
				reader = r
				defer func() { _ = r.Close(); _ = w.Close() }()
				m.logger = slog.New(slog.NewTextHandler(w, nil))
			}
			if tt.beforeRun {
				m.Shutdown()
			}
			done := make(chan error, 1)
			go func() { done <- m.Run(t.Context()) }()
			if tt.suspended {
				entered := make(chan error, 1)
				go func() { var first [1]byte; _, err := reader.Read(first[:]); entered <- err }()
				select {
				case err := <-entered:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("startup never reached the real logger write")
				}
				// A one-byte read leaves the actual log write suspended outside
				// dispatch until shutdown has canceled frontend I/O.
			}
			if tt.fatal {
				m.ShutdownWithError(fatal)
			} else if !tt.beforeRun {
				m.Shutdown()
			}
			if reader != nil {
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if tt.fatal {
					if _, ok := errors.AsType[*master.ExitError](err); !ok || !errors.Is(err, fatal) {
						t.Fatalf("fatal shutdown lost its original error: %v", err)
					}
				} else if err != nil {
					t.Fatalf("ordinary shutdown before Ready: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("shutdown before Ready did not finish")
			}
			if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
				t.Fatal(err)
			}
		})
	}
}
