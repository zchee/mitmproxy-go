// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package readfile

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
)

func TestCancelledRunningDoesNotStartLoader(t *testing.T) {
	tests := map[string]struct {
		sync bool
	}{
		"error: cancelled ordinary hook":    {},
		"error: cancelled synchronous hook": {sync: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reader.Close(); _ = writer.Close() }()
			m, r, _ := newReader(t, reader)
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				return m.Options.Update(ctx, map[string]any{"rfile": new("-")})
			}); err != nil {
				t.Fatal(err)
			}
			err = m.Do(t.Context(), func(ctx context.Context) error {
				ctx, cancel := context.WithCancel(ctx)
				cancel()
				var err error
				if tt.sync {
					err = m.Addons.InvokeSync(ctx, r, addon.RunningHook{})
				} else {
					err = r.Running(ctx)
				}
				if r.cancel != nil || r.done != nil || r.closer != nil {
					t.Error("cancelled running hook started a loader")
				}
				return err
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Running = %v, want context.Canceled", err)
			}
		})
	}
}
