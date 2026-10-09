// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

func TestLocalModeAdmission(t *testing.T) {
	tests := map[string]struct{}{"local": {}, "local:curl,!123": {}}
	for spec := range tests {
		t.Run(spec, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			cfg.ListenPort = new(-1)
			mode, err := modespec.Parse(spec)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := New(mode, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if instance.IsRunning() || len(instance.ListenAddrs()) != 0 {
				t.Fatal("validation started a redirector")
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := instance.Start(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled local startup = %v", err)
			}
			if instance.IsRunning() || instance.LastError() == nil {
				t.Fatal("canceled local frontend state")
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLocalModeMissingOwner(t *testing.T) {
	tests := map[string]struct{}{"process owner is required": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t)
			mode, err := modespec.Parse("local")
			if err != nil {
				t.Fatal(err)
			}
			instance, err := New(mode, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := instance.Start(t.Context()); err == nil || err.Error() != "modeserver: local mode requires a process-owned redirector" {
				t.Fatalf("Start without owner = %v", err)
			}
			if instance.IsRunning() || instance.LastError() == nil {
				t.Fatal("owner error retained a frontend reservation")
			}
			if err := instance.Stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
