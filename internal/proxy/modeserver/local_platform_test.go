// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addons/errorcheck"
	"github.com/zchee/mitmproxy-go/internal/local"
	"github.com/zchee/mitmproxy-go/master"
)

type platformRefusalRedirector struct {
	platform string
	launches int
	controls int
}

// Launch supplies the platform-specific backend refusal to the mode start.
func (r *platformRefusalRedirector) Launch(context.Context) error {
	r.launches++
	return errors.New(local.UnavailableReason(r.platform, 0))
}

// SetIntercept records any incorrect control after a refused launch.
func (r *platformRefusalRedirector) SetIntercept(context.Context, string) error {
	r.controls++
	return errors.New("interception must not be configured after platform refusal")
}

// ReadPacket rejects a pump started after a refused launch.
func (*platformRefusalRedirector) ReadPacket(context.Context) (*local.PacketWithMeta, error) {
	return nil, errors.New("packet pump must not start after platform refusal")
}

// WritePacket rejects a pump started after a refused launch.
func (*platformRefusalRedirector) WritePacket(context.Context, *local.Packet) error {
	return errors.New("packet pump must not start after platform refusal")
}

// Close has no native process to release after platform refusal.
func (*platformRefusalRedirector) Close() error { return nil }

type refusedModeSetup struct {
	instance *Instance
	logger   *slog.Logger
}

// Name binds this startup adapter to Master's real server-setup contract.
func (*refusedModeSetup) Name() string { return "proxyserver" }

// SetupServers uses the production mode start and logs refusal as proxyserver does.
func (s *refusedModeSetup) SetupServers(ctx context.Context) error {
	if err := s.instance.Start(ctx); err != nil {
		s.logger.Error(err.Error())
	}
	return nil
}

func TestLocalFreeBSDStartRefusal(t *testing.T) {
	tests := map[string]struct {
		platform string
		text     string
	}{
		"error: FreeBSD mode start refuses with startup exit one": {
			platform: "freebsd", text: "Local redirect mode is not supported on freebsd",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer
			collector := errorcheck.New(errorcheck.Config{Stderr: &stderr, RepeatErrorsOnStderr: true})
			cfg, m, _ := fixture(t)
			redirector := &platformRefusalRedirector{platform: tt.platform}
			cfg.LocalRedirector = redirector
			cfg.Logger = slog.New(collector.LogHandler())
			instance := makeInstance(t, "local", cfg)
			if err := m.Addons.Add(t.Context(), collector, &refusedModeSetup{instance: instance, logger: cfg.Logger}); err != nil {
				t.Fatal(err)
			}
			err := m.Run(t.Context())
			var exit *master.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("master/errorcheck startup result = %v, want exit 1", err)
			}
			if instance.LastError() == nil {
				t.Fatal("FreeBSD local mode start did not record refusal")
			}
			if diff := gocmp.Diff(tt.text, instance.LastError().Error()); diff != "" {
				t.Fatalf("platform start refusal (-want +got):\n%s", diff)
			}
			if instance.IsRunning() || redirector.launches != 1 || redirector.controls != 0 {
				t.Fatalf("refused startup state: running=%v error=%v launch=%d control=%d", instance.IsRunning(), instance.LastError(), redirector.launches, redirector.controls)
			}
			if diff := gocmp.Diff("Error logged during startup:\n"+tt.text+"\n", stderr.String()); diff != "" {
				t.Fatalf("errorcheck exact log (-want +got):\n%s", diff)
			}
		})
	}
}
