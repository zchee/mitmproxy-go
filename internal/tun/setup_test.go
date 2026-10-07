// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tun

import (
	"errors"
	"syscall"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDeviceSetup(t *testing.T) {
	tests := map[string]struct {
		name           string
		attachErr      error
		configureErr   error
		wantCalls      []string
		wantConfigured bool
		wantErr        error
	}{
		"success: created": {wantCalls: []string{"open", "attach", "configure"}, wantConfigured: true},
		"success: persistent attach after configure permission denial":      {name: "tun0", configureErr: syscall.EPERM, wantCalls: []string{"open", "attach", "configure", "close", "open", "attach"}},
		"success: persistent attach after initial attach permission denial": {name: "tun0", attachErr: syscall.EPERM, wantCalls: []string{"open", "attach", "close", "open", "attach"}},
		"error: unnamed permission denial":                                  {configureErr: syscall.EPERM, wantErr: syscall.EPERM, wantCalls: []string{"open", "attach", "configure", "close"}},
		"error: other attach failure":                                       {name: "tun0", attachErr: syscall.EINVAL, wantErr: syscall.EINVAL, wantCalls: []string{"open", "attach", "close"}},
		"error: other configuration failure":                                {name: "tun0", configureErr: syscall.EIO, wantErr: syscall.EIO, wantCalls: []string{"open", "attach", "configure", "close"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var calls []string
			var opened int
			ops := setupOps{
				open:  func() (int, error) { calls = append(calls, "open"); opened++; return opened, nil },
				close: func(int) error { calls = append(calls, "close"); return nil },
				attach: func(fd int, requested string) (string, error) {
					calls = append(calls, "attach")
					if requested != tt.name {
						t.Fatalf("requested name = %q, want %q", requested, tt.name)
					}
					if fd == 1 && tt.attachErr != nil {
						return "", tt.attachErr
					}
					return "tun0", nil
				},
				configure: func(actual string) error {
					calls = append(calls, "configure")
					if actual != "tun0" {
						t.Fatalf("actual name = %q", actual)
					}
					return tt.configureErr
				},
			}
			fd, actual, configured, err := setupDevice(tt.name, ops)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("setup error = %v, want %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.wantCalls, calls); diff != "" {
				t.Fatalf("setup operations (-want +got):\n%s", diff)
			}
			if configured != tt.wantConfigured {
				t.Errorf("configured = %v, want %v", configured, tt.wantConfigured)
			}
			if err == nil && (fd != opened || actual != "tun0") {
				t.Errorf("setup returned fd %d name %q, want fd %d tun0", fd, actual, opened)
			}
		})
	}
}

func TestDeviceSetupOpenAndFallbackFailures(t *testing.T) {
	tests := map[string]struct {
		firstOpenErr    error
		secondOpenErr   error
		secondAttachErr error
		wantCloses      int
	}{
		"error: open does not retry": {firstOpenErr: syscall.EPERM},
		"error: fallback open":       {secondOpenErr: syscall.EIO, wantCloses: 1},
		"error: fallback attach":     {secondAttachErr: syscall.EPERM, wantCloses: 2},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var opens, closes int
			ops := setupOps{
				open: func() (int, error) {
					opens++
					if opens == 1 {
						return opens, tt.firstOpenErr
					}
					return opens, tt.secondOpenErr
				},
				close: func(int) error { closes++; return nil },
				attach: func(fd int, _ string) (string, error) {
					if fd == 2 {
						return "", tt.secondAttachErr
					}
					return "tun0", nil
				},
				configure: func(string) error { return syscall.EPERM },
			}
			_, _, _, err := setupDevice("tun0", ops)
			if err == nil {
				t.Fatal("expected setup failure")
			}
			if closes != tt.wantCloses {
				t.Errorf("closed %d descriptors, want %d", closes, tt.wantCloses)
			}
		})
	}
}
