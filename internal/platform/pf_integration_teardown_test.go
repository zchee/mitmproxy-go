// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build integration && darwin

package platform

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestOwnedAnchorTeardown(t *testing.T) {
	const anchor = "com.apple/mitmproxy-go-test"
	commandErr := errors.New("pfctl command failed")
	tests := map[string]struct {
		natOutput    string
		filterOutput string
		failCall     int
		wantError    string
	}{
		"success: nat then rules flushed and read-back empty": {},
		"success: diagnostic output without rules": {
			natOutput:    "No ALTQ support in kernel\nALTQ related functions disabled\n",
			filterOutput: "\n",
		},
		"error: rdr rule survives the flush": {
			natOutput: "rdr pass on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.2 port 1234 -> 127.0.0.1 port 5678\n",
			wantError: "rdr pass on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.2 port 1234 -> 127.0.0.1 port 5678",
		},
		"error: nat rule survives the flush": {
			natOutput: "nat on lo0 from 127.0.0.1 to any -> 127.0.0.2\n",
			wantError: "nat on lo0 from 127.0.0.1 to any -> 127.0.0.2",
		},
		"error: flush command fails": {
			failCall:  1,
			wantError: commandErr.Error(),
		},
		"error: filter flush command fails": {
			failCall:  2,
			wantError: commandErr.Error(),
		},
		"error: nat read-back fails": {
			failCall:  3,
			wantError: commandErr.Error(),
		},
		"error: filter read-back fails": {
			failCall:  4,
			wantError: commandErr.Error(),
		},
		"error: filter rule survives": {
			filterOutput: "pass in on lo0 all\n",
			wantError:    "pass in on lo0 all",
		},
		"error: block rule survives": {
			filterOutput: "block drop in all\n",
			wantError:    "block drop in all",
		},
		"error: match rule survives": {
			filterOutput: "match out on lo0 all\n",
			wantError:    "match out on lo0 all",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var calls [][]string
			pfctl := func(ctx context.Context, input string, args ...string) (string, error) {
				if ctx != t.Context() {
					t.Error("pfctl did not receive the caller context")
				}
				if input != "" {
					t.Errorf("pfctl input = %q, want empty", input)
				}
				calls = append(calls, slices.Clone(args))
				if len(calls) == tt.failCall {
					return "command diagnostic", commandErr
				}
				switch args[len(args)-1] {
				case "-sn":
					return tt.natOutput, nil
				case "-sr":
					return tt.filterOutput, nil
				default:
					return "", nil
				}
			}
			err := teardownOwnedAnchor(t.Context(), pfctl, anchor)
			wantCalls := [][]string{
				{"-a", anchor, "-F", "nat"},
				{"-a", anchor, "-F", "rules"},
				{"-a", anchor, "-sn"},
				{"-a", anchor, "-sr"},
			}
			if diff := cmp.Diff(wantCalls, calls); diff != "" {
				t.Errorf("pfctl calls (-want +got):\n%s", diff)
			}
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("teardown: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("teardown error = %v, want containing %q", err, tt.wantError)
			}
			if tt.failCall != 0 {
				if !errors.Is(err, commandErr) {
					t.Errorf("teardown error = %v, want wrapped %v", err, commandErr)
				}
				if !strings.Contains(err.Error(), "command diagnostic") {
					t.Errorf("teardown error lost command output: %v", err)
				}
			}
		})
	}
}
