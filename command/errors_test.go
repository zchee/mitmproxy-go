// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command_test

import (
	"errors"
	"fmt"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/command"
)

func TestError(t *testing.T) {
	cause := errors.New("underlying failure")
	tests := map[string]struct {
		err  *command.Error
		want string
	}{
		"empty":             {&command.Error{}, ""},
		"message":           {&command.Error{Msg: "command failed"}, "command failed"},
		"cause":             {&command.Error{Err: cause}, "underlying failure"},
		"message and cause": {&command.Error{Msg: "command failed", Err: cause}, "command failed"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, tt.err.Error()); diff != "" {
				t.Fatal(diff)
			}
			if got := errors.Is(tt.err, cause); got != (tt.err.Err == cause) {
				t.Fatalf("errors.Is = %v", got)
			}
			wrapped := fmt.Errorf("calling command: %w", tt.err)
			if got, ok := errors.AsType[*command.Error](wrapped); !ok || got != tt.err {
				t.Fatalf("errors.AsType = %v, %v", got, ok)
			}
		})
	}
}
