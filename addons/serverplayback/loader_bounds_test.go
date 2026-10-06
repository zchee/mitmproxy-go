// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package serverplayback

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flowio/har"
)

func TestReplayLoaderHARBound(t *testing.T) {
	tests := map[string]struct {
		entries int
		wantErr string
	}{
		"error: exact entry bound reaches entry validation": {entries: har.MaxEntries, wantErr: "HAR entry is missing timing, request or response"},
		"error: excess entries rejected before conversion":  {entries: har.MaxEntries + 1, wantErr: "HAR exceeds entry-count limit"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, s := setup(t)
			path := filepath.Join(t.TempDir(), "flows.har")
			input := `{"log":{"entries":[` + strings.Repeat("{},", tt.entries-1) + `{}]}}`
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				flows, err := s.readFiles(ctx, []string{path})
				if err == nil || flows != nil {
					t.Fatalf("readFiles = %d flows, error %v; want no flows and %q", len(flows), err, tt.wantErr)
				}
				wrapped, ok := errors.AsType[interface {
					error
					Unwrap() error
				}](err)
				if !ok {
					t.Fatalf("readFiles error %v has no HAR cause", err)
				}
				if diff := cmp.Diff(tt.wantErr, wrapped.Unwrap().Error()); diff != "" {
					t.Fatal(diff)
				}
				if diff := cmp.Diff(0, s.count(ctx)); diff != "" {
					t.Fatal(diff)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
