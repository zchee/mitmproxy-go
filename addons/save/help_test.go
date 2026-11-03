// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package save

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestSaveHelp(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct {
			want string
		}{
			"save_stream_file": {"Stream flows to file as they arrive. Prefix path with + to append. The full path can use python strftime() formatting, missing directories are created as needed. A new file is opened every time the formatted string changes."},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				_, manager := setup(t, nil)
				option, ok := manager.Options().Lookup(name)
				if !ok {
					t.Fatalf("real save loader did not register %s", name)
				}
				if diff := gocmp.Diff(tt.want, option.Help()); diff != "" {
					t.Fatalf("registered option help (-want +got):\n%s", diff)
				}
			})
		}
	})
}
