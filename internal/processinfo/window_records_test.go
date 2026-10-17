// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package processinfo

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestProcessWindowPIDs(t *testing.T) {
	cause := errors.New("unreadable owner")
	tests := map[string]struct {
		count   int64
		owners  []int32
		readErr error
		want    map[int32]struct{}
		visits  []int64
		wantErr bool
	}{
		"zero":     {want: map[int32]struct{}{}},
		"one":      {count: 1, owners: []int32{7}, want: map[int32]struct{}{7: {}}, visits: []int64{0}},
		"many":     {count: 4, owners: []int32{2, 0, 2, 9}, want: map[int32]struct{}{2: {}, 9: {}}, visits: []int64{0, 1, 2, 3}},
		"negative": {count: -1, wantErr: true},
		"failure":  {count: 1, readErr: cause, wantErr: true, visits: []int64{0}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var visits []int64
			got, err := readWindowPIDs(test.count, func(index int64) (int32, error) {
				visits = append(visits, index)
				if test.readErr != nil {
					return 0, test.readErr
				}
				return test.owners[index], nil
			})
			if (err != nil) != test.wantErr {
				t.Fatalf("readWindowPIDs error = %v, want error %t", err, test.wantErr)
			}
			if test.readErr != nil && !errors.Is(err, test.readErr) {
				t.Fatalf("lost native cause: %v", err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("window owners (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.visits, visits); diff != "" {
				t.Fatalf("visited indices (-want +got):\n%s", diff)
			}
		})
	}
}
