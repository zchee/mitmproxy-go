// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package stateutil

import (
	"regexp"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

// TestNoneVersusEmpty checks the distinction the helpers exist for: a nil
// pointer or slice becomes None (an untyped nil) where the attribute is
// optional, and an empty value where it is not.
func TestNoneVersusEmpty(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		got  any
		want any
	}{
		"success: Opt of nil is None": {
			got:  Opt[string](nil),
			want: nil,
		},
		"success: Opt dereferences": {
			got:  Opt(new(1.5)),
			want: 1.5,
		},
		"success: OptBytes of nil is None": {
			got:  OptBytes(nil),
			want: nil,
		},
		"success: OptBytes keeps empty bytes": {
			got:  OptBytes([]byte{}),
			want: []byte{},
		},
		"success: Bytes of nil is empty bytes": {
			got:  Bytes(nil),
			want: []byte{},
		},
		"success: BytesList of nil is an empty list": {
			got:  BytesList(nil),
			want: []any{},
		},
		"success: BytesList elements are never nil": {
			got:  BytesList([][]byte{nil, []byte("h2")}),
			want: []any{[]byte{}, []byte("h2")},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// gocmp tells a nil slice from an empty one, and an untyped
			// nil from a typed nil inside an interface.
			if diff := gocmp.Diff(tt.want, tt.got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNow(t *testing.T) {
	t.Parallel()

	before := float64(time.Now().Unix())
	got := Now()
	after := float64(time.Now().Unix() + 1)
	if got < before || got > after {
		t.Errorf("Now() = %f, want between %f and %f", got, before, after)
	}
}

func TestNewID(t *testing.T) {
	t.Parallel()

	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for range 100 {
		id := NewID()
		if !re.MatchString(id) {
			t.Fatalf("NewID() = %q, not a version 4 UUID", id)
		}
		if seen[id] {
			t.Fatalf("NewID() repeated %q", id)
		}
		seen[id] = true
	}
}
