// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// limitedBudget returns the default per-call budget with some limits lowered,
// so refusals are reached with small inputs.
func limitedBudget(change func(*viewLimits)) *viewBudget {
	budget := newViewBudget("MsgPack")
	change(&budget.limits)
	return budget
}

// TestContentviewLimits checks that each decoder refuses work beyond its
// budget before allocating for it, and that one budget spans every stage of a
// call.
func TestContentviewLimits(t *testing.T) {
	t.Run("msgpack", func(t *testing.T) {
		tests := map[string]struct {
			run      func(*viewBudget) error
			limits   func(*viewLimits)
			stage    string
			resource string
			// materialized bounds the bytes reserved before the refusal; a
			// negative value leaves the counter unchecked.
			materialized int64
		}{
			"input bytes": {
				run:      func(b *viewBudget) error { _, err := prettifyMsgpack(make([]byte, 9), b); return err },
				limits:   func(l *viewLimits) { l.InputBytes = 8 },
				stage:    "MsgPack decoding",
				resource: "input bytes",
			},
			"logical nodes": {
				run:      func(b *viewBudget) error { _, err := prettifyMsgpack([]byte{0x95, 1, 2, 3, 4, 5}, b); return err },
				limits:   func(l *viewLimits) { l.Nodes = 4 },
				stage:    "MsgPack decoding",
				resource: "logical nodes",
			},
			"declared count beyond node budget": {
				// An array32 header announcing 2^32-1 elements.
				run: func(b *viewBudget) error {
					_, err := prettifyMsgpack([]byte{0xdd, 0xff, 0xff, 0xff, 0xff, 1}, b)
					return err
				},
				limits:   func(*viewLimits) {},
				stage:    "MsgPack decoding",
				resource: "logical nodes",
			},
			"nesting depth": {
				run:          func(b *viewBudget) error { _, err := prettifyMsgpack([]byte{0x91, 0x91, 0x91, 0x01}, b); return err },
				limits:       func(l *viewLimits) { l.Depth = 2 },
				stage:        "MsgPack decoding",
				resource:     "nesting depth",
				materialized: -1,
			},
			"string materialization": {
				run: func(b *viewBudget) error {
					_, err := prettifyMsgpack(append([]byte{0xb0}, bytes.Repeat([]byte{'a'}, 16)...), b)
					return err
				},
				limits:       func(l *viewLimits) { l.OutputBytes = 15 },
				stage:        "MsgPack decoding",
				resource:     "materialized bytes",
				materialized: 0,
			},
			"binary text before encoding": {
				// Ten bytes fit the decoder; their sixteen base64 characters do not.
				run: func(b *viewBudget) error {
					_, err := prettifyMsgpack(append([]byte{0xc4, 10}, make([]byte, 10)...), b)
					return err
				},
				limits:       func(l *viewLimits) { l.OutputBytes = 20 },
				stage:        "MsgPack YAML",
				resource:     "materialized bytes",
				materialized: 10,
			},
			"rendered output": {
				// A hundred control bytes are reserved twice but render as
				// four escaped bytes each.
				run: func(b *viewBudget) error {
					_, err := prettifyMsgpack(append([]byte{0xd9, 100}, bytes.Repeat([]byte{1}, 100)...), b)
					return err
				},
				limits:       func(l *viewLimits) { l.OutputBytes = 300 },
				stage:        "YAML output",
				resource:     "output bytes",
				materialized: 200,
			},
			"reencode input bytes": {
				run:      func(b *viewBudget) error { _, err := reencodeMsgpack("[1, 2]", b); return err },
				limits:   func(l *viewLimits) { l.InputBytes = 5 },
				stage:    "YAML snapshot",
				resource: "input bytes",
			},
			"reencode logical nodes": {
				run:      func(b *viewBudget) error { _, err := reencodeMsgpack("[1, 2, 3, 4, 5]", b); return err },
				limits:   func(l *viewLimits) { l.Nodes = 4 },
				stage:    "YAML preflight",
				resource: "logical nodes",
			},
			"reencode alias fan-out": {
				// Every alias costs the anchored subtree again.
				run: func(b *viewBudget) error {
					_, err := reencodeMsgpack("a: &x [1, 2, 3, 4]\nb: [*x, *x, *x, *x, *x]\n", b)
					return err
				},
				limits:       func(l *viewLimits) { l.Nodes = 20 },
				stage:        "YAML preflight",
				resource:     "logical nodes",
				materialized: 1,
			},
			"reencode nesting depth": {
				run:      func(b *viewBudget) error { _, err := reencodeMsgpack("[[[1]]]", b); return err },
				limits:   func(l *viewLimits) { l.Depth = 2 },
				stage:    "YAML preflight",
				resource: "nesting depth",
			},
			"reencode sequence materialization": {
				run:      func(b *viewBudget) error { _, err := reencodeMsgpack("[1000, 2000, 3000, 4000, 5000]", b); return err },
				limits:   func(l *viewLimits) { l.OutputBytes = 10 },
				stage:    "MsgPack YAML",
				resource: "materialized bytes",
			},
			"reencode output": {
				// One integer that encodes as three bytes.
				run:      func(b *viewBudget) error { _, err := reencodeMsgpack("1000", b); return err },
				limits:   func(l *viewLimits) { l.OutputBytes = 2 },
				stage:    "MsgPack encoding",
				resource: "output bytes",
			},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				budget := limitedBudget(tt.limits)
				err := tt.run(budget)
				limit, ok := errors.AsType[*LimitError](err)
				if !ok {
					t.Fatalf("error %v is not a *LimitError", err)
				}
				got := []string{limit.View, limit.Stage, limit.Resource}
				if diff := cmp.Diff([]string{"MsgPack", tt.stage, tt.resource}, got); diff != "" {
					t.Fatalf("refusal (-want +got):\n%s", diff)
				}
				if limit.Attempted <= limit.Limit {
					t.Fatalf("refusal %+v does not exceed its limit", limit)
				}
				if tt.materialized >= 0 && budget.materialized > uint64(tt.materialized) {
					t.Fatalf("reserved %d materialized bytes before the refusal, want at most %d", budget.materialized, tt.materialized)
				}
				if strings.Contains(err.Error(), "aaaa") {
					t.Fatalf("diagnostic %q includes input content", err)
				}
			})
		}

		t.Run("one budget spans every stage", func(t *testing.T) {
			budget := newViewBudget("MsgPack")
			text, err := prettifyMsgpack(testMsgPack, budget)
			if err != nil {
				t.Fatal(err)
			}
			// Nine values, counted by the decoder, the YAML conversion and the
			// emitter; the output counter holds exactly the rendered text.
			got := []uint64{budget.nodes, budget.output}
			if diff := cmp.Diff([]uint64{27, uint64(len(text))}, got); diff != "" {
				t.Fatalf("prettify counters [nodes output] (-want +got):\n%s", diff)
			}
			budget = newViewBudget("MsgPack")
			data, err := reencodeMsgpack(text, budget)
			if err != nil {
				t.Fatal(err)
			}
			// Preflight counts the document and nine values, the conversion
			// the same, and the encoder the nine values.
			got = []uint64{budget.nodes, budget.output}
			if diff := cmp.Diff([]uint64{29, uint64(len(data))}, got); diff != "" {
				t.Fatalf("reencode counters [nodes output] (-want +got):\n%s", diff)
			}
		})

		t.Run("deepest value round trips", func(t *testing.T) {
			depth := newViewBudget("MsgPack").limits.Depth
			input := append(bytes.Repeat([]byte{0x91}, depth), 0x01)
			text, err := MsgPack{}.Prettify(input, Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			data, err := MsgPack{}.Reencode(text, Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(input, data) {
				t.Fatalf("round trip = %x, want %x", data, input)
			}
			_, err = MsgPack{}.Prettify(append([]byte{0x91}, input...), Metadata{})
			if _, ok := errors.AsType[*LimitError](err); !ok {
				t.Fatalf("one level deeper than the limit: %v, want a *LimitError", err)
			}
		})
	})
}
