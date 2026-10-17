// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// limitedBudget returns the default per-call budget with some limits lowered,
// so refusals are reached with small inputs.
func limitedBudget(view string, change func(*viewLimits)) *viewBudget {
	budget := newViewBudget(view)
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
				budget := limitedBudget("MsgPack", tt.limits)
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
	t.Run("grpc", testGRPCLimits)

	t.Run("protobuf", func(t *testing.T) {
		prettify := func(data []byte) func(*viewBudget) error {
			return func(b *viewBudget) error { _, err := prettifyProtobuf(data, nil, b); return err }
		}
		reencode := func(text string) func(*viewBudget) error {
			return func(b *viewBudget) error { _, err := reencodeProtobuf(text, nil, b); return err }
		}
		nested := func(levels int) []byte {
			data := []byte{0x08, 0x01}
			for range levels {
				data = append([]byte{0x2a, byte(len(data))}, data...)
			}
			return data
		}
		tests := map[string]struct {
			run          func(*viewBudget) error
			limits       func(*viewLimits)
			spent        func(*viewBudget)
			stage        string
			resource     string
			materialized int64
		}{
			"input bytes": {
				run:      prettify(make([]byte, 9)),
				limits:   func(l *viewLimits) { l.InputBytes = 8 },
				stage:    "Protobuf wire",
				resource: "input bytes",
			},
			"wire fields": {
				run:          prettify([]byte{8, 1, 8, 2, 8, 3, 8, 4, 8, 5}),
				limits:       func(l *viewLimits) { l.Nodes = 3 },
				stage:        "Protobuf wire",
				resource:     "logical nodes",
				materialized: -1,
			},
			"nested message depth": {
				run:          prettify(nested(3)),
				limits:       func(l *viewLimits) { l.Depth = 2 },
				stage:        "Protobuf wire",
				resource:     "nesting depth",
				materialized: -1,
			},
			"group depth": {
				run:      prettify([]byte{0x0b, 0x0b, 0x0b, 0x0c, 0x0c, 0x0c}),
				limits:   func(l *viewLimits) { l.Depth = 2 },
				stage:    "Protobuf wire",
				resource: "nesting depth",
			},
			"binary text before encoding": {
				// Forty unreadable bytes fit as a wire field; their eighty
				// hexadecimal characters do not.
				run:          prettify(append([]byte{0x0a, 40}, bytes.Repeat([]byte{0xff}, 40)...)),
				limits:       func(l *viewLimits) { l.OutputBytes = 100 },
				stage:        "Protobuf YAML",
				resource:     "materialized bytes",
				materialized: 100,
			},
			"rendered output after earlier work": {
				// The comment-spacing writer checks the shared output counter
				// before buffering.
				run:          prettify(protobufRoundTrips["varint"].proto),
				limits:       func(*viewLimits) {},
				spent:        func(b *viewBudget) { b.output = b.limits.OutputBytes - 5 },
				stage:        "YAML comment spacing",
				resource:     "output bytes",
				materialized: -1,
			},
			"reencode logical nodes": {
				run:      reencode("1: 1\n2: 2\n3: 3\n4: 4\n"),
				limits:   func(l *viewLimits) { l.Nodes = 4 },
				stage:    "YAML preflight",
				resource: "logical nodes",
			},
			"reencode nesting depth": {
				run:      reencode("1: {1: {1: {1: 1}}}"),
				limits:   func(l *viewLimits) { l.Depth = 2 },
				stage:    "YAML preflight",
				resource: "nesting depth",
			},
			"reencode output after earlier work": {
				run:          reencode("1: 150"),
				limits:       func(*viewLimits) {},
				spent:        func(b *viewBudget) { b.output = b.limits.OutputBytes - 2 },
				stage:        "Protobuf encoding",
				resource:     "output bytes",
				materialized: -1,
			},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				budget := limitedBudget("Protobuf", tt.limits)
				if tt.spent != nil {
					tt.spent(budget)
				}
				err := tt.run(budget)
				limit, ok := errors.AsType[*LimitError](err)
				if !ok {
					t.Fatalf("error %v is not a *LimitError", err)
				}
				if diff := cmp.Diff([]string{"Protobuf", tt.stage, tt.resource}, []string{limit.View, limit.Stage, limit.Resource}); diff != "" {
					t.Fatalf("refusal (-want +got):\n%s", diff)
				}
				if tt.materialized >= 0 && budget.materialized > uint64(tt.materialized) {
					t.Fatalf("reserved %d materialized bytes before the refusal, want at most %d", budget.materialized, tt.materialized)
				}
			})
		}

		t.Run("declared length beyond input", func(t *testing.T) {
			// Field 1 announces 2^28 bytes of payload and carries one.
			budget := newViewBudget("Protobuf")
			if _, err := prettifyProtobuf([]byte{0x0a, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00}, nil, budget); err == nil {
				t.Fatal("truncated length-delimited field was accepted")
			}
			if budget.materialized != 0 {
				t.Fatalf("reserved %d materialized bytes for a truncated field", budget.materialized)
			}
		})

		t.Run("schema group depth", func(t *testing.T) {
			// A declared group is parsed through the same bounded group
			// walker; the refusal is not retried without the definition.
			path := filepath.Join(t.TempDir(), "groups.proto")
			const schema = "syntax = \"proto2\";\nmessage Outer {\n  optional group Item = 1 {\n    optional group Inner = 2 {\n      optional int32 id = 3;\n    }\n  }\n}\n"
			if err := os.WriteFile(path, []byte(schema), 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, err := loadProtobufSchema(t.Context(), []string{path}, schemaLimits{}, newViewBudget("Protobuf"))
			if err != nil {
				t.Fatal(err)
			}
			descriptor, err := loaded.messageDescriptor("", true)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte{0x0b, 0x13, 0x18, 0x01, 0x14, 0x0c}
			if _, err := prettifyProtobuf(data, descriptor, newViewBudget("Protobuf")); err != nil {
				t.Fatalf("rendering within the default limits: %v", err)
			}
			budget := limitedBudget("Protobuf", func(l *viewLimits) { l.Depth = 1 })
			_, err = prettifyProtobuf(data, descriptor, budget)
			limit, ok := errors.AsType[*LimitError](err)
			if !ok {
				t.Fatalf("error %v is not a *LimitError", err)
			}
			if diff := cmp.Diff([]string{"Protobuf", "Protobuf wire", "nesting depth"}, []string{limit.View, limit.Stage, limit.Resource}); diff != "" {
				t.Fatalf("refusal (-want +got):\n%s", diff)
			}
		})

		t.Run("fallback keeps spent work", func(t *testing.T) {
			schema, err := loadProtobufSchema(t.Context(), []string{protobufFixture("simple.proto")}, schemaLimits{}, newViewBudget("Protobuf"))
			if err != nil {
				t.Fatal(err)
			}
			descriptor, err := schema.messageDescriptor("", true)
			if err != nil {
				t.Fatal(err)
			}
			data := protobufRoundTrips["string"].proto
			schemaless := newViewBudget("Protobuf")
			if _, err := prettifyProtobuf(data, nil, schemaless); err != nil {
				t.Fatal(err)
			}
			retried := newViewBudget("Protobuf")
			text, err := prettifyProtobuf(data, descriptor, retried)
			if err != nil {
				t.Fatal(err)
			}
			if text != protobufRoundTrips["string"].yaml {
				t.Fatalf("fallback rendering = %q", text)
			}
			if retried.nodes <= schemaless.nodes {
				t.Fatalf("retry spent %d nodes, schema-less alone %d; the failed attempt was refunded", retried.nodes, schemaless.nodes)
			}
		})
	})
}
