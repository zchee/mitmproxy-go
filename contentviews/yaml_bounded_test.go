// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	yaml "go.yaml.in/yaml/v4"
)

func TestBoundedYAMLPreflight(t *testing.T) {
	tests := map[string]struct {
		input string
		nodes uint64
		depth int
		fail  string
	}{
		"empty stream":              {input: "", depth: 64},
		"scalar":                    {input: "one", nodes: 2, depth: 64},
		"mapping keys and values":   {input: "{a: b}", nodes: 4, depth: 64},
		"empty scalars":             {input: "{a:}", nodes: 4, depth: 64},
		"multiple documents":        {input: "--- one\n--- two\n", nodes: 4, depth: 64},
		"alias work":                {input: "[&a [one], *a]", nodes: 7, depth: 64},
		"anchor overwrite":          {input: "[&a one, &a two, *a]", nodes: 6, depth: 64},
		"cycle":                     {input: "[&a [*a]]", depth: 64, fail: "cyclic alias"},
		"forward alias":             {input: "[*missing]", depth: 64, fail: "undefined alias"},
		"document anchor isolation": {input: "--- &a one\n--- *a\n", depth: 64, fail: "undefined alias"},
		"native depth boundary":     {input: strings.Repeat("[", 64) + "x" + strings.Repeat("]", 64), nodes: 66, depth: 64},
		"native depth refusal":      {input: strings.Repeat("[", 65) + "x" + strings.Repeat("]", 65), depth: 64, fail: "nesting depth"},
		"expanded alias depth":      {input: "a: &a [[[x]]]\nb: [[[*a]]]\n", depth: 6, fail: "nesting depth"},
		"malformed":                 {input: "[one,", depth: 64, fail: "load error"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			budget := newViewBudget("test")
			budget.limits.Depth = tt.depth
			err := preflightYAML([]byte(tt.input), budget)
			if tt.fail != "" {
				if err == nil || !strings.Contains(err.Error(), tt.fail) {
					t.Fatalf("preflight error = %v; want %q", err, tt.fail)
				}
				if tt.fail == "nesting depth" {
					if limitError, ok := errors.AsType[*LimitError](err); !ok || limitError.Resource != "nesting depth" {
						t.Fatalf("depth refusal lost typed limit error: %v", err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.nodes, budget.nodes); diff != "" {
				t.Fatalf("logical work mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBoundedYAMLZeroComposition(t *testing.T) {
	tests := map[string]struct {
		input string
		limit uint64
	}{
		"broad shallow million children": {input: strings.Repeat("- x\n", 1_000_001), limit: 1_000_000},
		"mapping over boundary":          {input: "{a: b}", limit: 3},
		"alias fanout over boundary":     {input: "[&a [x, x, x], *a, *a]", limit: 10},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			budget := newViewBudget("test")
			budget.limits.Nodes = tt.limit
			created := 0
			documents, err := parseBoundedYAMLWithLoader([]byte(tt.input), budget, func(r io.Reader, opts ...yaml.Option) (*yaml.Loader, error) {
				created++
				return yaml.NewLoader(r, opts...)
			})
			if _, ok := errors.AsType[*LimitError](err); !ok {
				t.Fatalf("want pre-composition typed limit, got %v", err)
			}
			if created != 0 || documents != nil {
				t.Fatalf("preflight rejection constructed %d loaders and returned %d documents", created, len(documents))
			}
			t.Logf("input bytes=%d; logical work=%d; loaders constructed=%d; composed nodes=0", len(tt.input), budget.nodes, created)
		})
	}
}

func TestBoundedYAMLComposition(t *testing.T) {
	tests := map[string]struct {
		input string
		count int
	}{
		"empty":        {input: ""},
		"single":       {input: "{a: [b, c]}", count: 1},
		"multiple":     {input: "--- a\n--- b\n", count: 2},
		"anchor alias": {input: "[&a one, *a]", count: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			input := []byte(tt.input)
			before := bytes.Clone(input)
			documents, err := parseBoundedYAML(input, newViewBudget("test"))
			if err != nil || len(documents) != tt.count {
				t.Fatalf("parse: documents=%d, error=%v; want %d documents", len(documents), err, tt.count)
			}
			if diff := gocmp.Diff(before, input); diff != "" {
				t.Fatalf("input changed: %s", diff)
			}
		})
	}
}

func TestBoundedYAMLAggregate(t *testing.T) {
	tests := map[string]struct {
		first, second string
		limit         uint64
	}{
		"documents share work":      {first: "a", second: "b", limit: 3},
		"frame attempts share work": {first: "[a]", second: "b", limit: 4},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			budget := newViewBudget("grpc")
			budget.limits.Nodes = tt.limit
			if _, err := parseBoundedYAML([]byte(tt.first), budget); err != nil {
				t.Fatal(err)
			}
			spent := budget.nodes
			if _, err := parseBoundedYAML([]byte(tt.second), budget); err == nil {
				t.Fatal("second parse reset the aggregate work budget")
			}
			if budget.nodes < spent {
				t.Fatal("failed attempt refunded consumed work")
			}
		})
	}
}

func TestViewBudgetReservations(t *testing.T) {
	tests := map[string]struct {
		operation func(*viewBudget) error
		resource  string
	}{
		"input":           {operation: func(b *viewBudget) error { return b.checkInput("input", 5) }, resource: "input bytes"},
		"nodes":           {operation: func(b *viewBudget) error { return b.chargeNodes("nodes", 5) }, resource: "logical nodes"},
		"output":          {operation: func(b *viewBudget) error { return b.chargeOutput("output", 5) }, resource: "output bytes"},
		"decompressed":    {operation: func(b *viewBudget) error { return b.chargeDecompressed("frame", 5) }, resource: "decompressed bytes"},
		"materialization": {operation: func(b *viewBudget) error { return b.chargeMaterialization("hex", 5) }, resource: "materialized bytes"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			budget := newViewBudget("test")
			budget.limits = viewLimits{InputBytes: 4, OutputBytes: 4, DecompressedBytes: 4, Nodes: 4, Depth: 4}
			err := tt.operation(budget)
			limitError, ok := errors.AsType[*LimitError](err)
			if !ok || limitError.Resource != tt.resource || limitError.Limit != 4 || limitError.Attempted != 5 {
				t.Fatalf("wrong limit refusal: %#v", err)
			}
		})
	}
	t.Run("output check does not double charge", func(t *testing.T) {
		budget := newViewBudget("test")
		budget.limits.OutputBytes = 4
		if err := budget.checkOutput("size", 4); err != nil {
			t.Fatal(err)
		}
		if err := budget.chargeMaterialization("allocation", 4); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if _, err := newBoundedViewWriter(&out, budget).Write([]byte("1234")); err != nil {
			t.Fatal(err)
		}
		if budget.output != 4 || budget.materialized != 4 {
			t.Fatalf("output=%d materialized=%d", budget.output, budget.materialized)
		}
	})
	t.Run("checked addition overflow", func(t *testing.T) {
		budget := newViewBudget("test")
		budget.limits.Nodes, budget.nodes = math.MaxUint64, 1
		if err := budget.chargeNodes("overflow", math.MaxUint64); err == nil {
			t.Fatal("overflow was accepted")
		}
		if budget.nodes != 1 {
			t.Fatal("overflow mutated spent counter")
		}
	})
}

func TestBoundedYAMLWriter(t *testing.T) {
	budget := newViewBudget("test")
	budget.limits.OutputBytes = 3
	var output bytes.Buffer
	writer := newBoundedViewWriter(&output, budget)
	if _, err := writer.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	if n, err := writer.Write([]byte("cd")); n != 0 || err == nil {
		t.Fatalf("overflow write = %d, %v", n, err)
	}
	if output.String() != "ab" || budget.output != 2 {
		t.Fatalf("overflow reached writer: %q, spent=%d", output.String(), budget.output)
	}
	reader, pipe := io.Pipe()
	t.Cleanup(func() { _ = pipe.Close(); _ = reader.Close() })
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := newBoundedViewWriter(pipe, newViewBudget("test")).Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("lost writer cause: %v", err)
	}
}

func TestBoundedYAMLEmission(t *testing.T) {
	tests := map[string]struct {
		value, comment string
		style          yaml.Style
		want           string
	}{
		"inline gap":          {value: "1", comment: "# integer", want: "field: 1  # integer\n"},
		"hash inside string":  {value: "x # y", comment: "# text", want: "field: 'x # y'  # text\n"},
		"multiline comment":   {value: "1", comment: "# first\n# second", want: "field: 1  # first\n\n# second\n"},
		"block scalar hashes": {value: "# payload\nstill # payload\n", style: yaml.LiteralStyle, want: "field: |\n  # payload\n  still # payload\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			value := &yaml.Node{Kind: yaml.ScalarNode, Value: tt.value, Style: tt.style, LineComment: tt.comment}
			if name == "inline gap" || name == "multiline comment" {
				value.Tag = "!!int"
			} else {
				value.Tag = "!!str"
			}
			node := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "field"}, value}}
			before := *value
			got, err := dumpBoundedYAML(node, newViewBudget("test"), yamlEmitOptions{InlineCommentGap: 2})
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("emission mismatch (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(before, *value); diff != "" {
				t.Fatalf("node mutation: %s", diff)
			}
			if strings.ContainsRune(got, 0) {
				t.Fatal("private comment marker escaped output")
			}
		})
	}
}

func TestBoundedYAMLEmissionLimits(t *testing.T) {
	tests := map[string]struct {
		value string
		limit uint64
		want  string
	}{
		"exact output boundary":    {value: "x", limit: 2, want: "x\n"},
		"escaping expands":         {value: strings.Repeat("\x01", 8), limit: 16},
		"scalar before allocation": {value: "123456789", limit: 8},
		"comments count":           {value: "x", limit: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			budget := newViewBudget("test")
			budget.limits.OutputBytes = tt.limit
			got, err := dumpBoundedYAML(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: tt.value}, budget, yamlEmitOptions{})
			if tt.want != "" {
				if err != nil || got != tt.want || budget.output != uint64(len(tt.want)) {
					t.Fatalf("exact boundary: output=%q spent=%d error=%v", got, budget.output, err)
				}
			} else if _, ok := errors.AsType[*LimitError](err); !ok || got != "" {
				t.Fatalf("partial output=%q, error=%v", got, err)
			}
			if budget.output > tt.limit {
				t.Fatalf("writer exceeded output bound: %d", budget.output)
			}
		})
	}
	t.Run("node graph cycle", func(t *testing.T) {
		node := &yaml.Node{Kind: yaml.SequenceNode}
		node.Content = []*yaml.Node{node}
		if _, err := dumpBoundedYAML(node, newViewBudget("test"), yamlEmitOptions{}); err == nil {
			t.Fatal("cyclic node graph accepted")
		}
	})
}
