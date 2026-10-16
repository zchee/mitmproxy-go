// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	yaml "go.yaml.in/yaml/v4"

	"github.com/zchee/mitmproxy-go/contentviews"
)

// codecProbe verifies delegation and shared accounting, not codec fidelity.
type codecProbe struct {
	budgets []*viewBudget
	cause   error
	node    *yaml.Node
	docs    []*yaml.Node
	text    string
	data    []byte
}

func (p *codecProbe) account(budget *viewBudget) error {
	p.budgets = append(p.budgets, budget)
	if p.cause != nil {
		return p.cause
	}
	return budget.reserveNodes(1, "adapter")
}

func (p *codecProbe) Decode(_ []byte, budget *viewBudget) (*yaml.Node, error) {
	return p.node, p.account(budget)
}

func (p *codecProbe) Encode(_ *yaml.Node, budget *viewBudget) ([]byte, error) {
	return p.data, p.account(budget)
}

func (p *codecProbe) Load(_ string, budget *viewBudget) ([]*yaml.Node, error) {
	return p.docs, p.account(budget)
}

func (p *codecProbe) Dump(_ *yaml.Node, budget *viewBudget) (string, error) {
	return p.text, p.account(budget)
}

func TestMsgPackAdapterWiring(t *testing.T) {
	tests := map[string]struct{ reencode bool }{
		"prettify": {},
		"reencode": {reencode: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			probe := &codecProbe{node: &yaml.Node{}, docs: []*yaml.Node{{}}, text: "rendered", data: []byte{1}}
			view := MsgPack{codec: probe, yaml: probe}
			if tt.reencode {
				got, err := view.Reencode("source", contentviews.Metadata{})
				if err != nil || !cmp.Equal(probe.data, got) {
					t.Fatalf("Reencode=%v, %v", got, err)
				}
			} else {
				got, err := view.Prettify([]byte{1}, contentviews.Metadata{})
				if err != nil || got != probe.text {
					t.Fatalf("Prettify=%q, %v", got, err)
				}
			}
			if len(probe.budgets) != 2 || probe.budgets[0] != probe.budgets[1] || probe.budgets[0].nodes != 2 {
				t.Fatal("codec stages did not retain one accumulating budget")
			}
		})
	}
}

func TestMsgPackAdapterErrors(t *testing.T) {
	cause := &LimitError{View: "MsgPack", Stage: "adapter", Bound: "nodes"}
	probe := &codecProbe{cause: cause}
	view := MsgPack{codec: probe, yaml: probe}
	if text, err := view.Prettify(nil, contentviews.Metadata{}); text != "" || !errors.Is(err, cause) {
		t.Fatalf("Prettify=%q, %v", text, err)
	}
	if data, err := view.Reencode("invalid", contentviews.Metadata{}); data != nil || !errors.Is(err, cause) || !strings.HasPrefix(err.Error(), "Invalid YAML") {
		t.Fatalf("Reencode=%x, %v", data, err)
	}
	tests := map[string]struct{ docs []*yaml.Node }{
		"none":     {},
		"multiple": {docs: []*yaml.Node{{}, {}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			codec := &codecProbe{docs: tt.docs}
			if _, err := (MsgPack{codec: codec, yaml: codec}).Reencode("", contentviews.Metadata{}); err == nil {
				t.Fatal("expected document count error")
			}
		})
	}
}

func TestMsgPackSelection(t *testing.T) {
	tests := map[string]struct{ priority float64 }{
		"application/msgpack":   {1},
		"application/x-msgpack": {1},
		"text/plain":            {0},
		"":                      {0},
	}
	view := MsgPack{}
	for mediaType, tt := range tests {
		t.Run(mediaType, func(t *testing.T) {
			if got := view.RenderPriority(nil, contentviews.Metadata{ContentType: mediaType}); got != tt.priority {
				t.Fatalf("priority=%v, want %v", got, tt.priority)
			}
		})
	}
	if view.Name() != "MsgPack" || view.SyntaxHighlight() != "yaml" {
		t.Fatal("incorrect MsgPack display metadata")
	}
	if _, err := view.Prettify(nil, contentviews.Metadata{}); err == nil {
		t.Fatal("unconfigured view must fail")
	}
}
