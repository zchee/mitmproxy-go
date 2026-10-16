// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import yaml "go.yaml.in/yaml/v4"

// The loader preflights all documents with native events before composing any
// node. Both methods charge the same caller-owned budget before allocating.
type yamlCodec interface {
	Load(text string, budget *viewBudget) ([]*yaml.Node, error)
	Dump(node *yaml.Node, budget *viewBudget) (string, error)
}

// MsgPack conversion retains ordered mappings, nonstring keys and scalar types.
// It reserves logical entries before constructing nodes or allocating buffers.
type msgpackCodec interface {
	Decode(data []byte, budget *viewBudget) (*yaml.Node, error)
	Encode(node *yaml.Node, budget *viewBudget) ([]byte, error)
}
