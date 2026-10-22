// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"errors"
	"fmt"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// concurrentValue is callable only so direct calls have a stable diagnostic.
// The hook adapter, not Starlark Call, selects the frozen counterpart.
type concurrentValue struct{ function *starlark.Function }

func (v *concurrentValue) String() string      { return "concurrent(" + v.function.Name() + ")" }
func (*concurrentValue) Type() string          { return "concurrent" }
func (v *concurrentValue) Name() string        { return v.String() }
func (v *concurrentValue) Freeze()             { v.function.Freeze() }
func (*concurrentValue) Truth() starlark.Bool  { return true }
func (*concurrentValue) Hash() (uint32, error) { return 0, errors.New("unhashable: concurrent") }
func (v *concurrentValue) CallInternal(*starlark.Thread, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return nil, fmt.Errorf("%s cannot be called directly; it runs only when invoked as a hook", v)
}

func concurrentBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var fn *starlark.Function
	if err := starlark.UnpackArgs("concurrent", args, kwargs, "fn", &fn); err != nil {
		return nil, err
	}
	return &concurrentValue{function: fn}, nil
}

func concurrentEligible(name string) bool {
	switch name {
	case "requestheaders", "request", "responseheaders", "response", "error",
		"http_connect", "http_connect_upstream", "http_connected", "http_connect_error",
		"websocket_start", "websocket_message", "websocket_end",
		"tcp_start", "tcp_message", "tcp_end", "tcp_error",
		"udp_start", "udp_message", "udp_end", "udp_error",
		"dns_request", "dns_response", "dns_error":
		return true
	default:
		return false
	}
}

// A node's children are indexed by addons position; the separate name and module
// identity prevent ambiguous string paths or silently remapping changed trees.
type concurrentNode struct {
	module   *starlarkstruct.Module
	name     string
	wrappers map[string]*concurrentValue
	children []*concurrentNode
}

func discoverConcurrent(members starlark.StringDict, module *starlarkstruct.Module) (*concurrentNode, int, error) {
	if err := validateTree(members); err != nil {
		return nil, 0, err
	}
	return concurrentTree(members, module)
}

func concurrentTree(members starlark.StringDict, module *starlarkstruct.Module) (*concurrentNode, int, error) {
	node := &concurrentNode{module: module, wrappers: make(map[string]*concurrentValue)}
	if module != nil {
		node.name = module.Name
	}
	count := 0
	for _, name := range members.Keys() {
		wrapper, ok := members[name].(*concurrentValue)
		if !ok {
			continue
		}
		if !concurrentEligible(name) {
			return nil, 0, fmt.Errorf("Concurrent decorator not supported for '%s' method.", name) //nolint:staticcheck // Match the upstream binding-name diagnostic.
		}
		node.wrappers[name] = wrapper
		count++
	}
	children, err := childrenOf(members)
	if err != nil {
		return nil, 0, err
	}
	for position, child := range children {
		next, n, err := concurrentTree(child.Members, child)
		if err != nil {
			return nil, 0, fmt.Errorf("addons[%d](%s): %w", position, child.Name, err)
		}
		node.children = append(node.children, next)
		count += n
	}
	return node, count, nil
}

func (n *concurrentNode) corresponds(other *concurrentNode, live bool) error {
	if n.name != other.name || len(n.children) != len(other.children) || (live && n.module != other.module) {
		return errors.New("concurrent addons path changed")
	}
	if len(n.wrappers) != len(other.wrappers) {
		return errors.New("concurrent hook bindings changed")
	}
	for name, a := range n.wrappers {
		b := other.wrappers[name]
		if b == nil || (live && a != b) || a.function.NumParams() != b.function.NumParams() || a.function.NumKwonlyParams() != b.function.NumKwonlyParams() || a.function.HasVarargs() != b.function.HasVarargs() || a.function.HasKwargs() != b.function.HasKwargs() {
			return fmt.Errorf("concurrent hook %s has no compatible counterpart", name)
		}
	}
	for position, child := range n.children {
		if err := child.corresponds(other.children[position], live); err != nil {
			return fmt.Errorf("addons[%d](%s): %w", position, child.name, err)
		}
	}
	return nil
}
