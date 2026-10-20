// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package keymap implements context-sensitive console key bindings.
package keymap

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

// Contexts returns the upstream's supported contexts in sorted order.
func Contexts() []string {
	return []string{"chooser", "commands", "commonkey", "dataviewer", "eventlog", "flowlist", "flowview", "global", "grideditor", "help", "keybindings", "options"}
}

// Binding describes one command bound across one or more contexts.
type Binding struct {
	Key, Command, Help string
	Contexts           []string
}

// KeySpec translates the configured space spelling to an input key.
func (b Binding) KeySpec() string { return strings.ReplaceAll(b.Key, "space", " ") }

// KeyShort returns the compact help label used by upstream.
func (b Binding) KeyShort() string {
	return strings.NewReplacer("enter", "⏎", "right", "→", "space", "␣").Replace(b.Key)
}

// Keymap owns bindings under dispatch; callers receive detached value copies.
type Keymap struct {
	bindings []Binding
	change   func()
}

// New creates an empty keymap. change must be nonblocking and must not reenter it.
func New(change func()) *Keymap { return &Keymap{change: change} }

func validate(contexts []string) error {
	if len(contexts) == 0 {
		return fmt.Errorf("Must specify at least one context.") //nolint:staticcheck // Preserve upstream's binding validation error.
	}
	for _, ctx := range contexts {
		if !slices.Contains(Contexts(), ctx) {
			return fmt.Errorf("Unsupported context: %s", ctx)
		}
	}
	return nil
}

func clone(b Binding) Binding { b.Contexts = slices.Clone(b.Contexts); return b }
func (k *Keymap) changed() {
	if k.change != nil {
		k.change()
	}
}

// Add merges a key/command's contexts, replacing other bindings in those contexts.
func (k *Keymap) Add(binding Binding) error {
	if err := validate(binding.Contexts); err != nil {
		return err
	}
	binding = clone(binding)
	slices.Sort(binding.Contexts)
	binding.Contexts = slices.Compact(binding.Contexts)
	for i, b := range k.bindings {
		if b.Key == binding.Key && strings.TrimSpace(b.Command) == strings.TrimSpace(binding.Command) {
			contexts := append(slices.Clone(b.Contexts), binding.Contexts...)
			slices.Sort(contexts)
			k.bindings[i].Contexts = slices.Compact(contexts)
			if binding.Help != "" {
				k.bindings[i].Help = binding.Help
			}
			k.changed()
			return nil
		}
	}
	k.remove(binding.Key, binding.Contexts)
	k.bindings = append(k.bindings, binding)
	k.changed()
	return nil
}

// Remove unbinds key in the named contexts and keeps its other contexts intact.
func (k *Keymap) Remove(key string, contexts []string) error {
	if err := validate(contexts); err != nil {
		return err
	}
	k.remove(key, contexts)
	k.changed()
	return nil
}

func (k *Keymap) remove(key string, contexts []string) {
	for i := range k.bindings {
		if k.bindings[i].Key != key {
			continue
		}
		k.bindings[i].Contexts = slices.DeleteFunc(k.bindings[i].Contexts, func(c string) bool { return slices.Contains(contexts, c) })
	}
	k.bindings = slices.DeleteFunc(k.bindings, func(b Binding) bool { return len(b.Contexts) == 0 })
}

// Get returns a detached binding for the exact context and translated key.
func (k *Keymap) Get(context, key string) (Binding, bool) {
	for _, b := range slices.Backward(k.bindings) {
		if slices.Contains(b.Contexts, context) && b.KeySpec() == key {
			return clone(b), true
		}
	}
	return Binding{}, false
}

// Handle resolves local-before-global bindings; only suppresses global fallback.
func (k *Keymap) Handle(context, key string, only bool) (string, bool) {
	if b, ok := k.Get(context, key); ok {
		return b.Command, true
	}
	if !only {
		if b, ok := k.Get("global", key); ok {
			return b.Command, true
		}
	}
	return key, false
}

// BindingForHelp resolves current help rather than retaining an invalid cache.
func (k *Keymap) BindingForHelp(help string) (Binding, bool) {
	for _, b := range k.bindings {
		if b.Help == help {
			return clone(b), true
		}
	}
	return Binding{}, false
}

// List returns single-key bindings before chords, sorting each by key and contexts.
func (k *Keymap) List(context string) []Binding {
	var result []Binding
	for _, b := range k.bindings {
		if context == "all" || slices.Contains(b.Contexts, context) {
			result = append(result, clone(b))
		}
	}
	slices.SortFunc(result, func(a, b Binding) int {
		ac, bc := len(strings.Fields(a.Key)) != 1, len(strings.Fields(b.Key)) != 1
		if ac != bc {
			if ac {
				return 1
			}
			return -1
		}
		return cmp.Compare(a.Key+strings.Join(a.Contexts, ","), b.Key+strings.Join(b.Contexts, ","))
	})
	return result
}

// Snapshot returns immutable-by-ownership metadata for the keybindings widget.
func (k *Keymap) Snapshot() []contract.Binding {
	bindings := k.List("all")
	result := make([]contract.Binding, len(bindings))
	for i, b := range bindings {
		result[i] = contract.Binding{Key: b.Key, Command: b.Command, Help: b.Help, Contexts: b.Contexts}
	}
	return result
}

// Install applies a completely validated configuration atomically under dispatch.
func (k *Keymap) Install(bindings []Binding) error {
	for _, b := range bindings {
		if err := validate(b.Contexts); err != nil {
			return err
		}
	}
	next := New(nil)
	for _, b := range k.bindings {
		next.bindings = append(next.bindings, clone(b))
	}
	for _, b := range bindings {
		if err := next.Remove(b.Key, b.Contexts); err != nil {
			return err
		}
		if err := next.Add(b); err != nil {
			return err
		}
	}
	k.bindings = next.bindings
	k.changed()
	return nil
}
