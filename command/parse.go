// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

// ParseResult describes one token of a possibly partial command line
// (mitmproxy's command.ParseResult).
type ParseResult struct {
	// Value is the token as it appears on the line, quotes included.
	Value string
	// Type is the identity the token was checked against: [SpaceType] for a
	// separator, the identity of the parameter the token lands on, and
	// [UnknownType] for a token beyond the command's parameters.
	Type Type
	// Valid reports whether the token parses as Type. A separator is always
	// valid; a token of an identity outside the registry never is.
	Valid bool
}

// ParsePartial parses a possibly partial command line and returns one
// [ParseResult] per token and the parameters still missing from the line
// (mitmproxy's CommandManager.parse_partial).
//
// Every line parses: an unknown command name or an unparseable argument
// makes its token invalid rather than failing. Checking a token's validity
// runs the identity's parse, so a [ChoiceType] argument executes its options
// command and a flow argument resolves its specification, each through
// [Manager.Call]'s Runner with ctx.
func (m *Manager) ParsePartial(ctx context.Context, cmdstr string) ([]ParseResult, []Param) {
	var parsed []ParseResult
	nextParams := []Param{{Type: CmdType}, {Type: ArgType}}
	var (
		expected    Param
		hasExpected bool
	)
	for _, part := range Lex(cmdstr) {
		if isSpace(part) {
			parsed = append(parsed, ParseResult{Value: part, Type: SpaceType, Valid: true})
			continue
		}

		switch {
		case hasExpected && expected.Variadic:
			// A variadic parameter takes every remaining token.
		case len(nextParams) > 0:
			expected = nextParams[0]
			nextParams = nextParams[1:]
			hasExpected = true
		default:
			expected = Param{Type: UnknownType}
			hasExpected = true
		}

		// A known command name fills in that command's parameters for the
		// placeholder [Param] of identity Arg that follows a Cmd parameter;
		// an unknown one just consumes the placeholder.
		if expected.Type == CmdType && len(nextParams) > 0 && nextParams[0].Type == ArgType {
			if c := m.get(part); c != nil {
				nextParams = append(slices.Clone(c.Params), nextParams[1:]...)
			} else {
				nextParams = nextParams[1:]
			}
		}

		valid := false
		if inRegistry(expected.Type) {
			_, err := expected.Type.Parse(ctx, m, part)
			valid = err == nil
		}
		parsed = append(parsed, ParseResult{Value: part, Type: expected.Type, Valid: valid})
	}
	return parsed, nextParams
}

// Execute parses a command line and calls the command it names, converting
// the remaining words as [Manager.CallStrings] does (mitmproxy's
// CommandManager.execute). A line without a command word is refused with an
// error wrapping [ErrInvalidArgument].
func (m *Manager) Execute(ctx context.Context, cmdstr string) (any, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrArgumentMismatch)
	}
	var words []string
	for _, part := range Lex(cmdstr) {
		if !isSpace(part) {
			words = append(words, Unquote(part))
		}
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("%w: Invalid command: %s", ErrInvalidArgument, pyrepr.Str(cmdstr))
	}
	run := func(ctx context.Context) (any, error) {
		// Dynamic argument checks must see the same dispatch hold as the
		// command, including the checks performed for partial parsing.
		m.ParsePartial(ctx, cmdstr)
		return m.callStrings(ctx, words[0], words[1:])
	}
	m.mu.RLock()
	r := m.runner
	m.mu.RUnlock()
	if r == nil {
		return run(ctx)
	}
	return r(ctx, words[0], run)
}

// CallStrings calls the command registered under name with string
// arguments, parsing each argument with its parameter's type identity and
// checking the result against the command's return identity (mitmproxy's
// CommandManager.call_strings).
//
// Like [Manager.Call] it refuses a nil ctx and runs through the Runner, as
// a synchronous call under the addon dispatch lock once an addon manager
// installed its Runner. Argument parsing runs inside that same hold, so a
// [ChoiceType] options command or a flow specification's view.flows.resolve
// call and the command itself are one atomic dispatch. An argument that does
// not parse is refused with an error wrapping [ErrInvalidArgument] that
// names the command and the parameter; resolving a flow argument without
// the view addon also wraps [ErrUnknownCommand] and names the missing
// view.flows.resolve command.
func (m *Manager) CallStrings(ctx context.Context, name string, args []string) (any, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: %s: nil context", ErrArgumentMismatch, name)
	}
	run := func(ctx context.Context) (any, error) {
		return m.callStrings(ctx, name, args)
	}
	m.mu.RLock()
	r := m.runner
	m.mu.RUnlock()
	if r == nil {
		return run(ctx)
	}
	return r(ctx, name, run)
}

// callStrings is CallStrings inside the Runner's hold.
func (m *Manager) callStrings(ctx context.Context, name string, args []string) (any, error) {
	c := m.get(name)
	if c == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownCommand, name)
	}

	n := len(c.Params)
	variadic := n > 0 && c.Params[n-1].Variadic
	if (!variadic && len(args) != n) || (variadic && len(args) < n-1) {
		params := make([]string, n)
		for i, p := range c.Params {
			params[i] = p.String()
		}
		return nil, fmt.Errorf("%w: \n    Expected: %s %s\n    Received: %s",
			ErrArgumentMismatch, c.Name, strings.Join(params, " "), pyrepr.Value(args))
	}

	native := make([]any, len(args))
	for i, arg := range args {
		p := c.Params[min(i, n-1)]
		if !inRegistry(p.Type) {
			return nil, fmt.Errorf("%w: %s argument %s: unsupported argument type %s", ErrInvalidArgument, c.Name, p.Name, p.Type.Name())
		}
		v, err := p.Type.Parse(ctx, m, arg)
		if err != nil {
			return nil, fmt.Errorf("%w: %s argument %s (%s): %w", ErrInvalidArgument, c.Name, p.Name, pyrepr.Str(arg), err)
		}
		native[i] = v
	}

	ret, err := m.Call(ctx, name, native...)
	if err != nil {
		return nil, err
	}
	// Only the string path validates the result, as upstream's Command.call
	// does; Manager.Call trusts native Go values.
	if c.Return != nil && !c.Return.IsValid(ctx, m, ret) {
		return nil, fmt.Errorf("%w: %s returned unexpected data - expected %s", ErrInvalidArgument, c.Name, c.Return.Display())
	}
	return ret, nil
}

// Dump writes every command's help and signature to w, sorted by signature,
// in the layout of mitmproxy's CommandManager.dump: each help line prefixed
// with "# ", then the signature, then a blank line.
func (m *Manager) Dump(w io.Writer) error {
	var cmds []*Command
	for _, c := range m.Commands() {
		cmds = append(cmds, c)
	}
	slices.SortFunc(cmds, func(a, b *Command) int {
		return strings.Compare(a.SignatureHelp(), b.SignatureHelp())
	})
	for _, c := range cmds {
		for line := range strings.Lines(c.Help) {
			if _, err := fmt.Fprintf(w, "# %s\n", strings.TrimSuffix(line, "\n")); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s\n\n", c.SignatureHelp()); err != nil {
			return err
		}
	}
	return nil
}

// get returns the command registered under name, or nil.
func (m *Manager) get(name string) *Command {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.commands.Get(name)
	if !ok {
		return nil
	}
	return c
}

// has reports whether a command is registered under name.
func (m *Manager) has(name string) bool {
	return m.get(name) != nil
}
