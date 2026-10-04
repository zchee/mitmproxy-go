// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package filter

import (
	"fmt"
	"io"
	"strings"

	"github.com/zchee/mitmproxy-go/filter/regex"
)

// Expr is a parsed filter expression.
//
// The concrete types are *Unary, *Rex, *Int, *And, *Or and *Not.
type Expr interface {
	// String returns the expression in canonical filter syntax. Parsing
	// the result yields an equal expression.
	String() string
	// Describe returns the English rendering mitmproxy prints for the
	// expression, such as "url matches /foo/i and response code is 200".
	Describe() string

	isExpr()
}

// Unary is an operator without an argument, such as ~q or ~marked.
type Unary struct {
	Token Token
}

// Rex is an operator whose argument is a regular expression, such as ~h or
// ~u. A bare word in a filter is a Rex with TokenURL.
type Rex struct {
	Token Token
	// Pattern is the regular expression after quotes and escapes were
	// removed.
	Pattern string

	re regex.Matcher
}

// Int is the ~c operator with its decimal argument.
type Int struct {
	Token Token
	// Value is the argument in canonical decimal form, without leading
	// zeros. It is kept as text because mitmproxy accepts integers of any
	// size, up to Python's limit of 4300 digits.
	Value string
}

// And matches when every operand matches. Juxtaposed expressions are
// joined with an implicit And.
type And struct {
	Exprs []Expr
}

// Or matches when any operand matches.
type Or struct {
	Exprs []Expr
}

// Not matches when its operand does not.
type Not struct {
	Expr Expr
}

func (*Unary) isExpr() {}
func (*Rex) isExpr()   {}
func (*Int) isExpr()   {}
func (*And) isExpr()   {}
func (*Or) isExpr()    {}
func (*Not) isExpr()   {}

// Regexp returns the compiled pattern. It is nil for a Rex that was not
// built by Parse.
func (r *Rex) Regexp() regex.Matcher { return r.re }

// Flags returns the regex flags the pattern was compiled with, including
// global inline flags at the start of the pattern.
func (r *Rex) Flags() regex.Flags {
	if r.re == nil {
		return r.Token.RegexFlags() | regex.IgnoreCase
	}
	return r.re.Flags()
}

func (u *Unary) String() string { return u.Token.String() }
func (r *Rex) String() string   { return r.Token.String() + " " + quote(r.Pattern) }
func (n *Int) String() string   { return n.Token.String() + " " + n.Value }
func (a *And) String() string   { return join(a.Exprs, " & ", syntaxOperand) }
func (o *Or) String() string    { return join(o.Exprs, " | ", syntaxOperand) }
func (n *Not) String() string   { return "!" + syntaxOperand(n.Expr) }

// Describe returns the upstream text for the operator, such as "has no response".
func (u *Unary) Describe() string { return tokens[u.Token].describe }

// Describe returns the upstream text for the operator with the pattern and its
// flags in /pattern/flags form, such as "header matches /rex/im".
func (r *Rex) Describe() string {
	return fmt.Sprintf(tokens[r.Token].describe, "/"+r.Pattern+"/"+r.Flags().String())
}

// Describe returns "response code is N".
func (n *Int) Describe() string { return fmt.Sprintf(tokens[n.Token].describe, n.Value) }

// Describe joins the operands with "and", parenthesizing nested groups.
func (a *And) Describe() string { return join(a.Exprs, " and ", describeOperand) }

// Describe joins the operands with "or", parenthesizing nested groups.
func (o *Or) Describe() string { return join(o.Exprs, " or ", describeOperand) }

// Describe returns "not" followed by the operand.
func (n *Not) Describe() string { return "not " + describeOperand(n.Expr) }

func isGroup(e Expr) bool {
	switch e.(type) {
	case *And, *Or:
		return true
	}
	return false
}

// describeOperand parenthesizes an And or Or operand, like upstream's
// _parenthesize.
func describeOperand(e Expr) string {
	if isGroup(e) {
		return "(" + e.Describe() + ")"
	}
	return e.Describe()
}

// syntaxOperand parenthesizes an And or Or operand so that it parses back
// as one operand.
func syntaxOperand(e Expr) string {
	if !isGroup(e) {
		return e.String()
	}
	// An operator without an argument must be followed by whitespace:
	// "(~q & ~s)" is an unknown operator "~s)".
	if endsWithUnary(e) {
		return "(" + e.String() + " )"
	}
	return "(" + e.String() + ")"
}

func endsWithUnary(e Expr) bool {
	for {
		switch x := e.(type) {
		case *Unary:
			return true
		case *Not:
			e = x.Expr
		case *And:
			if len(x.Exprs) == 0 {
				return false
			}
			e = x.Exprs[len(x.Exprs)-1]
		case *Or:
			if len(x.Exprs) == 0 {
				return false
			}
			e = x.Exprs[len(x.Exprs)-1]
		default:
			return false
		}
	}
}

func join(es []Expr, sep string, operand func(Expr) string) string {
	var b strings.Builder
	for i, e := range es {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(operand(e))
	}
	return b.String()
}

// quote returns s as a filter argument: unchanged when it is a valid
// unquoted word, otherwise double-quoted with the escapes the parser
// reverses.
func quote(s string) string {
	if s != "" && !strings.ContainsAny(s, wordStop) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := range len(s) {
		switch c := s[i]; c {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			// A raw tab would be expanded to spaces before parsing.
			b.WriteString(`\t`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Dump writes the expression tree the way upstream's dump method does: one
// line per node, indented by tabs, holding the upstream class name followed
// by the pattern for operators that have one.
func Dump(w io.Writer, e Expr) error {
	return dump(w, e, 0)
}

func dump(w io.Writer, e Expr, indent int) error {
	var name, arg string
	var children []Expr
	switch e := e.(type) {
	case *Unary:
		name = tokens[e.Token].class
	case *Rex:
		name, arg = tokens[e.Token].class, e.Pattern
	case *Int:
		name = tokens[e.Token].class
	case *And:
		name, children = "FAnd", e.Exprs
	case *Or:
		name, children = "FOr", e.Exprs
	case *Not:
		name, children = "FNot", []Expr{e.Expr}
	default:
		return fmt.Errorf("filter: cannot dump %T", e)
	}
	if _, err := io.WriteString(w, strings.Repeat("\t", indent)+name+arg+"\n"); err != nil {
		return err
	}
	for _, c := range children {
		if err := dump(w, c, indent+1); err != nil {
			return err
		}
	}
	return nil
}
