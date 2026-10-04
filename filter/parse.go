// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package filter parses mitmproxy flow filter expressions.
//
// The language is the one mitmproxy's flowfilter module defines with
// pyparsing, and Parse accepts and rejects exactly the inputs mitmproxy
// does:
//
//   - Operators are ~ followed by a name, such as ~q, ~h regex or ~c 404.
//     The name must be followed by whitespace, a non-ASCII character or the
//     end of the input, so ~q& and ~h"x" are errors.
//   - A regex argument is either a run of characters other than ( ) ~ ' "
//     and the whitespace characters space, tab, CR and LF, or a string in
//     double or single quotes with backslash escapes. A bare argument
//     without an operator means ~u. Because & | and ! are word characters,
//     a&b is one bare word, not a conjunction.
//   - ! (not) binds tightest, then & (and), then | (or); parentheses
//     group. Expressions written next to each other at the top level are
//     joined with an implicit and; inside parentheses they are an error.
//   - Tabs are expanded to spaces before parsing, as pyparsing's
//     parse_string does with str.expandtabs, so a tab inside a quoted
//     argument reaches the pattern as spaces.
//   - In a quoted argument \t, \n, \f and \r become control characters,
//     \0 becomes NUL, and any other backslash is dropped, so \d is "d".
//     \x41 stays the text "x41": pyparsing 3.3's QuotedString writes its
//     numeric-escape regex in an f-string, which turns {2} and {4} into
//     the literal digits 2 and 4, so only \xH2 and \uH4 are decoded.
//   - Patterns are case-insensitive unless the environment variable
//     MITMPROXY_CASE_SENSITIVE_FILTERS is "1". ~h, ~hq, ~hs, ~meta and
//     ~comment compile with MULTILINE, ~b, ~bq and ~bs with DOTALL. See
//     package regex for how Python patterns map onto Go engines.
//
// mitmproxy reads MITMPROXY_CASE_SENSITIVE_FILTERS once at import time;
// Parse reads it on every call.
package filter

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/filter/regex"
)

const (
	// whitespace is pyparsing's DEFAULT_WHITE_CHARS. Other spaces, such as
	// form feed or U+3000, are ordinary word characters.
	whitespace = " \n\t\r"
	// wordStop ends an unquoted argument.
	wordStop = "()~'\"" + whitespace
	// maxIntDigits is CPython's default limit for converting a decimal
	// string to int; upstream's int() raises ValueError beyond it.
	maxIntDigits = 4300
)

// Operator precedences, as pyparsing's infix_notation assigns them.
const (
	precOr  = 10
	precAnd = 20
	precNot = 30
)

// ParseError describes why a filter expression was rejected.
type ParseError struct {
	// Expr is the expression that was parsed.
	Expr string
	// Offset is the byte offset in Expr where the problem was detected.
	Offset int
	// Msg describes the problem.
	Msg string
}

func (e *ParseError) Error() string {
	if e.Expr == "" {
		return "empty filter expression"
	}
	return fmt.Sprintf("invalid filter expression %q: %s at offset %d", e.Expr, e.Msg, e.Offset)
}

// Parse parses a filter expression.
//
// The returned error is a *ParseError naming the offset of the problem.
func Parse(expr string) (Expr, error) {
	if expr == "" {
		return nil, &ParseError{Msg: "empty filter expression"}
	}
	if !utf8.ValidString(expr) {
		off := 0
		for off < len(expr) {
			r, size := utf8.DecodeRuneInString(expr[off:])
			if r == utf8.RuneError && size == 1 {
				break
			}
			off += size
		}
		return nil, &ParseError{Expr: expr, Offset: off, Msg: "invalid UTF-8"}
	}
	p := &parser{orig: expr, src: expandTabs(expr), ignoreCase: os.Getenv("MITMPROXY_CASE_SENSITIVE_FILTERS") != "1"}
	var exprs []Expr
	for {
		p.skipSpace()
		if p.pos == len(p.src) {
			break
		}
		e, err := p.infix()
		if err != nil {
			return nil, err
		}
		exprs = append(exprs, e)
	}
	switch len(exprs) {
	case 0:
		return nil, p.errorf(p.pos, "expected a filter expression")
	case 1:
		return exprs[0], nil
	}
	return &And{Exprs: exprs}, nil
}

type parser struct {
	// orig is the expression as passed to Parse; src is orig with tabs
	// expanded, which is what pyparsing parses.
	orig       string
	src        string
	pos        int
	ignoreCase bool
}

func (p *parser) errorf(off int, msg string) *ParseError {
	return &ParseError{Expr: p.orig, Offset: origOffset(p.orig, off), Msg: msg}
}

// expandTabs replaces tabs the way Python's str.expandtabs() does, which
// pyparsing applies to its input before parsing: each tab becomes spaces up
// to the next multiple of 8 columns, and CR and LF reset the column. A tab
// inside a quoted argument therefore reaches the pattern as spaces.
func expandTabs(s string) string {
	if !strings.Contains(s, "\t") {
		return s
	}
	var b strings.Builder
	col := 0
	for _, r := range s {
		switch r {
		case '\t':
			n := 8 - col%8
			b.WriteString(strings.Repeat(" ", n))
			col += n
		case '\n', '\r':
			b.WriteRune(r)
			col = 0
		default:
			b.WriteRune(r)
			col++
		}
	}
	return b.String()
}

// origOffset maps a byte offset in expandTabs(orig) back to orig.
func origOffset(orig string, off int) int {
	if !strings.Contains(orig, "\t") {
		return off
	}
	pos, col := 0, 0
	for i, r := range orig {
		width := utf8.RuneLen(r)
		switch r {
		case '\t':
			width = 8 - col%8
			col += width
		case '\n', '\r':
			col = 0
		default:
			col++
		}
		if off < pos+width {
			return i
		}
		pos += width
	}
	return len(orig)
}

func (p *parser) skipSpace() {
	for p.pos < len(p.src) && strings.IndexByte(whitespace, p.src[p.pos]) >= 0 {
		p.pos++
	}
}

func (p *parser) peek(c byte) bool { return p.pos < len(p.src) && p.src[p.pos] == c }

type opKind uint8

const (
	opNot opKind = iota
	opAnd
	opOr
	opParen
)

type operator struct {
	kind opKind
	prec int
	// operands is the number of operands a chained And or Or collects.
	operands int
	// offset is where an opening parenthesis was, for error messages.
	offset int
}

// infix parses one operator-precedence expression the way pyparsing 3.3's
// infix_notation does: a shunting-yard loop with no backtracking that stops
// at the first place where an operator is expected but none follows.
func (p *parser) infix() (Expr, error) {
	var (
		operands  []Expr
		operators []operator
		depth     int
	)
	reduce := func(minPrec int) {
		for len(operators) > 0 {
			top := operators[len(operators)-1]
			if top.kind == opParen || top.prec <= minPrec {
				return
			}
			operators = operators[:len(operators)-1]
			switch top.kind {
			case opNot:
				operands[len(operands)-1] = &Not{Expr: operands[len(operands)-1]}
			case opAnd, opOr:
				n := len(operands) - top.operands
				args := append([]Expr(nil), operands[n:]...)
				operands = operands[:n]
				if top.kind == opAnd {
					operands = append(operands, &And{Exprs: args})
				} else {
					operands = append(operands, &Or{Exprs: args})
				}
			}
		}
	}
	binary := func(kind opKind, prec int) {
		reduce(prec)
		if n := len(operators); n > 0 && operators[n-1].kind == kind {
			operators[n-1].operands++
			return
		}
		operators = append(operators, operator{kind: kind, prec: prec, operands: 2})
	}

	expectOperand := true
	for {
		p.skipSpace()
		if expectOperand {
			switch {
			case p.peek('!'):
				operators = append(operators, operator{kind: opNot, prec: precNot})
				p.pos++
			case p.peek('('):
				operators = append(operators, operator{kind: opParen, offset: p.pos})
				depth++
				p.pos++
			default:
				e, err := p.atom()
				if err != nil {
					return nil, err
				}
				operands = append(operands, e)
				expectOperand = false
			}
			continue
		}
		if depth > 0 && p.peek(')') {
			reduce(-1)
			operators = operators[:len(operators)-1]
			depth--
			p.pos++
			continue
		}
		if p.peek('&') {
			binary(opAnd, precAnd)
			p.pos++
			expectOperand = true
			continue
		}
		if p.peek('|') {
			binary(opOr, precOr)
			p.pos++
			expectOperand = true
			continue
		}
		break
	}
	reduce(-1)
	if depth > 0 {
		var open int
		for _, op := range operators {
			if op.kind == opParen {
				open = op.offset
			}
		}
		if p.pos == len(p.src) {
			return nil, p.errorf(p.pos, "missing ')' for '(' at offset "+strconv.Itoa(open))
		}
		return nil, p.errorf(p.pos, "expected '&', '|' or ')' inside parentheses opened at offset "+strconv.Itoa(open))
	}
	return operands[0], nil
}

// atom parses an operator with its argument, or a bare URL pattern.
func (p *parser) atom() (Expr, error) {
	if p.pos == len(p.src) {
		return nil, p.errorf(p.pos, "unexpected end of expression")
	}
	switch c := p.src[p.pos]; c {
	case ')':
		return nil, p.errorf(p.pos, "unexpected ')'")
	case '~':
		return p.operator()
	}
	start := p.pos
	pattern, err := p.argument()
	if err != nil {
		return nil, err
	}
	return p.rex(TokenURL, pattern, start)
}

func (p *parser) operator() (Expr, error) {
	start := p.pos
	end := start + 1
	for end < len(p.src) && p.src[end] > ' ' && p.src[end] < 0x7f {
		end++
	}
	name := p.src[start:end]
	tok, ok := tokenByCode[name[1:]]
	if !ok {
		return nil, p.errorf(start, "unknown operator "+strconv.Quote(name))
	}
	p.pos = end
	switch tok.Arity() {
	case ArityRegex:
		p.skipSpace()
		argStart := p.pos
		if p.pos == len(p.src) || strings.IndexByte("()~", p.src[p.pos]) >= 0 {
			return nil, p.errorf(p.pos, tok.String()+" requires a regex argument")
		}
		pattern, err := p.argument()
		if err != nil {
			return nil, err
		}
		return p.rex(tok, pattern, argStart)
	case ArityInt:
		p.skipSpace()
		digitsStart := p.pos
		for p.pos < len(p.src) && '0' <= p.src[p.pos] && p.src[p.pos] <= '9' {
			p.pos++
		}
		digits := p.src[digitsStart:p.pos]
		if digits == "" {
			return nil, p.errorf(digitsStart, tok.String()+" requires an integer argument")
		}
		if len(digits) > maxIntDigits {
			return nil, p.errorf(digitsStart, tok.String()+" argument exceeds "+strconv.Itoa(maxIntDigits)+" digits")
		}
		if v := strings.TrimLeft(digits, "0"); v != "" {
			digits = v
		} else {
			digits = "0"
		}
		return &Int{Token: tok, Value: digits}, nil
	}
	return &Unary{Token: tok}, nil
}

// argument parses an unquoted word or a quoted string at p.pos.
func (p *parser) argument() (string, error) {
	switch q := p.src[p.pos]; q {
	case '"', '\'':
		return p.quoted(q)
	}
	start := p.pos
	for p.pos < len(p.src) && strings.IndexByte(wordStop, p.src[p.pos]) < 0 {
		p.pos++
	}
	return p.src[start:p.pos], nil
}

// quoted parses a string enclosed in q, like pyparsing's
// QuotedString(q, esc_char="\\"): the string ends at the first unescaped q,
// and may not contain a raw CR or LF, nor a backslash before an LF.
func (p *parser) quoted(q byte) (string, error) {
	start := p.pos
	i := start + 1
	for {
		if i >= len(p.src) {
			return "", p.errorf(start, "unterminated quoted string")
		}
		switch c := p.src[i]; c {
		case q:
			p.pos = i + 1
			return unescape(p.src[start+1 : i]), nil
		case '\n', '\r':
			return "", p.errorf(i, "line break inside quoted string")
		case '\\':
			if i+1 >= len(p.src) {
				return "", p.errorf(start, "unterminated quoted string")
			}
			if p.src[i+1] == '\n' {
				return "", p.errorf(i, "line break inside quoted string")
			}
			_, size := utf8.DecodeRuneInString(p.src[i+1:])
			i += 1 + size
		default:
			i++
		}
	}
}

// unescape reverses the escapes of a quoted argument the way pyparsing
// 3.3's QuotedString does. Its numeric-escape pattern is written in an
// f-string, so the repetition counts {3}, {2} and {4} became the literal
// digits 3, 2 and 4: \x41 is not an escape for "A" (it yields "x41"),
// while \xA2 yields U+00A2. Every other backslash escape drops the
// backslash, so \d yields "d".
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		switch n := s[i+1]; {
		case n == 't':
			b.WriteByte('\t')
			i += 2
		case n == 'n':
			b.WriteByte('\n')
			i += 2
		case n == 'f':
			b.WriteByte('\f')
			i += 2
		case n == 'r':
			b.WriteByte('\r')
			i += 2
		case '0' <= n && n <= '7' && i+2 < len(s) && s[i+2] == '3':
			b.WriteByte(n)
			b.WriteByte('3')
			i += 3
		case n == '0':
			b.WriteByte(0)
			i += 2
		case n == 'x' && hexEscape(s, i, '2'), n == 'u' && hexEscape(s, i, '4'):
			b.WriteRune(rune(unhex(s[i+2])<<4 | unhex(s[i+3])))
			i += 4
		default:
			_, size := utf8.DecodeRuneInString(s[i+1:])
			b.WriteString(s[i+1 : i+1+size])
			i += 1 + size
		}
	}
	return b.String()
}

// hexEscape reports whether s[i:] starts with a backslash, a letter, one hex
// digit and last.
func hexEscape(s string, i int, last byte) bool {
	return i+3 < len(s) && isHex(s[i+2]) && s[i+3] == last
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) int {
	switch {
	case c <= '9':
		return int(c - '0')
	case c >= 'a':
		return int(c-'a') + 10
	}
	return int(c-'A') + 10
}

func (p *parser) rex(tok Token, pattern string, offset int) (Expr, error) {
	flags := tok.RegexFlags()
	if p.ignoreCase {
		flags |= regex.IgnoreCase
	}
	re, err := regex.Compile(pattern, flags)
	if err != nil {
		return nil, p.errorf(offset, "cannot compile expression: "+err.Error())
	}
	return &Rex{Token: tok, Pattern: pattern, re: re}, nil
}
