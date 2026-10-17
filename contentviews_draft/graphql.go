// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"bytes"
	"encoding/binary"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
)

// GraphQL separates GraphQL queries from their JSON envelope.
type GraphQL struct{}

// Name returns the view's selection name.
func (GraphQL) Name() string { return "GraphQL" }

// SyntaxHighlight returns the renderer's syntax name.
func (GraphQL) SyntaxHighlight() string { return "none" }

// RenderPriority selects GraphQL JSON objects and batches.
func (GraphQL) RenderPriority(data []byte, metadata contentviews.Metadata) float64 {
	if metadata.ContentType != "application/json" || len(data) == 0 {
		return 0
	}
	root, err := parseGraphQLJSON(data, &viewBudget{view: "GraphQL"})
	if err == nil && isGraphQL(root) {
		return 2
	}
	return 0
}

// Prettify formats query envelopes without changing member order or input.
func (GraphQL) Prettify(data []byte, _ contentviews.Metadata) (string, error) {
	budget := &viewBudget{view: "GraphQL"}
	root, err := parseGraphQLJSON(data, budget)
	if err != nil {
		return "", err
	}
	if !isGraphQL(root) {
		return "", fmt.Errorf("not a GraphQL message")
	}
	var out strings.Builder
	operations := []*graphJSON{root}
	if root.kind == '[' {
		operations = root.elements
	}
	for i, operation := range operations {
		if root.kind == '[' {
			if err := graphWrite(&out, budget, fmt.Sprintf("--- %d/%d\n", i, len(operations)-1)); err != nil {
				return "", err
			}
		}
		if err := formatGraphQL(&out, operation, budget); err != nil {
			return "", err
		}
	}
	return out.String(), nil
}

func formatGraphQL(out *strings.Builder, operation *graphJSON, budget *viewBudget) error {
	query := operation.member("query")
	if operation.kind != '{' || query == nil || query.kind != '"' {
		return fmt.Errorf("invalid GraphQL operation")
	}
	if err := writeGraphJSON(out, operation, budget, 0, true); err != nil {
		return err
	}
	if err := graphWrite(out, budget, "\n---\n"); err != nil {
		return err
	}
	if err := graphWrite(out, budget, query.text); err != nil {
		return err
	}
	return graphWrite(out, budget, "\n")
}

type graphJSON struct {
	kind     byte
	text     string
	members  []graphMember
	elements []*graphJSON
}

type graphMember struct {
	key   string
	value *graphJSON
}

func (n *graphJSON) member(key string) *graphJSON {
	if n != nil {
		for _, member := range n.members {
			if member.key == key {
				return member.value
			}
		}
	}
	return nil
}

func isGraphQL(root *graphJSON) bool {
	if root.kind == '[' {
		return len(root.elements) != 0 && root.elements[0].kind == '{' && root.elements[0].member("query") != nil
	}
	query := root.member("query")
	return root.kind == '{' && query != nil && query.kind == '"' && strings.ContainsRune(query.text, '\n')
}

func parseGraphQLJSON(data []byte, budget *viewBudget) (*graphJSON, error) {
	if len(data) > maxViewBytes {
		return nil, &LimitError{View: "GraphQL", Stage: "JSON", Bound: "input bytes"}
	}
	data, err := graphJSONUTF8(data)
	if err != nil {
		return nil, err
	}
	data, constants, err := graphConstants(data, budget)
	if err != nil {
		return nil, err
	}
	decoder := jsontext.NewDecoder(bytes.NewReader(data), jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	root, err := readGraphJSON(decoder, constants, budget, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.ReadToken(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("trailing GraphQL JSON data")
	}
	return root, nil
}

func readGraphJSON(decoder *jsontext.Decoder, constants map[int64]string, budget *viewBudget, depth int) (*graphJSON, error) {
	if err := budget.checkDepth(depth, "JSON"); err != nil {
		return nil, err
	}
	if err := budget.reserveNodes(1, "JSON"); err != nil {
		return nil, err
	}
	kind := byte(decoder.PeekKind())
	node := &graphJSON{kind: kind}
	if kind == '{' || kind == '[' {
		if _, err := decoder.ReadToken(); err != nil {
			return nil, err
		}
		if kind == '{' {
			positions := make(map[string]int)
			for decoder.PeekKind() != '}' {
				if err := budget.reserveNodes(1, "JSON key"); err != nil {
					return nil, err
				}
				raw, err := decoder.ReadValue()
				if err != nil {
					return nil, err
				}
				key := graphUnquote(raw)
				value, err := readGraphJSON(decoder, constants, budget, depth+1)
				if err != nil {
					return nil, err
				}
				if index, found := positions[key]; found {
					node.members[index].value = value
				} else {
					positions[key] = len(node.members)
					node.members = append(node.members, graphMember{key, value})
				}
			}
		} else {
			for decoder.PeekKind() != ']' {
				child, err := readGraphJSON(decoder, constants, budget, depth+1)
				if err != nil {
					return nil, err
				}
				node.elements = append(node.elements, child)
			}
		}
		_, err := decoder.ReadToken()
		return node, err
	}
	raw, err := decoder.ReadValue()
	if err != nil {
		return nil, err
	}
	if kind == '"' {
		node.text = graphUnquote(raw)
	} else {
		if kind == '0' && !bytes.ContainsAny(raw, ".eE") && len(bytes.TrimPrefix(raw, []byte("-"))) > 4300 {
			return nil, fmt.Errorf("GraphQL integer exceeds Python's conversion limit")
		}
		node.text = string(raw)
		if constant, found := constants[decoder.InputOffset()]; found {
			node.text = constant
		} else if kind == '0' && strings.ContainsAny(node.text, ".eE") {
			value, err := strconv.ParseFloat(node.text, 64)
			if err != nil && !errors.Is(err, strconv.ErrRange) {
				return nil, err
			}
			switch {
			case math.IsInf(value, 1):
				node.text = "Infinity"
			case math.IsInf(value, -1):
				node.text = "-Infinity"
			default:
				node.text = tnetstring.FormatFloat(value)
			}
		} else if node.text == "-0" {
			node.text = "0"
		}
	}
	return node, nil
}

func graphConstants(data []byte, budget *viewBudget) ([]byte, map[int64]string, error) {
	var constants map[int64]string
	quoted := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			quoted = !quoted
			continue
		}
		if quoted {
			if data[i] == '\\' {
				i++
			}
			continue
		}
		for _, literal := range []string{"NaN", "Infinity", "-Infinity"} {
			end := i + len(literal)
			if !bytes.HasPrefix(data[i:], []byte(literal)) || i > 0 && !strings.ContainsRune("[,: \t\r\n", rune(data[i-1])) || end < len(data) && !strings.ContainsRune(",]} \t\r\n", rune(data[end])) {
				continue
			}
			if err := budget.reserveNodes(1, "JSON constant"); err != nil {
				return nil, nil, err
			}
			if constants == nil {
				data = bytes.Clone(data)
				constants = make(map[int64]string)
			}
			for j := i; j < end-1; j++ {
				data[j] = ' '
			}
			data[end-1] = '0'
			constants[int64(end)] = literal
			i = end - 1
			break
		}
	}
	return data, constants, nil
}

func graphWrite(out *strings.Builder, budget *viewBudget, text string) error {
	if err := budget.reserveBytes(len(text), "GraphQL output"); err != nil {
		return err
	}
	out.WriteString(text)
	return nil
}

func writeGraphJSON(out *strings.Builder, node *graphJSON, budget *viewBudget, depth int, replaceQuery bool) error {
	if node.kind == '"' {
		return graphQuote(out, budget, node.text)
	}
	if node.kind != '{' && node.kind != '[' {
		return graphWrite(out, budget, node.text)
	}
	open, close := "{", "}"
	length := len(node.members)
	if node.kind == '[' {
		open, close, length = "[", "]", len(node.elements)
	}
	if err := graphWrite(out, budget, open); err != nil {
		return err
	}
	for i := range length {
		if i != 0 {
			if err := graphWrite(out, budget, ","); err != nil {
				return err
			}
		}
		if err := graphWrite(out, budget, "\n"+strings.Repeat("  ", depth+1)); err != nil {
			return err
		}
		var value *graphJSON
		if node.kind == '{' {
			member := node.members[i]
			if err := graphQuote(out, budget, member.key); err != nil {
				return err
			}
			if err := graphWrite(out, budget, ": "); err != nil {
				return err
			}
			value = member.value
			if replaceQuery && member.key == "query" {
				value = &graphJSON{kind: '"', text: "..."}
			}
		} else {
			value = node.elements[i]
		}
		if err := writeGraphJSON(out, value, budget, depth+1, false); err != nil {
			return err
		}
	}
	if length != 0 {
		if err := graphWrite(out, budget, "\n"+strings.Repeat("  ", depth)); err != nil {
			return err
		}
	}
	return graphWrite(out, budget, close)
}

func graphQuote(out *strings.Builder, budget *viewBudget, text string) error {
	if err := graphWrite(out, budget, "\""); err != nil {
		return err
	}
	for len(text) != 0 {
		r, size := utf8.DecodeRuneInString(text)
		if r == utf8.RuneError && size == 1 && len(text) >= 3 && text[0] == 0xed && text[1] >= 0xa0 && text[1] <= 0xbf && text[2]&0xc0 == 0x80 {
			r, size = rune(text[0]&15)<<12|rune(text[1]&63)<<6|rune(text[2]&63), 3
		}
		text = text[size:]
		var escaped string
		switch r {
		case '"', '\\':
			escaped = "\\" + string(r)
		case '\b':
			escaped = `\b`
		case '\f':
			escaped = `\f`
		case '\n':
			escaped = `\n`
		case '\r':
			escaped = `\r`
		case '\t':
			escaped = `\t`
		default:
			if r < 32 || r > 126 {
				if r > 0xffff {
					hi, lo := utf16.EncodeRune(r)
					escaped = fmt.Sprintf("\\u%04x\\u%04x", hi, lo)
				} else {
					escaped = fmt.Sprintf("\\u%04x", r)
				}
			} else {
				escaped = string(r)
			}
		}
		if err := graphWrite(out, budget, escaped); err != nil {
			return err
		}
	}
	return graphWrite(out, budget, "\"")
}

func graphUnquote(raw []byte) string {
	var out []byte
	for i := 1; i < len(raw)-1; i++ {
		if raw[i] != '\\' {
			out = append(out, raw[i])
			continue
		}
		i++
		switch raw[i] {
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			code, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			i += 4
			r := rune(code)
			if r >= 0xd800 && r <= 0xdbff && i+6 < len(raw) && raw[i+1] == '\\' && raw[i+2] == 'u' {
				low, _ := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
				if low >= 0xdc00 && low <= 0xdfff {
					r = utf16.DecodeRune(r, rune(low))
					i += 6
				}
			}
			out = graphAppendRune(out, r)
		default:
			out = append(out, raw[i])
		}
	}
	return string(out)
}

func graphAppendRune(out []byte, r rune) []byte {
	if r >= 0xd800 && r <= 0xdfff {
		return append(out, byte(0xe0|r>>12), byte(0x80|(r>>6)&63), byte(0x80|r&63))
	}
	return utf8.AppendRune(out, r)
}

func graphJSONUTF8(data []byte) ([]byte, error) {
	var order binary.ByteOrder
	width := 1
	switch {
	case bytes.HasPrefix(data, []byte{0, 0, 0xfe, 0xff}):
		order, width, data = binary.BigEndian, 4, data[4:]
	case bytes.HasPrefix(data, []byte{0xff, 0xfe, 0, 0}):
		order, width, data = binary.LittleEndian, 4, data[4:]
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
		order, width, data = binary.BigEndian, 2, data[2:]
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		order, width, data = binary.LittleEndian, 2, data[2:]
	case bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}):
		data = data[3:]
	case len(data) >= 4 && data[0] == 0 && data[1] == 0:
		order, width = binary.BigEndian, 4
	case len(data) >= 4 && data[1] == 0 && data[2] == 0 && data[3] == 0:
		order, width = binary.LittleEndian, 4
	case len(data) >= 2 && data[0] == 0:
		order, width = binary.BigEndian, 2
	case len(data) >= 2 && data[1] == 0:
		order, width = binary.LittleEndian, 2
	}
	if width == 1 {
		for i := 0; i < len(data); {
			r, size := utf8.DecodeRune(data[i:])
			if r == utf8.RuneError && size == 1 {
				if i+2 >= len(data) || data[i] != 0xed || data[i+1] < 0xa0 || data[i+1] > 0xbf || data[i+2]&0xc0 != 0x80 {
					return nil, fmt.Errorf("invalid GraphQL JSON encoding")
				}
				size = 3
			}
			i += size
		}
		return data, nil
	}
	if len(data)%width != 0 {
		return nil, fmt.Errorf("invalid GraphQL JSON encoding")
	}
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i += width {
		var r rune
		if width == 4 {
			code := order.Uint32(data[i:])
			if code > utf8.MaxRune {
				return nil, fmt.Errorf("invalid GraphQL JSON encoding")
			}
			r = rune(code)
		} else {
			r = rune(order.Uint16(data[i:]))
			if r >= 0xd800 && r <= 0xdbff && i+3 < len(data) {
				low := rune(order.Uint16(data[i+2:]))
				if low >= 0xdc00 && low <= 0xdfff {
					r = utf16.DecodeRune(r, low)
					i += 2
				}
			}
		}
		size := utf8.RuneLen(r)
		if size < 0 {
			size = 3
		}
		if size > maxViewBytes-len(out) {
			return nil, &LimitError{View: "GraphQL", Stage: "JSON encoding", Bound: "input bytes"}
		}
		out = graphAppendRune(out, r)
	}
	return out, nil
}
