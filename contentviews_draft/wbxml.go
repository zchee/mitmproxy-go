// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/zchee/mitmproxy-go/contentviews"
)

// WBXML renders the pinned ActiveSync WBXML vocabulary as XML.
type WBXML struct{}

// Name returns the view's selection name.
func (WBXML) Name() string { return "WBXML" }

// SyntaxHighlight returns the renderer's syntax name.
func (WBXML) SyntaxHighlight() string { return "xml" }

// RenderPriority selects supported nonempty WBXML media types.
func (WBXML) RenderPriority(data []byte, metadata contentviews.Metadata) float64 {
	if len(data) != 0 && (metadata.ContentType == "application/vnd.wap.wbxml" || metadata.ContentType == "application/vnd.ms-sync.wbxml") {
		return 1
	}
	return 0
}

// Prettify parses complete tokens with bounded work and finite truncation errors.
func (WBXML) Prettify(data []byte, _ contentviews.Metadata) (string, error) {
	budget := &viewBudget{view: "WBXML"}
	root, err := parseWBXML(data, budget)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	if err := writeWBXML(&out, budget, "<?xml version=\"1.0\" ?>\n"); err != nil {
		return "", err
	}
	for _, child := range root.children {
		if err := renderWBXML(&out, child, budget, 0); err != nil {
			return "", err
		}
	}
	return out.String(), nil
}

type wbxmlNode struct {
	tag      string
	text     string
	cdata    bool
	children []*wbxmlNode
}

func wbxmlInteger(data []byte, offset int) (uint32, int, error) {
	var value uint32
	for count := 0; count < 5 && offset < len(data); count++ {
		b := data[offset]
		offset++
		if value > ^uint32(0)>>7 {
			return 0, offset, fmt.Errorf("WBXML integer overflow")
		}
		value = value<<7 | uint32(b&127)
		if b&128 == 0 {
			return value, offset, nil
		}
	}
	return 0, offset, fmt.Errorf("truncated or oversized WBXML integer")
}

func parseWBXML(data []byte, budget *viewBudget) (*wbxmlNode, error) {
	if len(data) > maxViewBytes {
		return nil, &LimitError{View: "WBXML", Stage: "input", Bound: "input bytes"}
	}
	if len(data) < 1 {
		return nil, fmt.Errorf("empty WBXML body")
	}
	_, offset, err := wbxmlInteger(data, 1)
	if err != nil {
		return nil, err
	}
	charset, offset, err := wbxmlInteger(data, offset)
	if err != nil {
		return nil, err
	}
	if charset != 0x6a {
		return nil, fmt.Errorf("unsupported WBXML character set")
	}
	tableLength, offset, err := wbxmlInteger(data, offset)
	if err != nil {
		return nil, err
	}
	if tableLength != 0 {
		return nil, fmt.Errorf("WBXML string tables are not supported")
	}
	root := &wbxmlNode{tag: "#document"}
	stack := []*wbxmlNode{root}
	page := 0
	for offset < len(data) {
		if err := budget.reserveNodes(1, "token"); err != nil {
			return nil, err
		}
		b := data[offset]
		offset++
		parent := stack[len(stack)-1]
		switch b {
		case 0:
			if offset == len(data) || data[offset] >= byte(len(wbxmlCodePages)) {
				return nil, fmt.Errorf("invalid WBXML code page")
			}
			page = int(data[offset])
			offset++
		case 1:
			if len(stack) == 1 {
				return nil, fmt.Errorf("WBXML END token out of sequence")
			}
			stack = stack[:len(stack)-1]
		case 3, 0xc3:
			if parent == root {
				return nil, fmt.Errorf("WBXML text outside document element")
			}
			var raw []byte
			if b == 3 {
				length := bytes.IndexByte(data[offset:], 0)
				if length < 0 {
					return nil, fmt.Errorf("unterminated WBXML inline string")
				}
				raw = data[offset : offset+length]
				offset += length + 1
			} else {
				length, next, err := wbxmlInteger(data, offset)
				if err != nil {
					return nil, err
				}
				offset = next
				if uint64(length) > uint64(len(data)-offset) {
					return nil, fmt.Errorf("truncated WBXML opaque data")
				}
				raw = data[offset : offset+int(length)]
				offset += int(length)
			}
			text, err := wbxmlByteText(raw, budget)
			if err != nil {
				return nil, err
			}
			parent.children = append(parent.children, &wbxmlNode{text: text, cdata: b == 0xc3})
		case 2, 4, 0x40, 0x41, 0x42, 0x43, 0x44, 0x80, 0x81, 0x82, 0x83, 0x84, 0xc0, 0xc1, 0xc2, 0xc4:
			return nil, fmt.Errorf("unsupported WBXML global token")
		default:
			if b&128 != 0 {
				return nil, fmt.Errorf("WBXML attributes are not supported")
			}
			tag := wbxmlCodePages[page][b&63]
			if tag == "" {
				return nil, fmt.Errorf("unknown WBXML tag")
			}
			if parent == root && len(root.children) != 0 {
				return nil, fmt.Errorf("multiple WBXML document elements")
			}
			if err := budget.checkDepth(len(stack), "element"); err != nil {
				return nil, err
			}
			node := &wbxmlNode{tag: tag}
			parent.children = append(parent.children, node)
			if b&64 != 0 {
				stack = append(stack, node)
			}
		}
	}
	return root, nil
}

func wbxmlByteText(data []byte, budget *viewBudget) (string, error) {
	size := len(data)
	for _, b := range data {
		if b >= 128 {
			size++
		}
	}
	if err := budget.reserveScalar(size); err != nil {
		return "", err
	}
	var out strings.Builder
	out.Grow(size)
	for _, b := range data {
		out.WriteRune(rune(b))
	}
	return out.String(), nil
}

func writeWBXML(out *strings.Builder, budget *viewBudget, text string) error {
	if err := budget.reserveBytes(len(text), "XML output"); err != nil {
		return err
	}
	out.WriteString(text)
	return nil
}

func writeWBXMLText(out *strings.Builder, budget *viewBudget, text string) error {
	for len(text) != 0 {
		index := strings.IndexAny(text, "&<>")
		if index < 0 {
			return writeWBXML(out, budget, text)
		}
		if err := writeWBXML(out, budget, text[:index]); err != nil {
			return err
		}
		escaped := "&amp;"
		switch text[index] {
		case '<':
			escaped = "&lt;"
		case '>':
			escaped = "&gt;"
		}
		if err := writeWBXML(out, budget, escaped); err != nil {
			return err
		}
		text = text[index+1:]
	}
	return nil
}

func renderWBXML(out *strings.Builder, node *wbxmlNode, budget *viewBudget, depth int) error {
	if node.cdata {
		if strings.Contains(node.text, "]]>") {
			return fmt.Errorf("invalid WBXML CDATA delimiter")
		}
		if err := writeWBXML(out, budget, "<![CDATA["); err != nil {
			return err
		}
		if err := writeWBXML(out, budget, node.text); err != nil {
			return err
		}
		return writeWBXML(out, budget, "]]>")
	}
	indent := strings.Repeat("    ", depth)
	if node.tag == "" {
		if err := writeWBXML(out, budget, indent); err != nil {
			return err
		}
		if err := writeWBXMLText(out, budget, node.text); err != nil {
			return err
		}
		return writeWBXML(out, budget, "\n")
	}
	if err := writeWBXML(out, budget, indent+"<"+node.tag); err != nil {
		return err
	}
	if len(node.children) == 0 {
		return writeWBXML(out, budget, "/>\n")
	}
	if len(node.children) == 1 && node.children[0].tag == "" {
		if err := writeWBXML(out, budget, ">"); err != nil {
			return err
		}
		child := node.children[0]
		if child.cdata {
			if err := renderWBXML(out, child, budget, depth+1); err != nil {
				return err
			}
		} else if err := writeWBXMLText(out, budget, child.text); err != nil {
			return err
		}
		return writeWBXML(out, budget, "</"+node.tag+">\n")
	}
	if err := writeWBXML(out, budget, ">\n"); err != nil {
		return err
	}
	for _, child := range node.children {
		if err := renderWBXML(out, child, budget, depth+1); err != nil {
			return err
		}
	}
	return writeWBXML(out, budget, indent+"</"+node.tag+">\n")
}
