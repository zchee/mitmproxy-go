// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v4"
	"go.yaml.in/yaml/v4/plugin/limit"

	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/omap"
)

// DNS renders DNS messages as editable YAML, including TCP framing when metadata
// carries a TCP or HTTP message. Calls are pure and safe to run concurrently.
type DNS struct{}

// Name returns the registered view name.
func (DNS) Name() string { return "DNS" }

// SyntaxHighlight returns the upstream DNS view's highlighting language.
func (DNS) SyntaxHighlight() string { return "yaml" }

// RenderPriority prefers DNS media types and flows whose server port is 53 or 5353.
func (DNS) RenderPriority(_ []byte, metadata Metadata) float64 {
	if metadata.ContentType == "application/dns-message" {
		return 1
	}
	if metadata.Flow != nil {
		common := metadata.Flow.Common()
		if common != nil && common.ServerConn != nil && common.ServerConn.Address != nil {
			port := common.ServerConn.Address.Port
			if port == 53 || port == 5353 {
				return 1
			}
		}
	}
	return 0
}

// Prettify decodes DNS wire bytes and returns upstream-ordered YAML.
// Malformed DNS or missing TCP framing returns an error.
func (DNS) Prettify(data []byte, metadata Metadata) (string, error) {
	if metadata.TCPMessage != nil || metadata.HTTPMessage != nil {
		if len(data) < 2 {
			return "", errors.New("DNS TCP message lacks length prefix")
		}
		data = data[2:]
	}
	message, err := dns.Unpack(data, nil)
	if err != nil {
		return "", err
	}
	value := message.ToJSON()
	value.Delete("status_code")
	value.Delete("timestamp")
	node, err := dnsYAMLNode(value)
	if err != nil {
		return "", err
	}
	out, err := yaml.Dump(node, yaml.WithV4Defaults(), yaml.WithLineWidth(-1))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Reencode reconstructs DNS wire bytes from YAML without changing metadata.
// YAML text is bounded at 1 MiB, nesting at 64, and alias expansion at 10,000;
// malformed fields, excessive decoding work or oversized DNS returns an error.
func (DNS) Reencode(prettified string, metadata Metadata) ([]byte, error) {
	if len(prettified) > 1<<20 {
		return nil, errors.New("DNS YAML exceeds 1 MiB")
	}
	var node yaml.Node
	if err := yaml.Load([]byte(prettified), &node, yaml.WithPlugin(limit.New(limit.DepthValue(64), limit.AliasValue(10000)))); err != nil {
		return nil, err
	}
	remaining := 1 << 20
	value, err := dnsYAMLValue(&node, 0, &remaining)
	if err != nil {
		return nil, err
	}
	object, ok := value.(*omap.Map[any])
	if !ok {
		return nil, errors.New("DNS YAML must contain a mapping")
	}
	message, err := dns.MessageFromJSON(object)
	if err != nil {
		return nil, err
	}
	data, err := dns.Pack(message)
	if err != nil {
		return nil, err
	}
	if metadata.TCPMessage != nil || metadata.HTTPMessage != nil {
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(data)))
		return append(framed, data...), nil
	}
	return data, nil
}

func dnsYAMLNode(value any) (*yaml.Node, error) {
	switch value := value.(type) {
	case *omap.Map[any]:
		node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		serviceParams := value.Has("target_name") && value.Has("priority")
		for key, value := range value.All() {
			child, err := dnsYAMLNode(value)
			if err != nil {
				return nil, err
			}
			keyNode := yamlString(key)
			if serviceParams {
				if _, err := strconv.ParseUint(key, 10, 16); err == nil {
					keyNode = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: key}
				}
			}
			node.Content = append(node.Content, keyNode, child)
		}
		return node, nil
	case []any:
		node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, value := range value {
			child, err := dnsYAMLNode(value)
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, child)
		}
		return node, nil
	case string:
		return yamlString(value), nil
	case int:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(value)}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(value)}, nil
	default:
		return nil, fmt.Errorf("unsupported DNS YAML value %T", value)
	}
}

func dnsYAMLValue(node *yaml.Node, depth int, remaining *int) (any, error) {
	if node == nil || depth > 64 || *remaining <= 0 {
		return nil, errors.New("DNS YAML nesting or work limit exceeded")
	}
	*remaining--
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) != 1 {
			return nil, errors.New("DNS YAML requires one document")
		}
		return dnsYAMLValue(node.Content[0], depth+1, remaining)
	case yaml.AliasNode:
		return dnsYAMLValue(node.Alias, depth+1, remaining)
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return nil, errors.New("invalid DNS YAML mapping")
		}
		object := omap.New[any]()
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode {
				return nil, errors.New("DNS YAML mapping key must be scalar")
			}
			value, err := dnsYAMLValue(node.Content[i+1], depth+1, remaining)
			if err != nil {
				return nil, err
			}
			object.Set(key.Value, value)
		}
		return object, nil
	case yaml.SequenceNode:
		values := []any{}
		for _, child := range node.Content {
			value, err := dnsYAMLValue(child, depth+1, remaining)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		return values, nil
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!null":
			return nil, nil
		case "!!bool":
			return strconv.ParseBool(node.Value)
		case "!!int":
			value := strings.ReplaceAll(node.Value, "_", "")
			base := 10
			trimmed := strings.TrimLeft(value, "+-")
			if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0o") || strings.HasPrefix(trimmed, "0b") {
				base = 0
			}
			return strconv.ParseInt(value, base, 64)
		case "!!float":
			return strconv.ParseFloat(node.Value, 64)
		default:
			return node.Value, nil
		}
	default:
		return nil, fmt.Errorf("unsupported DNS YAML node kind %v", node.Kind)
	}
}

var _ InteractiveView = DNS{}
