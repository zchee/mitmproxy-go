// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/contentviews"
)

// MQTT renders the supported MQTT control packet summaries.
type MQTT struct{}

// Name returns the view's selection name.
func (MQTT) Name() string { return "MQTT" }

// SyntaxHighlight returns the renderer's syntax name.
func (MQTT) SyntaxHighlight() string { return "none" }

// RenderPriority keeps MQTT an explicitly selected display view.
func (MQTT) RenderPriority([]byte, contentviews.Metadata) float64 { return 0 }

// Prettify decodes one MQTT packet without retaining transport state.
func (MQTT) Prettify(data []byte, _ contentviews.Metadata) (string, error) {
	if len(data) > maxViewBytes {
		return "", &LimitError{View: "MQTT", Stage: "packet", Bound: "input bytes"}
	}
	body, err := mqttBody(data)
	if err != nil {
		return "", err
	}
	budget := &viewBudget{view: "MQTT"}
	typ := data[0] >> 4
	if typ == 1 {
		return mqttConnect(body, budget)
	}
	if typ == 3 {
		return mqttPublish(body, (data[0]>>1)&3, budget)
	}
	if typ == 8 {
		return mqttSubscribe(body, budget)
	}
	names := [...]string{"reserved", "CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL", "PUBCOMP", "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK", "PINGREQ", "PINGRESP", "DISCONNECT", "reserved"}
	if typ == 12 || typ == 13 {
		return "[" + names[typ] + "]", nil
	}
	return "Packet type " + names[typ] + " is not supported yet!", nil
}

func mqttBody(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("truncated MQTT fixed header")
	}
	length, shift := 0, 0
	for i := 1; i < len(data); i++ {
		if i > 3 {
			return nil, fmt.Errorf("malformed MQTT remaining length")
		}
		length |= int(data[i]&127) << shift
		if data[i]&128 == 0 {
			if length != len(data)-i-1 {
				return nil, fmt.Errorf("MQTT remaining length does not match input")
			}
			return data[i+1:], nil
		}
		shift += 7
	}
	return nil, fmt.Errorf("truncated MQTT remaining length")
}

func mqttField(body []byte, offset int) ([]byte, int, error) {
	if len(body)-offset < 2 {
		return nil, offset, fmt.Errorf("truncated MQTT field length")
	}
	length := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if length > len(body)-offset {
		return nil, offset, fmt.Errorf("truncated MQTT field")
	}
	return body[offset : offset+length], offset + length, nil
}

func mqttPublish(body []byte, qos byte, budget *viewBudget) (string, error) {
	topic, offset, err := mqttField(body, 0)
	if err != nil {
		return "", err
	}
	if qos == 1 || qos == 2 {
		if len(body)-offset < 2 {
			return "", fmt.Errorf("truncated MQTT packet identifier")
		}
		offset += 2
	}
	if offset == len(body) {
		return "", fmt.Errorf("empty MQTT publish payload")
	}
	const prefix, middle, suffix = "[PUBLISH] '", "' to topic '", "'"
	if err := budget.reserveBytes(len(prefix)+len(middle)+len(suffix), "publish output"); err != nil {
		return "", err
	}
	payload, err := escapedViewBytes(body[offset:], budget)
	if err != nil {
		return "", err
	}
	topicText, err := escapedViewBytes(topic, budget)
	if err != nil {
		return "", err
	}
	return prefix + payload + middle + topicText + suffix, nil
}

func mqttSubscribe(body []byte, budget *viewBudget) (string, error) {
	if len(body) < 2 {
		return "", fmt.Errorf("truncated MQTT subscription identifier")
	}
	const prefix = "[SUBSCRIBE] sent topic filters: "
	if err := budget.reserveBytes(len(prefix), "subscribe output"); err != nil {
		return "", err
	}
	var output strings.Builder
	output.WriteString(prefix)
	seen := make(map[string]bool)
	for offset := 2; offset < len(body); {
		if err := budget.reserveNodes(1, "subscription"); err != nil {
			return "", err
		}
		topic, next, err := mqttField(body, offset)
		if err != nil {
			return "", err
		}
		if next == len(body) {
			return "", fmt.Errorf("truncated MQTT subscription QoS")
		}
		offset = next + 1
		if !utf8.Valid(topic) {
			return "", fmt.Errorf("invalid MQTT topic text")
		}
		if err := budget.reserveScalar(len(topic)); err != nil {
			return "", err
		}
		text := string(topic)
		if seen[text] {
			continue
		}
		punctuation := 2
		if len(seen) != 0 {
			punctuation += 2
		}
		if err := budget.reserveBytes(len(text)+punctuation, "subscription output"); err != nil {
			return "", err
		}
		if len(seen) != 0 {
			output.WriteString(", ")
		}
		seen[text] = true
		output.WriteByte('\'')
		output.WriteString(text)
		output.WriteByte('\'')
	}
	return output.String(), nil
}

func mqttConnect(body []byte, budget *viewBudget) (string, error) {
	if len(body) < 10 {
		return "", fmt.Errorf("truncated MQTT connect header")
	}
	flags := body[7]
	names := []int{0}
	if flags&4 != 0 {
		names = append(names, 1, 2)
	}
	if flags&128 != 0 {
		names = append(names, 3)
	}
	if flags&64 != 0 {
		names = append(names, 4)
	}
	values := [5]string{"None", "None", "None", "None", "None"}
	var provided [5]bool
	fieldCount := 0
	for offset := 10; offset < len(body); {
		if fieldCount == len(names) {
			return "", fmt.Errorf("unexpected MQTT connect field")
		}
		field, next, err := mqttField(body, offset)
		if err != nil {
			return "", err
		}
		offset = next
		index := names[fieldCount]
		provided[index] = true
		fieldCount++
		if index == 2 || index == 4 {
			values[index], err = escapedViewBytes(field, budget)
			if err != nil {
				return "", err
			}
			continue
		}
		if !utf8.Valid(field) {
			return "", fmt.Errorf("invalid MQTT connect text")
		}
		if err := budget.reserveNodes(1, "connect field"); err != nil {
			return "", err
		}
		if err := budget.reserveBytes(len(field), "connect text"); err != nil {
			return "", err
		}
		values[index] = string(field)
	}
	if fieldCount == 0 {
		return "", fmt.Errorf("empty MQTT connect payload")
	}
	labels := [...]string{"[CONNECT]\n\nClient Id: ", "\nWill Topic: ", "\nWill Message: ", "\nUser Name: ", "\nPassword: "}
	size := 1
	for i, label := range labels {
		size += len(label)
		if !provided[i] {
			size += 4
		}
	}
	if err := budget.reserveBytes(size, "connect output"); err != nil {
		return "", err
	}
	var output strings.Builder
	for i, label := range labels {
		output.WriteString(label)
		output.WriteString(values[i])
	}
	output.WriteByte('\n')
	return output.String(), nil
}
