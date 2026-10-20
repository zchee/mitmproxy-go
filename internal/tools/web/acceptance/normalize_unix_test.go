// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest && unix

package acceptance_test

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"strconv"
)

// Keep numbers distinct from strings without rounding integer metadata through float64.
type webJSONNumber string

type webIDKey struct {
	kind  string
	value string
}

type webBijections struct {
	ids   map[webIDKey]string
	times map[webJSONNumber]webJSONNumber
}

var webNumberDecoder = json.UnmarshalFromFunc(func(decoder *jsontext.Decoder, out *any) error {
	if decoder.PeekKind() != '0' {
		return errors.ErrUnsupported
	}
	raw, err := decoder.ReadValue()
	if err != nil {
		return err
	}
	number, ok := new(big.Rat).SetString(string(raw))
	if !ok {
		return errors.New("JSON number cannot be compared exactly")
	}
	*out = webJSONNumber(number.RatString())
	return nil
})

func decodeWebComparable(raw []byte) (any, error) {
	var result any
	if err := json.Unmarshal(raw, &result, json.WithUnmarshalers(webNumberDecoder)); err != nil {
		return nil, err
	}
	return result, nil
}

func (n *webBijections) flow(raw []byte) (any, error) {
	value, err := decodeWebComparable(raw)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("flow must be a JSON object")
	}
	if err := n.id(object, "flow"); err != nil {
		return nil, err
	}
	if err := n.timestamps(object, "timestamp_created"); err != nil {
		return nil, err
	}
	for _, name := range []string{"client_conn", "server_conn"} {
		connection, present, err := webObjectMember(object, name)
		if err != nil {
			return nil, err
		}
		if !present {
			continue
		}
		if err := n.id(connection, "connection"); err != nil {
			return nil, err
		}
		fields := []string{"timestamp_start", "timestamp_tls_setup", "timestamp_end"}
		if name == "server_conn" {
			fields = append(fields, "timestamp_tcp_setup")
		}
		if err := n.timestamps(connection, fields...); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"request", "response", "error", "messages_meta", "websocket"} {
		child, present, err := webObjectMember(object, name)
		if err != nil {
			return nil, err
		}
		if !present {
			continue
		}
		var fields []string
		switch name {
		case "request", "response":
			if object["type"] == "dns" {
				fields = []string{"timestamp"}
			} else {
				fields = []string{"timestamp_start", "timestamp_end"}
			}
		case "error":
			fields = []string{"timestamp"}
		case "messages_meta":
			fields = []string{"timestamp_last"}
		case "websocket":
			fields = []string{"timestamp_end"}
		}
		if err := n.timestamps(child, fields...); err != nil {
			return nil, err
		}
		if name == "websocket" {
			messages, present, err := webObjectMember(child, "messages_meta")
			if err != nil {
				return nil, err
			}
			if present {
				if err := n.timestamps(messages, "timestamp_last"); err != nil {
					return nil, err
				}
			}
		}
	}
	return object, nil
}

func webObjectMember(parent map[string]any, name string) (map[string]any, bool, error) {
	value, exists := parent[name]
	if !exists || value == nil {
		return nil, false, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, false, fmt.Errorf("%s must be an object or null", name)
	}
	return object, true, nil
}

func (n *webBijections) id(object map[string]any, kind string) error {
	value, ok := object["id"].(string)
	if !ok {
		return fmt.Errorf("%s id must be a string", kind)
	}
	if n.ids == nil {
		n.ids = make(map[webIDKey]string)
	}
	key := webIDKey{kind, value}
	canonical, exists := n.ids[key]
	if !exists {
		canonical = kind + ":" + strconv.Itoa(len(n.ids))
		n.ids[key] = canonical
	}
	object["id"] = canonical
	return nil
}

func (n *webBijections) timestamps(object map[string]any, names ...string) error {
	for _, name := range names {
		value, exists := object[name]
		if !exists || value == nil {
			continue
		}
		number, ok := value.(webJSONNumber)
		if !ok {
			return fmt.Errorf("%s must be a number or null", name)
		}
		if n.times == nil {
			n.times = make(map[webJSONNumber]webJSONNumber)
		}
		canonical, exists := n.times[number]
		if !exists {
			canonical = webJSONNumber(strconv.Itoa(len(n.times)))
			n.times[number] = canonical
		}
		object[name] = canonical
	}
	return nil
}
