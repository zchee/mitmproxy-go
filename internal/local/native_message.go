// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"errors"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// Linux datagrams and Windows message-mode pipes carry one raw protobuf per
// native message, unlike the length-delimited macOS stream protocol.
const (
	maxNativePacketSize     = 65535
	maxNativeIPCMessageSize = maxNativePacketSize + 1024
)

var errNativeMessageTooLarge = errors.New("native redirector message exceeds size limit")

func decodeNativePacket(data []byte) (*PacketWithMeta, error) {
	if len(data) > maxNativeIPCMessageSize {
		return nil, errNativeMessageTooLarge
	}
	if err := validateNativeWire(data, 2, 16); err != nil {
		return nil, err
	}
	packet := new(PacketWithMeta)
	if err := (proto.UnmarshalOptions{RecursionLimit: 16}).Unmarshal(data, packet); err != nil {
		return nil, err
	}
	if len(packet.Data) > maxNativePacketSize {
		return nil, errNativeMessageTooLarge
	}
	return packet, nil
}

// Unmarshal's recursion limit does not cover skipped unknown groups. Scan those
// iteratively before decoding, and apply the same budget inside tunnel metadata.
func validateNativeWire(data []byte, nestedField protowire.Number, budget int) error {
	var groups [16]protowire.Number
	depth := 0
	for len(data) != 0 {
		number, kind, n := protowire.ConsumeTag(data)
		if n < 0 {
			return protowire.ParseError(n)
		}
		data = data[n:]
		switch kind {
		case protowire.StartGroupType:
			if depth == budget {
				return errors.New("native redirector protobuf nesting exceeds limit")
			}
			groups[depth] = number
			depth++
		case protowire.EndGroupType:
			if depth == 0 || groups[depth-1] != number {
				return errors.New("invalid native redirector protobuf group")
			}
			depth--
		default:
			if kind == protowire.BytesType && depth == 0 && number == nestedField {
				body, n := protowire.ConsumeBytes(data)
				if n < 0 {
					return protowire.ParseError(n)
				}
				if err := validateNativeWire(body, 0, budget-1); err != nil {
					return err
				}
				data = data[n:]
			} else {
				n := protowire.ConsumeFieldValue(number, kind, data)
				if n < 0 {
					return protowire.ParseError(n)
				}
				data = data[n:]
			}
		}
	}
	if depth != 0 {
		return errors.New("truncated native redirector protobuf group")
	}
	return nil
}

func encodeNativeProxy(message *FromProxy) ([]byte, error) {
	if message == nil || message.Message == nil {
		return nil, errors.New("native redirector message is missing")
	}
	if len(message.GetPacket().GetData()) > maxNativePacketSize || proto.Size(message) > maxNativeIPCMessageSize {
		return nil, errNativeMessageTooLarge
	}
	return proto.Marshal(message)
}
