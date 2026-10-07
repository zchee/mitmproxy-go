// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

const (
	frameData        uint64 = 0
	frameHeaders     uint64 = 1
	frameCancelPush  uint64 = 3
	frameSettings    uint64 = 4
	framePushPromise uint64 = 5
	frameGoAway      uint64 = 7
	frameMaxPushID   uint64 = 13
	maxSettingsSize         = 8 << 10
	maxQUICVarint    uint64 = (1 << 62) - 1
)

type frame struct {
	kind     uint64
	length   uint64
	id       uint64
	settings map[uint64]uint64
}

// Dispatch follows quic-go's MIT-licensed http3/frames.go without converting
// ordered headers into net/http values. Body payloads remain with their owner.
func readFrame(reader io.Reader) (frame, error) {
	for {
		kind, err := readVarint(reader)
		if err != nil {
			return frame{}, err
		}
		length, err := readVarint(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return frame{}, err
		}
		parsed := frame{kind: kind, length: length}
		switch kind {
		case frameData, framePushPromise:
			return parsed, nil
		case frameHeaders:
			if length > MaxHeaderBytes {
				return frame{}, connectionError(ErrCodeExcessiveLoad, "encoded field section exceeds header limit")
			}
			return parsed, nil
		case frameSettings:
			payload, err := readPayload(reader, length, maxSettingsSize)
			if err != nil {
				return frame{}, err
			}
			parsed.settings, err = parseSettings(payload)
			return parsed, err
		case frameGoAway, frameCancelPush, frameMaxPushID:
			if length == 0 || length > 8 {
				return frame{}, connectionError(ErrCodeFrameError, "identifier frame has inconsistent length")
			}
			payload, err := readPayload(reader, length, 8)
			if err != nil {
				return frame{}, err
			}
			buffer := bytes.NewReader(payload)
			parsed.id, err = readVarint(buffer)
			if err != nil || buffer.Len() != 0 {
				return frame{}, connectionError(ErrCodeFrameError, "identifier frame has inconsistent length")
			}
			return parsed, nil
		case 2, 6, 8, 9:
			return frame{}, connectionError(ErrCodeFrameUnexpected, fmt.Sprintf("reserved frame type %d", kind))
		default:
			if _, err := io.CopyN(io.Discard, reader, int64(length)); err != nil {
				if errors.Is(err, io.EOF) {
					err = io.ErrUnexpectedEOF
				}
				return frame{}, err
			}
		}
	}
}

func readPayload(reader io.Reader, length, limit uint64) ([]byte, error) {
	if length > limit {
		return nil, connectionError(ErrCodeExcessiveLoad, "frame payload exceeds limit")
	}
	// Grow from bytes actually received, not from the peer's length prefix.
	payload, err := io.ReadAll(io.LimitReader(reader, int64(length)))
	if err != nil {
		return nil, err
	}
	if uint64(len(payload)) != length {
		return nil, connectionError(ErrCodeFrameError, "truncated frame payload")
	}
	return payload, nil
}

func parseSettings(payload []byte) (map[uint64]uint64, error) {
	settings := make(map[uint64]uint64)
	reader := bytes.NewReader(payload)
	for reader.Len() > 0 {
		id, err := readVarint(reader)
		if err != nil {
			return nil, connectionError(ErrCodeFrameError, "truncated setting identifier")
		}
		value, err := readVarint(reader)
		if err != nil {
			return nil, connectionError(ErrCodeFrameError, "truncated setting value")
		}
		if _, exists := settings[id]; exists {
			return nil, connectionError(ErrCodeSettingsError, fmt.Sprintf("duplicate setting %d", id))
		}
		if id >= 2 && id <= 5 {
			return nil, connectionError(ErrCodeSettingsError, fmt.Sprintf("reserved setting %d", id))
		}
		if (id == 8 || id == 0x33) && value > 1 {
			return nil, connectionError(ErrCodeSettingsError, fmt.Sprintf("invalid boolean setting %d", id))
		}
		settings[id] = value
	}
	return settings, nil
}

func connectionError(code ErrorCode, message string) error {
	return &ConnectionError{Code: code, Message: message}
}

func readQPACKInstruction(reader io.Reader, encoder bool) error {
	var first [1]byte
	if _, err := io.ReadFull(reader, first[:]); err != nil {
		return err
	}
	code := ErrCodeQPACKDecoderStreamError
	prefix := uint8(6)
	if encoder {
		code = ErrCodeQPACKEncoderStreamError
		prefix = 5
		if first[0]&0xe0 != 0x20 {
			return connectionError(code, "dynamic insertion on zero-capacity table")
		}
	} else if first[0]&0xc0 != 0x40 {
		return connectionError(code, "unexpected acknowledgement or insert count increment")
	}
	value, err := readPrefixedInteger(reader, first[0], prefix)
	if err != nil {
		return connectionError(code, "malformed instruction integer")
	}
	if encoder && value != 0 {
		return connectionError(code, "nonzero dynamic table capacity")
	}
	return nil
}

func readPrefixedInteger(reader io.Reader, first byte, prefix uint8) (uint64, error) {
	mask := uint64(1<<prefix) - 1
	value := uint64(first) & mask
	if value < mask {
		return value, nil
	}
	var octet [1]byte
	for shift := uint(0); shift < 63; shift += 7 {
		if _, err := io.ReadFull(reader, octet[:]); err != nil {
			return 0, err
		}
		part := uint64(octet[0] & 0x7f)
		if part > (maxQUICVarint-value)>>shift {
			return 0, errors.New("h3: instruction integer exceeds 62 bits")
		}
		value += part << shift
		if octet[0]&0x80 == 0 {
			return value, nil
		}
	}
	return 0, errors.New("h3: instruction integer exceeds 62 bits")
}

func writeFrame(writer io.Writer, kind uint64, payload []byte) error {
	head := appendVarint(nil, kind)
	head = appendVarint(head, uint64(len(payload)))
	if _, err := writer.Write(head); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}
