// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

// Match the default maximum of upstream's tokio LengthDelimitedCodec.
const maxIPCMessageSize = 8 << 20

var errIPCMessageTooLarge = errors.New("redirector IPC message exceeds size limit")

func readIPC(reader io.Reader, message proto.Message) error {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return fmt.Errorf("read IPC length: %w", err)
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length > maxIPCMessageSize {
		return fmt.Errorf("%w: %d bytes", errIPCMessageTooLarge, length)
	}
	// Grow only as bytes arrive, never by a peer's declared length alone.
	payload, err := io.ReadAll(io.LimitReader(reader, int64(length)))
	if err != nil {
		return fmt.Errorf("read IPC payload: %w", err)
	}
	if uint64(len(payload)) != uint64(length) {
		return fmt.Errorf("read IPC payload: %w", io.ErrUnexpectedEOF)
	}
	if err := (proto.UnmarshalOptions{RecursionLimit: 16}).Unmarshal(payload, message); err != nil {
		return fmt.Errorf("decode IPC payload: %w", err)
	}
	return nil
}

func writeIPC(writer io.Writer, message proto.Message) error {
	if size := proto.Size(message); size > maxIPCMessageSize {
		return fmt.Errorf("%w: %d bytes", errIPCMessageTooLarge, size)
	}
	payload, err := proto.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode IPC payload: %w", err)
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
	if _, err := io.Copy(writer, bytes.NewReader(prefix[:])); err != nil {
		return fmt.Errorf("write IPC length: %w", err)
	}
	if _, err := io.Copy(writer, bytes.NewReader(payload)); err != nil {
		return fmt.Errorf("write IPC payload: %w", err)
	}
	return nil
}
