// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package imagemeta extracts the display metadata of PNG, GIF, JPEG and
// ICO images, reading exactly the fields mitmproxy's parsers read.
package imagemeta

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// errShortRead reports a field that extends past the end of its data.
var errShortRead = errors.New("image data ends inside a field")

// stream reads binary fields from a byte slice, as the upstream parsers'
// stream reader does: every read past the end is an error, and seeking is
// explicit.
type stream struct {
	data []byte
	pos  int
}

// bytesN returns the next n bytes. A negative or too-large n is an error.
func (s *stream) bytesN(n int) ([]byte, error) {
	if n < 0 || n > len(s.data)-s.pos {
		return nil, errShortRead
	}
	out := s.data[s.pos : s.pos+n]
	s.pos += n
	return out, nil
}

// rest returns the bytes from the current position to the end.
func (s *stream) rest() []byte {
	out := s.data[s.pos:]
	s.pos = len(s.data)
	return out
}

// eof reports whether the stream is exhausted.
func (s *stream) eof() bool { return s.pos >= len(s.data) }

// terminated returns the bytes before the next NUL and consumes the
// terminator. A missing terminator is an error, as upstream's
// read_bytes_term(0, false, true, true) has it.
func (s *stream) terminated() ([]byte, error) {
	for i := s.pos; i < len(s.data); i++ {
		if s.data[i] == 0 {
			out := s.data[s.pos:i]
			s.pos = i + 1
			return out, nil
		}
	}
	return nil, errShortRead
}

func (s *stream) u1() (byte, error) {
	b, err := s.bytesN(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (s *stream) u2be() (uint16, error) {
	b, err := s.bytesN(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (s *stream) u4be() (uint32, error) {
	b, err := s.bytesN(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (s *stream) u2le() (uint16, error) {
	b, err := s.bytesN(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (s *stream) u4le() (uint32, error) {
	b, err := s.bytesN(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// u2 reads an unsigned 16-bit integer in the byte order bo.
func (s *stream) u2(bo binary.ByteOrder) (uint16, error) {
	b, err := s.bytesN(2)
	if err != nil {
		return 0, err
	}
	return bo.Uint16(b), nil
}

// u4 reads an unsigned 32-bit integer in the byte order bo.
func (s *stream) u4(bo binary.ByteOrder) (uint32, error) {
	b, err := s.bytesN(4)
	if err != nil {
		return 0, err
	}
	return bo.Uint32(b), nil
}

// expect consumes len(want) bytes and requires them to equal want, as
// upstream's contents validation does.
func (s *stream) expect(want []byte, what string) error {
	got, err := s.bytesN(len(want))
	if err != nil {
		return err
	}
	if string(got) != string(want) {
		return fmt.Errorf("%s is %q, not %q", what, got, want)
	}
	return nil
}
