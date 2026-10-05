// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package imagemeta

import (
	"fmt"
	"strconv"

	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

// GIF block and extension-label values the upstream parser knows; any
// other value makes the upstream view fail when it asks for the name.
const (
	gifBlockExtension      = 0x21
	gifBlockLocalImage     = 0x2c
	gifBlockEndOfFile      = 0x3b
	gifLabelGraphicControl = 0xf9
	gifLabelComment        = 0xfe
	gifLabelApplication    = 0xff
)

// ParseGIF lists a GIF image's metadata the way mitmproxy displays it: the
// format, version, screen size and background color index, then the bytes
// of every comment extension in file order, written as Python shows a
// bytes object.
func ParseGIF(data []byte) ([][2]string, error) {
	s := &stream{data: data}
	if err := s.expect([]byte("GIF"), "GIF magic"); err != nil {
		return nil, err
	}
	versionBytes, err := s.bytesN(3)
	if err != nil {
		return nil, err
	}
	version, err := asciiText(versionBytes, "GIF version")
	if err != nil {
		return nil, err
	}
	width, err := s.u2le()
	if err != nil {
		return nil, err
	}
	height, err := s.u2le()
	if err != nil {
		return nil, err
	}
	flags, err := s.u1()
	if err != nil {
		return nil, err
	}
	background, err := s.u1()
	if err != nil {
		return nil, err
	}
	if _, err := s.u1(); err != nil { // pixel aspect ratio
		return nil, err
	}
	if flags&0x80 != 0 {
		if _, err := s.bytesN((2 << (flags & 7)) * 3); err != nil { // global color table
			return nil, err
		}
	}
	parts := [][2]string{
		{"Format", "Compuserve GIF"},
		{"Version", "GIF" + version},
		{"Size", fmt.Sprintf("%d x %d px", width, height)},
		{"background", strconv.Itoa(int(background))},
	}
	// Upstream parses blocks with do-while semantics: at least one block
	// must follow the screen descriptor, and the loop ends after the
	// trailer block or at the end of the data.
	for {
		blockType, err := s.u1()
		if err != nil {
			return nil, err
		}
		switch blockType {
		case gifBlockExtension:
			parts, err = parseGIFExtension(parts, s)
			if err != nil {
				return nil, err
			}
		case gifBlockLocalImage:
			if _, err := s.bytesN(8); err != nil { // left, top, width, height
				return nil, err
			}
			localFlags, err := s.u1()
			if err != nil {
				return nil, err
			}
			if localFlags&0x80 != 0 {
				if _, err := s.bytesN((2 << (localFlags & 7)) * 3); err != nil { // local color table
					return nil, err
				}
			}
			if _, err := s.u1(); err != nil { // LZW minimum code size
				return nil, err
			}
			if _, err := gifSubblocks(s); err != nil {
				return nil, err
			}
		case gifBlockEndOfFile:
			return parts, nil
		default:
			return nil, fmt.Errorf("GIF block type %#x is unknown", blockType)
		}
		if s.eof() {
			return parts, nil
		}
	}
}

// parseGIFExtension reads one extension block and appends the comment rows
// the upstream view displays for it.
func parseGIFExtension(parts [][2]string, s *stream) ([][2]string, error) {
	label, err := s.u1()
	if err != nil {
		return nil, err
	}
	switch label {
	case gifLabelGraphicControl:
		if err := s.expect([]byte{4}, "GIF graphic control block size"); err != nil {
			return nil, err
		}
		if _, err := s.bytesN(4); err != nil { // flags, delay, transparent index
			return nil, err
		}
		if err := s.expect([]byte{0}, "GIF graphic control terminator"); err != nil {
			return nil, err
		}
		return parts, nil
	case gifLabelComment:
		entries, err := gifSubblocks(s)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if len(entry) > 0 {
				parts = append(parts, [2]string{"comment", pyrepr.Bytes(entry)})
			}
		}
		return parts, nil
	case gifLabelApplication:
		if err := s.expect([]byte{11}, "GIF application identifier length"); err != nil {
			return nil, err
		}
		identifier, err := s.bytesN(8)
		if err != nil {
			return nil, err
		}
		if _, err := asciiText(identifier, "GIF application identifier"); err != nil {
			return nil, err
		}
		if _, err := s.bytesN(3); err != nil { // authentication code
			return nil, err
		}
		_, err = gifSubblocks(s)
		return parts, err
	default:
		// The upstream parser falls back to reading subblocks, and its view
		// then fails to name the unknown label.
		if _, err := gifSubblocks(s); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("GIF extension label %#x is unknown", label)
	}
}

// gifSubblocks reads length-prefixed subblocks up to the empty terminator
// and returns their bytes.
func gifSubblocks(s *stream) ([][]byte, error) {
	var entries [][]byte
	for {
		n, err := s.u1()
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return entries, nil
		}
		entry, err := s.bytesN(int(n))
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
}
