// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package imagemeta

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"

	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

// ztxtDecompressLimit caps the decompressed size of a zTXt chunk's text, so
// a small body cannot expand without bound. Upstream decompresses without a
// limit; the difference is recorded in docs/compat.md.
const ztxtDecompressLimit = 64 << 20

// ParsePNG lists a PNG image's metadata the way mitmproxy displays it: the
// format and pixel size, then the gamma, physical-dimension, textual and
// compressed-textual chunks in file order.
func ParsePNG(data []byte) ([][2]string, error) {
	s := &stream{data: data}
	if err := s.expect(pngMagic, "PNG magic"); err != nil {
		return nil, err
	}
	ihdrLen, err := s.u4be()
	if err != nil {
		return nil, err
	}
	if ihdrLen != 13 {
		return nil, fmt.Errorf("PNG IHDR length is %d, not 13", ihdrLen)
	}
	if err := s.expect([]byte("IHDR"), "PNG first chunk type"); err != nil {
		return nil, err
	}
	width, err := s.u4be()
	if err != nil {
		return nil, err
	}
	height, err := s.u4be()
	if err != nil {
		return nil, err
	}
	// Bit depth, color type, compression method, filter method, interlace
	// method; only the color type matters, for the bKGD chunk's layout.
	ihdrTail, err := s.bytesN(5)
	if err != nil {
		return nil, err
	}
	colorType := ihdrTail[1]
	if _, err := s.bytesN(4); err != nil { // IHDR checksum
		return nil, err
	}
	parts := [][2]string{
		{"Format", "Portable network graphics"},
		{"Size", fmt.Sprintf("%d x %d px", width, height)},
	}
	// Upstream parses chunks with do-while semantics: at least one chunk
	// must follow the image header, and the loop ends after an IEND chunk
	// or at the end of the data.
	for {
		length, err := s.u4be()
		if err != nil {
			return nil, err
		}
		typBytes, err := s.bytesN(4)
		if err != nil {
			return nil, err
		}
		typ, err := utf8Text(typBytes, "PNG chunk type")
		if err != nil {
			return nil, err
		}
		if int64(length) > int64(len(s.data)-s.pos) {
			return nil, errShortRead
		}
		body, err := s.bytesN(int(length))
		if err != nil {
			return nil, err
		}
		if _, err := s.bytesN(4); err != nil { // chunk checksum
			return nil, err
		}
		parts, err = parsePNGChunk(parts, typ, body, colorType)
		if err != nil {
			return nil, err
		}
		if typ == "IEND" || s.eof() {
			break
		}
	}
	return parts, nil
}

// parsePNGChunk validates one chunk's body the way the upstream parser
// does and appends the rows the upstream view displays for it.
func parsePNGChunk(parts [][2]string, typ string, body []byte, colorType byte) ([][2]string, error) {
	c := &stream{data: body}
	switch typ {
	case "iTXt":
		keywordBytes, err := c.terminated()
		if err != nil {
			return nil, err
		}
		keyword, err := utf8Text(keywordBytes, "PNG iTXt keyword")
		if err != nil {
			return nil, err
		}
		if _, err := c.bytesN(2); err != nil { // compression flag and method
			return nil, err
		}
		language, err := c.terminated()
		if err != nil {
			return nil, err
		}
		if _, err := asciiText(language, "PNG iTXt language tag"); err != nil {
			return nil, err
		}
		translated, err := c.terminated()
		if err != nil {
			return nil, err
		}
		if _, err := utf8Text(translated, "PNG iTXt translated keyword"); err != nil {
			return nil, err
		}
		text, err := utf8Text(c.rest(), "PNG iTXt text")
		if err != nil {
			return nil, err
		}
		return append(parts, [2]string{keyword, text}), nil
	case "gAMA":
		gamma, err := c.u4be()
		if err != nil {
			return nil, err
		}
		return append(parts, [2]string{"gamma", pyrepr.Value(float64(gamma) / 100000)}), nil
	case "tIME":
		_, err := c.bytesN(7)
		return parts, err
	case "PLTE":
		for !c.eof() {
			if _, err := c.bytesN(3); err != nil {
				return nil, err
			}
		}
		return parts, nil
	case "bKGD":
		var err error
		switch colorType {
		case 0, 4: // greyscale, with or without alpha
			_, err = c.bytesN(2)
		case 2, 6: // truecolor, with or without alpha
			_, err = c.bytesN(6)
		case 3: // indexed
			_, err = c.bytesN(1)
		}
		return parts, err
	case "pHYs":
		x, err := c.u4be()
		if err != nil {
			return nil, err
		}
		y, err := c.u4be()
		if err != nil {
			return nil, err
		}
		if _, err := c.u1(); err != nil { // unit
			return nil, err
		}
		return append(parts, [2]string{"aspect", fmt.Sprintf("%d x %d", x, y)}), nil
	case "fdAT":
		_, err := c.u4be() // sequence number
		return parts, err
	case "tEXt":
		keyword, err := c.terminated()
		if err != nil {
			return nil, err
		}
		return append(parts, [2]string{latin1(keyword), latin1(c.rest())}), nil
	case "cHRM":
		_, err := c.bytesN(32)
		return parts, err
	case "acTL":
		_, err := c.bytesN(8)
		return parts, err
	case "sRGB":
		_, err := c.u1()
		return parts, err
	case "zTXt":
		keywordBytes, err := c.terminated()
		if err != nil {
			return nil, err
		}
		keyword, err := utf8Text(keywordBytes, "PNG zTXt keyword")
		if err != nil {
			return nil, err
		}
		if _, err := c.u1(); err != nil { // compression method
			return nil, err
		}
		text, err := inflate(c.rest())
		if err != nil {
			return nil, fmt.Errorf("PNG zTXt text: %w", err)
		}
		return append(parts, [2]string{keyword, latin1(text)}), nil
	case "fcTL":
		_, err := c.bytesN(26)
		return parts, err
	default:
		return parts, nil
	}
}

// inflate decompresses a zlib stream, refusing output beyond
// ztxtDecompressLimit.
func inflate(compressed []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(io.LimitReader(r, ztxtDecompressLimit+1))
	if closeErr := r.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if len(out) > ztxtDecompressLimit {
		return nil, fmt.Errorf("decompressed text exceeds %d bytes", ztxtDecompressLimit)
	}
	return out, nil
}
