// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package imagemeta

import (
	"fmt"
	"strconv"
)

// pngMagic is the signature that starts every PNG file.
var pngMagic = []byte("\x89PNG\r\n\x1a\n")

// ParseICO lists an ICO container's directory the way mitmproxy displays
// it: the image count, then each image's size, bit depth and whether its
// data is an embedded PNG.
func ParseICO(data []byte) ([][2]string, error) {
	s := &stream{data: data}
	if err := s.expect([]byte{0, 0, 1, 0}, "ICO magic"); err != nil {
		return nil, err
	}
	numImages, err := s.u2le()
	if err != nil {
		return nil, err
	}
	parts := [][2]string{
		{"Format", "ICO"},
		{"Number of images", strconv.Itoa(int(numImages))},
	}
	for i := range int(numImages) {
		width, err := s.u1()
		if err != nil {
			return nil, err
		}
		height, err := s.u1()
		if err != nil {
			return nil, err
		}
		if _, err := s.u1(); err != nil { // color count
			return nil, err
		}
		if err := s.expect([]byte{0}, "ICO reserved byte"); err != nil {
			return nil, err
		}
		if _, err := s.u2le(); err != nil { // planes
			return nil, err
		}
		bpp, err := s.u2le()
		if err != nil {
			return nil, err
		}
		if _, err := s.u4le(); err != nil { // image data length
			return nil, err
		}
		offset, err := s.u4le()
		if err != nil {
			return nil, err
		}
		// Upstream pre-reads 8 bytes at the image offset to detect an
		// embedded PNG; a header past the end of the file is an error.
		start := int64(offset)
		if start+8 > int64(len(data)) {
			return nil, errShortRead
		}
		isPNG := "False"
		if string(data[start:start+8]) == string(pngMagic) {
			isPNG = "True"
		}
		parts = append(parts, [2]string{
			fmt.Sprintf("Image %d", i+1),
			fmt.Sprintf("Size: %d x %d\n%18sBits per pixel: %d\n%18sPNG: %s",
				u8OrDefault(width), u8OrDefault(height), "", bpp, "", isPNG),
		})
	}
	return parts, nil
}

// u8OrDefault reads an ICO dimension byte, where zero means 256.
func u8OrDefault(v byte) int {
	if v == 0 {
		return 256
	}
	return int(v)
}
