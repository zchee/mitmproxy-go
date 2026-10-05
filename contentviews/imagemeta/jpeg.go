// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package imagemeta

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// JPEG marker values whose segments carry the metadata mitmproxy displays.
const (
	jpegMarkerSOF0 = 0xc0
	jpegMarkerSOI  = 0xd8
	jpegMarkerEOI  = 0xd9
	jpegMarkerSOS  = 0xda
	jpegMarkerAPP0 = 0xe0
	jpegMarkerAPP1 = 0xe1
	jpegMarkerCOM  = 0xfe
)

// ParseJPEG lists a JPEG image's metadata the way mitmproxy displays it:
// the format, then per segment in file order the JFIF version, density and
// unit, comments, Exif text fields and the pixel size.
func ParseJPEG(data []byte) ([][2]string, error) {
	s := &stream{data: data}
	parts := [][2]string{{"Format", "JPEG (ISO 10918)"}}
	for !s.eof() {
		if err := s.expect([]byte{0xff}, "JPEG segment magic"); err != nil {
			return nil, err
		}
		marker, err := s.u1()
		if err != nil {
			return nil, err
		}
		if !jpegMarkerKnown(marker) {
			// The upstream view fails to name a marker outside its
			// enumeration.
			return nil, fmt.Errorf("JPEG marker %#x is unknown", marker)
		}
		if marker == jpegMarkerSOI || marker == jpegMarkerEOI {
			continue
		}
		length, err := s.u2be()
		if err != nil {
			return nil, err
		}
		if length < 2 {
			return nil, fmt.Errorf("JPEG segment length %d is shorter than its own field", length)
		}
		body, err := s.bytesN(int(length) - 2)
		if err != nil {
			return nil, err
		}
		parts, err = parseJPEGSegment(parts, marker, body)
		if err != nil {
			return nil, err
		}
		if marker == jpegMarkerSOS {
			// The entropy-coded image data after the start-of-scan segment
			// runs to the end of the file.
			s.rest()
		}
	}
	return parts, nil
}

// jpegMarkerKnown reports whether the upstream parser's marker
// enumeration names m: the temporary marker, the start-of-frame group,
// the soi-to-dhp group, the application segments and the comment.
func jpegMarkerKnown(m byte) bool {
	switch {
	case m == 1, m >= 192 && m <= 199, m >= 216 && m <= 222, m >= 224 && m <= 239, m == 254:
		return true
	default:
		return false
	}
}

// parseJPEGSegment validates one segment's body the way the upstream
// parser does and appends the rows the upstream view displays for it.
func parseJPEGSegment(parts [][2]string, marker byte, body []byte) ([][2]string, error) {
	c := &stream{data: body}
	switch marker {
	case jpegMarkerSOF0:
		if _, err := c.u1(); err != nil { // bits per sample
			return nil, err
		}
		height, err := c.u2be()
		if err != nil {
			return nil, err
		}
		width, err := c.u2be()
		if err != nil {
			return nil, err
		}
		components, err := c.u1()
		if err != nil {
			return nil, err
		}
		if _, err := c.bytesN(3 * int(components)); err != nil {
			return nil, err
		}
		return append(parts, [2]string{"Size", fmt.Sprintf("%d x %d px", width, height)}), nil
	case jpegMarkerAPP0:
		magic, err := c.bytesN(5)
		if err != nil {
			return nil, err
		}
		if _, err := asciiText(magic, "JPEG APP0 magic"); err != nil {
			return nil, err
		}
		versionMajor, err := c.u1()
		if err != nil {
			return nil, err
		}
		versionMinor, err := c.u1()
		if err != nil {
			return nil, err
		}
		unit, err := c.u1()
		if err != nil {
			return nil, err
		}
		densityX, err := c.u2be()
		if err != nil {
			return nil, err
		}
		densityY, err := c.u2be()
		if err != nil {
			return nil, err
		}
		thumbnailX, err := c.u1()
		if err != nil {
			return nil, err
		}
		thumbnailY, err := c.u1()
		if err != nil {
			return nil, err
		}
		if _, err := c.bytesN(3 * int(thumbnailX) * int(thumbnailY)); err != nil {
			return nil, err
		}
		parts = append(parts,
			[2]string{"jfif_version", fmt.Sprintf("(%d, %d)", versionMajor, versionMinor)},
			[2]string{"jfif_density", fmt.Sprintf("(%d, %d)", densityX, densityY)},
		)
		if unit > 2 {
			// The upstream view fails to take the value of a density unit
			// outside its enumeration.
			return nil, fmt.Errorf("JPEG density unit %d is unknown", unit)
		}
		return append(parts, [2]string{"jfif_unit", strconv.Itoa(int(unit))}), nil
	case jpegMarkerAPP1:
		magicBytes, err := c.terminated()
		if err != nil {
			return nil, err
		}
		magic, err := asciiText(magicBytes, "JPEG APP1 magic")
		if err != nil {
			return nil, err
		}
		if magic != "Exif" {
			return parts, nil
		}
		if err := c.expect([]byte{0}, "JPEG Exif padding"); err != nil {
			return nil, err
		}
		return appendExifRows(parts, c.rest())
	case jpegMarkerSOS:
		components, err := c.u1()
		if err != nil {
			return nil, err
		}
		if _, err := c.bytesN(2 * int(components)); err != nil {
			return nil, err
		}
		// Spectral selection bounds and successive approximation.
		_, err = c.bytesN(3)
		return parts, err
	case jpegMarkerCOM:
		return append(parts, [2]string{"comment", utf8BackslashReplace(body)}), nil
	default:
		return parts, nil
	}
}

// appendExifRows parses the TIFF structure of an Exif APP1 segment and
// appends one row per first-IFD field whose value lives outside the field
// record, named by upstream's tag table.
func appendExifRows(parts [][2]string, tiff []byte) ([][2]string, error) {
	s := &stream{data: tiff}
	endianness, err := s.u2le()
	if err != nil {
		return nil, err
	}
	var bo binary.ByteOrder
	switch endianness {
	case 0x4949:
		bo = binary.LittleEndian
	case 0x4d4d:
		bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("unknown Exif endianness %#x", endianness)
	}
	if _, err := s.u2(bo); err != nil { // version
		return nil, err
	}
	ifdOffset, err := s.u4(bo)
	if err != nil {
		return nil, err
	}
	if int64(ifdOffset) > int64(len(tiff)) {
		return nil, errShortRead
	}
	s.pos = int(ifdOffset)
	numFields, err := s.u2(bo)
	if err != nil {
		return nil, err
	}
	type ifdField struct {
		tag  uint16
		data []byte
	}
	fields := make([]ifdField, 0, min(int(numFields), 256))
	for range int(numFields) {
		tag, err := s.u2(bo)
		if err != nil {
			return nil, err
		}
		fieldType, err := s.u2(bo)
		if err != nil {
			return nil, err
		}
		length, err := s.u4(bo)
		if err != nil {
			return nil, err
		}
		offset, err := s.u4(bo)
		if err != nil {
			return nil, err
		}
		// Upstream multiplies the count by the type's size only for the
		// two-byte and four-byte integer types; every other type counts
		// one byte per element.
		unit := uint64(1)
		switch fieldType {
		case 3:
			unit = 2
		case 4:
			unit = 4
		}
		byteLength := uint64(length) * unit
		if byteLength <= 4 {
			// The value fits inside the field record; the upstream view
			// skips it without looking at the tag.
			continue
		}
		if uint64(offset)+byteLength > uint64(len(tiff)) {
			return nil, errShortRead
		}
		fields = append(fields, ifdField{tag, tiff[offset : uint64(offset)+byteLength]})
	}
	if _, err := s.u4(bo); err != nil { // next IFD offset
		return nil, err
	}
	for _, field := range fields {
		name, ok := exifTagNames[field.tag]
		if !ok {
			// The upstream view fails to name a tag outside its table.
			return nil, fmt.Errorf("unknown Exif tag %d", field.tag)
		}
		text, err := utf8Text(field.data, "Exif field value")
		if err != nil {
			return nil, err
		}
		parts = append(parts, [2]string{name, strings.Trim(text, "\x00")})
	}
	return parts, nil
}
