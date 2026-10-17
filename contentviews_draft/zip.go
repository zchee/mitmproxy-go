// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	yaml "go.yaml.in/yaml/v4"
	"golang.org/x/text/encoding/charmap"

	"github.com/zchee/mitmproxy-go/contentviews"
)

// ZIP displays archive filenames without opening or extracting entries.
type ZIP struct{ yaml yamlCodec }

// Name returns the view's selection name.
func (ZIP) Name() string { return "ZIP Archive" }

// SyntaxHighlight returns the renderer's syntax name.
func (ZIP) SyntaxHighlight() string { return "yaml" }

// RenderPriority selects nonempty ZIP media types.
func (ZIP) RenderPriority(data []byte, metadata contentviews.Metadata) float64 {
	if len(data) != 0 && metadata.ContentType == "application/zip" {
		return 1
	}
	return 0
}

// Prettify validates central-directory bounds before constructing a ZIP reader.
func (v ZIP) Prettify(data []byte, _ contentviews.Metadata) (string, error) {
	budget := &viewBudget{view: "ZIP"}
	names, err := zipNames(data, budget, zip.NewReader)
	if err != nil {
		return "", err
	}
	if len(names.Content) == 0 {
		return "(empty zip file)", nil
	}
	if v.yaml == nil {
		return "", fmt.Errorf("ZIP YAML adapter is not configured")
	}
	return v.yaml.Dump(names, budget)
}

func zipNames(data []byte, budget *viewBudget, construct func(io.ReaderAt, int64) (*zip.Reader, error)) (*yaml.Node, error) {
	count, err := preflightZIP(data, budget)
	if err != nil {
		return nil, err
	}
	reader, err := construct(bytes.NewReader(data), int64(len(data)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return nil, err
	}
	if reader == nil || len(reader.File) != count {
		return nil, fmt.Errorf("ZIP reader disagrees with directory preflight")
	}
	if err := budget.reserveNodes(1, "YAML sequence"); err != nil {
		return nil, err
	}
	root := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, file := range reader.File {
		if err := budget.reserveNodes(1, "filename node"); err != nil {
			return nil, err
		}
		name := file.Name
		if file.Flags&0x800 == 0 {
			var decoded strings.Builder
			for i := range len(name) {
				decoded.WriteRune(charmap.CodePage437.DecodeByte(name[i]))
			}
			name = decoded.String()
		}
		node := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}
		if strings.ContainsRune(name, '\n') {
			node.Style = yaml.DoubleQuotedStyle
		}
		root.Content = append(root.Content, node)
	}
	return root, nil
}

func preflightZIP(data []byte, budget *viewBudget) (int, error) {
	if len(data) > maxViewBytes {
		return 0, &LimitError{View: "ZIP", Stage: "directory", Bound: "input bytes"}
	}
	end := -1
	for i := len(data) - 22; i >= max(0, len(data)-65*1024); i-- {
		if binary.LittleEndian.Uint32(data[i:i+4]) == 0x06054b50 {
			if int(binary.LittleEndian.Uint16(data[i+20:i+22])) > len(data)-i-22 {
				return 0, fmt.Errorf("truncated ZIP comment")
			}
			end = i
			break
		}
	}
	if end < 0 {
		return 0, fmt.Errorf("missing ZIP end record")
	}
	if binary.LittleEndian.Uint16(data[end+4:end+6]) != 0 || binary.LittleEndian.Uint16(data[end+6:end+8]) != 0 {
		return 0, fmt.Errorf("multidisk ZIP is not supported")
	}
	records := uint64(binary.LittleEndian.Uint16(data[end+10 : end+12]))
	if uint64(binary.LittleEndian.Uint16(data[end+8:end+10])) != records {
		return 0, fmt.Errorf("inconsistent ZIP directory counts")
	}
	size := uint64(binary.LittleEndian.Uint32(data[end+12 : end+16]))
	offset := uint64(binary.LittleEndian.Uint32(data[end+16 : end+20]))
	if records == 0xffff || size == 0xffffffff || offset == 0xffffffff {
		if end < 20 || binary.LittleEndian.Uint32(data[end-20:end-16]) != 0x07064b50 {
			return 0, fmt.Errorf("missing ZIP64 locator")
		}
		if binary.LittleEndian.Uint32(data[end-16:end-12]) != 0 || binary.LittleEndian.Uint32(data[end-4:end]) != 1 {
			return 0, fmt.Errorf("multidisk ZIP64 is not supported")
		}
		position := binary.LittleEndian.Uint64(data[end-12 : end-4])
		if position > uint64(end-20) || uint64(end-20)-position < 56 {
			return 0, fmt.Errorf("invalid ZIP64 end offset")
		}
		p := int(position)
		if binary.LittleEndian.Uint32(data[p:p+4]) != 0x06064b50 {
			return 0, fmt.Errorf("invalid ZIP64 end signature")
		}
		length := binary.LittleEndian.Uint64(data[p+4 : p+12])
		if length < 44 || length > uint64(end-20-p-12) {
			return 0, fmt.Errorf("invalid ZIP64 end length")
		}
		if binary.LittleEndian.Uint32(data[p+16:p+20]) != 0 || binary.LittleEndian.Uint32(data[p+20:p+24]) != 0 {
			return 0, fmt.Errorf("multidisk ZIP64 is not supported")
		}
		records = binary.LittleEndian.Uint64(data[p+32 : p+40])
		if binary.LittleEndian.Uint64(data[p+24:p+32]) != records {
			return 0, fmt.Errorf("inconsistent ZIP64 directory counts")
		}
		size = binary.LittleEndian.Uint64(data[p+40 : p+48])
		offset = binary.LittleEndian.Uint64(data[p+48 : p+56])
		end = p
	}
	if size > uint64(end) || offset > uint64(len(data)) {
		return 0, fmt.Errorf("invalid ZIP directory range")
	}
	start := end - int(size)
	if uint64(start) > offset {
		if _, _, err := zipDirectoryEntry(data, int(offset), end); err == nil {
			start = int(offset)
		}
	}
	count, metadataBytes := 0, 0
	position := start
	for position+4 <= end && binary.LittleEndian.Uint32(data[position:position+4]) == 0x02014b50 {
		next, decodedBytes, err := zipDirectoryEntry(data, position, end)
		if err != nil {
			return 0, err
		}
		if err := budget.reserveNodes(1, "directory entry"); err != nil {
			return 0, err
		}
		if err := budget.reserveScalar(decodedBytes); err != nil {
			return 0, err
		}
		metadataBytes += next - position
		if metadataBytes > maxViewBytes {
			return 0, &LimitError{View: "ZIP", Stage: "directory", Bound: "metadata bytes"}
		}
		count++
		position = next
	}
	if position+6 <= end && binary.LittleEndian.Uint32(data[position:position+4]) == 0x05054b50 {
		length := int(binary.LittleEndian.Uint16(data[position+4 : position+6]))
		if length > end-position-6 {
			return 0, fmt.Errorf("truncated ZIP directory signature")
		}
		position += 6 + length
	}
	if position-start != int(size) || uint64(count) != records {
		return 0, fmt.Errorf("ZIP directory size or entry count mismatch")
	}
	return count, nil
}

func zipDirectoryEntry(data []byte, offset, end int) (int, int, error) {
	if offset < 0 || end-offset < 46 || binary.LittleEndian.Uint32(data[offset:offset+4]) != 0x02014b50 {
		return 0, 0, fmt.Errorf("truncated ZIP directory header")
	}
	header := data[offset : offset+46]
	nameLength := int(binary.LittleEndian.Uint16(header[28:30]))
	extraLength := int(binary.LittleEndian.Uint16(header[30:32]))
	commentLength := int(binary.LittleEndian.Uint16(header[32:34]))
	length := 46 + nameLength + extraLength + commentLength
	if length > end-offset {
		return 0, 0, fmt.Errorf("truncated ZIP directory metadata")
	}
	name := data[offset+46 : offset+46+nameLength]
	decodedBytes := len(name)
	if binary.LittleEndian.Uint16(header[8:10])&0x800 != 0 {
		if !utf8.Valid(name) {
			return 0, 0, fmt.Errorf("invalid UTF-8 ZIP filename")
		}
	} else {
		decodedBytes = 0
		for _, b := range name {
			decodedBytes += utf8.RuneLen(charmap.CodePage437.DecodeByte(b))
		}
	}
	extra := data[offset+46+nameLength : offset+46+nameLength+extraLength]
	for len(extra) >= 4 {
		tag := binary.LittleEndian.Uint16(extra[:2])
		size := int(binary.LittleEndian.Uint16(extra[2:4]))
		extra = extra[4:]
		if size > len(extra) {
			return 0, 0, fmt.Errorf("truncated ZIP extra field")
		}
		if tag == 1 {
			required := 0
			for _, start := range []int{20, 24, 42} {
				if binary.LittleEndian.Uint32(header[start:start+4]) == 0xffffffff {
					required += 8
				}
			}
			if required > size {
				return 0, 0, fmt.Errorf("truncated ZIP64 extra field")
			}
		}
		extra = extra[size:]
	}
	return offset + length, decodedBytes, nil
}
