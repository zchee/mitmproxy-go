// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/net/idna"
)

const (
	maxWireSize    = 65535
	maxDecodedSize = 1 << 20
)

type limitError struct {
	resource string
	limit    int
}

func (e *limitError) Error() string {
	return fmt.Sprintf("DNS %s exceeds limit of %d bytes", e.resource, e.limit)
}

// Pack converts message to uncompressed DNS wire bytes, preserving opaque RDATA.
// It does not mutate message. Invalid fields, labels or a message exceeding the
// 65,535-byte TCP framing limit return an error.
func Pack(message *Message) ([]byte, error) {
	data, err := packHeader(message)
	if err != nil {
		return nil, err
	}
	for i, q := range message.Questions {
		name, err := packName(q.Name)
		if err != nil {
			return nil, fmt.Errorf("question #%d: %w", i, err)
		}
		if q.Type < 0 || q.Type > 65535 || q.Class < 0 || q.Class > 65535 {
			return nil, fmt.Errorf("question #%d: type or class out of bounds", i)
		}
		if len(name)+4 > maxWireSize-len(data) {
			return nil, &limitError{resource: "wire message", limit: maxWireSize}
		}
		data = append(data, name...)
		data = binary.BigEndian.AppendUint16(data, uint16(q.Type))
		data = binary.BigEndian.AppendUint16(data, uint16(q.Class))
	}
	for _, section := range [][]ResourceRecord{message.Answers, message.Authorities, message.Additionals} {
		for i, r := range section {
			name, err := packName(r.Name)
			if err != nil {
				return nil, fmt.Errorf("record #%d: %w", i, err)
			}
			if len(r.Data) > maxWireSize {
				return nil, &limitError{resource: "record data", limit: maxWireSize}
			}
			if r.Type < 0 || r.Type > 65535 || r.Class < 0 || r.Class > 65535 || r.TTL < 0 || uint64(r.TTL) > 0xffffffff {
				return nil, fmt.Errorf("record #%d: field out of bounds", i)
			}
			if len(name)+10+len(r.Data) > maxWireSize-len(data) {
				return nil, &limitError{resource: "wire message", limit: maxWireSize}
			}
			data = append(data, name...)
			data = binary.BigEndian.AppendUint16(data, uint16(r.Type))
			data = binary.BigEndian.AppendUint16(data, uint16(r.Class))
			data = binary.BigEndian.AppendUint32(data, uint32(r.TTL))
			data = binary.BigEndian.AppendUint16(data, uint16(len(r.Data)))
			data = append(data, r.Data...)
		}
	}
	return data, nil
}

// Unpack decodes exactly one whole DNS message. It returns owned data and copies
// timestamp when present. Malformed names, lengths or trailing bytes return an
// error. Wire bytes are capped at 65,535 and decoded names/RDATA at 1 MiB; pointer
// traversal is iterative, backward-only and limited to 1 MiB of inspected bytes.
func Unpack(data []byte, timestamp *float64) (*Message, error) {
	if len(data) > maxWireSize {
		return nil, &limitError{resource: "wire message", limit: maxWireSize}
	}
	decoder := nameDecoder{data: data, remaining: maxDecodedSize, work: maxDecodedSize, cache: make(map[int]nameResult)}
	message, err := unpackHeader(data)
	if err != nil {
		return nil, err
	}
	if timestamp != nil {
		message.Timestamp = new(*timestamp)
	}
	message.Questions = []Question{}
	message.Answers, message.Authorities, message.Additionals = []ResourceRecord{}, []ResourceRecord{}, []ResourceRecord{}
	offset := 12
	for i := range int(binary.BigEndian.Uint16(data[4:])) {
		name, end, err := decoder.unpack(offset, true)
		if err != nil {
			return nil, fmt.Errorf("question #%d: %w", i, err)
		}
		if len(data)-end < 4 {
			return nil, fmt.Errorf("question #%d: unpack requires a buffer of 4 bytes", i)
		}
		message.Questions = append(message.Questions, Question{Name: name, Type: int(binary.BigEndian.Uint16(data[end:])), Class: int(binary.BigEndian.Uint16(data[end+2:]))})
		offset = end + 4
	}
	for i, section := range []*[]ResourceRecord{&message.Answers, &message.Authorities, &message.Additionals} {
		sectionName := []string{"answer", "authority", "additional"}[i]
		for j := range int(binary.BigEndian.Uint16(data[6+i*2:])) {
			r, end, err := unpackRecord(&decoder, offset)
			if err != nil {
				return nil, fmt.Errorf("%s #%d: %w", sectionName, j, err)
			}
			*section = append(*section, r)
			offset = end
		}
	}
	if offset != len(data) {
		return nil, fmt.Errorf("unpack requires a buffer of %d bytes", offset)
	}
	return &message, nil
}

func unpackRecord(decoder *nameDecoder, offset int) (ResourceRecord, int, error) {
	data := decoder.data
	name, offset, err := decoder.unpack(offset, true)
	if err != nil {
		return ResourceRecord{}, 0, err
	}
	if len(data)-offset < 10 {
		return ResourceRecord{}, 0, fmt.Errorf("unpack requires a buffer of 10 bytes")
	}
	r := ResourceRecord{Name: name, Type: int(binary.BigEndian.Uint16(data[offset:])), Class: int(binary.BigEndian.Uint16(data[offset+2:])), TTL: int(binary.BigEndian.Uint32(data[offset+4:]))}
	length := int(binary.BigEndian.Uint16(data[offset+8:]))
	offset += 10
	if len(data)-offset < length {
		return ResourceRecord{}, 0, fmt.Errorf("unpack requires a data buffer of %d bytes", length)
	}
	end := offset + length
	if !recordHasCompression(r.Type) {
		if err := decoder.consume(length); err != nil {
			return ResourceRecord{}, 0, err
		}
		r.Data = slices.Clone(data[offset:end])
		return r, end, nil
	}
	// Upstream scans these RDATA formats byte by byte, even malformed ones.
	// Typed RR decoding would reject opaque records that its flow model preserves.
	r.Data = []byte{}
	for offset < end {
		if data[offset]&0xc0 == 0xc0 {
			name, next, err := decoder.unpack(offset, true)
			if err == nil {
				packed, err := packName(name)
				if err != nil {
					return ResourceRecord{}, 0, err
				}
				if err := decoder.consume(len(packed)); err != nil {
					return ResourceRecord{}, 0, err
				}
				r.Data = append(r.Data, packed...)
				offset = next
				continue
			}
			if _, ok := errors.AsType[*limitError](err); ok {
				return ResourceRecord{}, 0, err
			}
		}
		if err := decoder.consume(1); err != nil {
			return ResourceRecord{}, 0, err
		}
		r.Data = append(r.Data, data[offset])
		offset++
	}
	return r, end, nil
}

func recordHasCompression(typ int) bool {
	switch typ {
	case TypeCNAME, TypeHINFO, TypeMB, TypeMD, TypeMF, TypeMG, TypeMINFO, TypeMR, TypeMX, TypeNS, TypePTR, TypeSOA, TypeTXT, TypeRP, TypeAFSDB, TypeRT, TypeSIG, TypePX, TypeNXT, TypeNAPTR, TypeSRV:
		return true
	default:
		return false
	}
}

var nameIDNA = idna.New(idna.MapForLookup(), idna.Transitional(true), idna.StrictDomainName(false), idna.ValidateLabels(false), idna.VerifyDNSLength(false))

func packName(name string) ([]byte, error) {
	if len(name) > maxWireSize {
		return nil, &limitError{resource: "domain name", limit: maxWireSize}
	}
	data := make([]byte, 0, len(name)+2)
	if name != "" {
		for label := range strings.SplitSeq(name, ".") {
			if label == "" {
				return nil, fmt.Errorf("domain name %q contains empty labels", name)
			}
			if !isASCII(label) {
				var err error
				label, err = nameIDNA.ToASCII(label)
				if err != nil {
					return nil, fmt.Errorf("invalid domain label: %w", err)
				}
			}
			if len(label) > 63 {
				return nil, fmt.Errorf("domain name %q: label too long", name)
			}
			if len(label)+1 >= maxWireSize-len(data) {
				return nil, &limitError{resource: "domain name", limit: maxWireSize}
			}
			data = append(data, byte(len(label)))
			data = append(data, label...)
		}
	}
	return append(data, 0), nil
}

type nameResult struct {
	name string
	end  int
}

type nameDecoder struct {
	data      []byte
	remaining int
	work      int
	cache     map[int]nameResult
}

func (d *nameDecoder) consume(size int) error {
	if size > d.remaining {
		return &limitError{resource: "decoded name/RDATA", limit: maxDecodedSize}
	}
	d.remaining -= size
	return nil
}

func unpackName(data []byte, offset int, compression bool) (string, int, error) {
	if len(data) > maxWireSize {
		return "", 0, &limitError{resource: "RDATA", limit: maxWireSize}
	}
	d := nameDecoder{data: data, remaining: maxDecodedSize, work: maxDecodedSize, cache: make(map[int]nameResult)}
	return d.unpack(offset, compression)
}

func (d *nameDecoder) unpack(offset int, compression bool) (string, int, error) {
	start := offset
	var labels []string
	end := -1
	visited := make(map[int]bool)
	for {
		if offset >= len(d.data) {
			return "", 0, fmt.Errorf("unpack requires a buffer at offset %d", offset)
		}
		if visited[offset] {
			return "", 0, fmt.Errorf("unpack encountered domain name loop")
		}
		visited[offset] = true
		if d.work <= 0 {
			return "", 0, &limitError{resource: "name traversal", limit: maxDecodedSize}
		}
		d.work--
		if compression {
			if cached, ok := d.cache[offset]; ok {
				labels = append(labels, cached.name)
				if end < 0 {
					end = cached.end
				}
				break
			}
		}
		length := int(d.data[offset])
		if length&0xc0 == 0xc0 {
			if !compression {
				return "", 0, fmt.Errorf("unpack encountered a pointer which is not supported in RDATA")
			}
			if len(d.data)-offset < 2 {
				return "", 0, fmt.Errorf("unpack requires a pointer buffer of 2 bytes")
			}
			target := int(binary.BigEndian.Uint16(d.data[offset:]) & 0x3fff)
			if target >= offset {
				return "", 0, fmt.Errorf("unpack encountered forward compression pointer or domain name loop")
			}
			if end < 0 {
				end = offset + 2
			}
			offset = target
			continue
		}
		if length >= 64 {
			return "", 0, fmt.Errorf("unpack encountered a label of length %d", length)
		}
		offset++
		if length == 0 {
			if end < 0 {
				end = offset
			}
			break
		}
		if len(d.data)-offset < length {
			return "", 0, fmt.Errorf("unpack requires a label buffer of %d bytes", length)
		}
		if length > d.work {
			return "", 0, &limitError{resource: "name traversal", limit: maxDecodedSize}
		}
		d.work -= length
		label := string(d.data[offset : offset+length])
		if !isASCII(label) {
			return "", 0, fmt.Errorf("unpack encountered an illegal characters at offset %d", offset)
		}
		if strings.HasPrefix(label, "xn--") {
			var err error
			label, err = idna.Punycode.ToUnicode(label)
			if err != nil {
				return "", 0, fmt.Errorf("unpack encountered an illegal characters at offset %d", offset)
			}
		}
		labels = append(labels, label)
		offset += length
	}
	name := strings.Join(labels, ".")
	if err := d.consume(len(name) + 1); err != nil {
		return "", 0, err
	}
	if compression {
		d.cache[start] = nameResult{name: name, end: end}
	}
	return name, end, nil
}

func isASCII(value string) bool {
	for i := range len(value) {
		if value[i] >= 128 {
			return false
		}
	}
	return true
}

// DomainName decodes uncompressed RDATA as an IDNA domain name.
// Malformed labels, pointers or trailing bytes return an error.
func (r *ResourceRecord) DomainName() (string, error) {
	name, end, err := unpackName(r.Data, 0, false)
	if err != nil {
		return "", err
	}
	if end != len(r.Data) {
		return "", fmt.Errorf("unpack requires a buffer of %d bytes", end)
	}
	return name, nil
}

// SetDomainName replaces RDATA with an uncompressed IDNA domain name.
// Invalid labels return an error without changing the record.
func (r *ResourceRecord) SetDomainName(name string) error {
	data, err := packName(name)
	if err == nil {
		r.Data = data
	}
	return err
}
