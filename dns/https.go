// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"slices"
)

// HTTPSParam is an opaque service parameter in an HTTPS or SVCB record.
// Value is owned by the record; unknown keys are preserved.
type HTTPSParam struct {
	Key   uint16
	Value []byte
}

// HTTPSRecord is the ordered RDATA view of an HTTPS or SVCB resource record.
// Priority follows mitmproxy's signed 16-bit interpretation. TargetName is an
// uncompressed IDNA name; Params retains insertion order, including unknown keys.
type HTTPSRecord struct {
	Priority   int
	TargetName string
	Params     []HTTPSParam
}

// PackHTTPS encodes record as HTTPS/SVCB RDATA without mutating its fields.
// Invalid priority, labels, duplicate keys or oversized values return an error.
func PackHTTPS(record HTTPSRecord) ([]byte, error) {
	if record.Priority < -32768 || record.Priority > 32767 {
		return nil, fmt.Errorf("HTTPS priority %d is out of bounds", record.Priority)
	}
	name, err := packName(record.TargetName)
	if err != nil {
		return nil, err
	}
	if len(name) > maxWireSize-2 {
		return nil, &limitError{resource: "HTTPS RDATA", limit: maxWireSize}
	}
	data := binary.BigEndian.AppendUint16(nil, uint16(int16(record.Priority)))
	data = append(data, name...)
	seen := make(map[uint16]bool)
	for _, param := range record.Params {
		if seen[param.Key] {
			return nil, fmt.Errorf("duplicate HTTPS parameter %d", param.Key)
		}
		seen[param.Key] = true
		if len(param.Value) > maxWireSize {
			return nil, &limitError{resource: "HTTPS parameter", limit: maxWireSize}
		}
		if len(param.Value)+4 > maxWireSize-len(data) {
			return nil, &limitError{resource: "HTTPS RDATA", limit: maxWireSize}
		}
		data = binary.BigEndian.AppendUint16(data, param.Key)
		data = binary.BigEndian.AppendUint16(data, uint16(len(param.Value)))
		data = append(data, param.Value...)
	}
	return data, nil
}

// UnpackHTTPS decodes owned HTTPS/SVCB RDATA. Compressed TargetName and truncated
// fields return an error. Duplicate keys keep their first position and last value,
// matching mitmproxy's ordered dictionary semantics.
func UnpackHTTPS(data []byte) (HTTPSRecord, error) {
	if len(data) > maxWireSize {
		return HTTPSRecord{}, &limitError{resource: "HTTPS RDATA", limit: maxWireSize}
	}
	if len(data) < 2 {
		return HTTPSRecord{}, fmt.Errorf("unpack requires a buffer of 2 bytes")
	}
	name, offset, err := unpackName(data, 2, false)
	if err != nil {
		return HTTPSRecord{}, err
	}
	record := HTTPSRecord{Priority: int(int16(binary.BigEndian.Uint16(data))), TargetName: name, Params: []HTTPSParam{}}
	indices := make(map[uint16]int)
	for offset < len(data) {
		if len(data)-offset < 4 {
			return HTTPSRecord{}, fmt.Errorf("unpack requires a buffer of %d bytes", offset+4)
		}
		key := binary.BigEndian.Uint16(data[offset:])
		length := int(binary.BigEndian.Uint16(data[offset+2:]))
		offset += 4
		if len(data)-offset < length {
			return HTTPSRecord{}, fmt.Errorf("unpack requires a buffer of %d bytes", offset+length)
		}
		param := HTTPSParam{Key: key, Value: slices.Clone(data[offset : offset+length])}
		if index, exists := indices[key]; exists {
			record.Params[index] = param
		} else {
			indices[key] = len(record.Params)
			record.Params = append(record.Params, param)
		}
		offset += length
	}
	return record, nil
}

// HTTPSALPN returns owned protocol IDs, or nil when ALPN is absent.
// Malformed HTTPS RDATA returns an error. Truncated ALPN tokens follow upstream's
// clipped-slice behavior instead of imposing additional protocol validation.
func (r *ResourceRecord) HTTPSALPN() ([][]byte, error) {
	record, err := UnpackHTTPS(r.Data)
	if err != nil {
		return nil, err
	}
	for _, param := range record.Params {
		if param.Key != 1 {
			continue
		}
		result := [][]byte{}
		for offset := 0; offset < len(param.Value); {
			length := int(param.Value[offset])
			offset++
			result = append(result, slices.Clone(param.Value[offset:min(offset+length, len(param.Value))]))
			offset += length
		}
		return result, nil
	}
	return nil, nil
}

// SetHTTPSALPN replaces the ALPN parameter, or removes it for nil.
// Invalid RDATA or a protocol ID longer than 255 bytes leaves r unchanged.
func (r *ResourceRecord) SetHTTPSALPN(alpn [][]byte) error {
	var value []byte
	if alpn != nil {
		value = []byte{}
		for _, protocol := range alpn {
			if len(protocol) > 255 {
				return fmt.Errorf("ALPN protocol ID longer than 255 bytes")
			}
			if len(protocol)+1 > maxWireSize-len(value) {
				return &limitError{resource: "ALPN parameter", limit: maxWireSize}
			}
			value = append(value, byte(len(protocol)))
			value = append(value, protocol...)
		}
	}
	return r.setHTTPSParam(1, value)
}

// HTTPSECH returns the base64 ECH configuration, or nil when absent.
// Malformed HTTPS RDATA returns an error.
func (r *ResourceRecord) HTTPSECH() (*string, error) {
	record, err := UnpackHTTPS(r.Data)
	if err != nil {
		return nil, err
	}
	for _, param := range record.Params {
		if param.Key == 5 {
			return new(base64.StdEncoding.EncodeToString(param.Value)), nil
		}
	}
	return nil, nil
}

// SetHTTPSECH replaces the base64 ECH configuration, or removes it for nil.
// Invalid base64 or malformed RDATA returns an error without modifying r.
func (r *ResourceRecord) SetHTTPSECH(ech *string) error {
	var value []byte
	if ech != nil {
		if base64.StdEncoding.DecodedLen(len(*ech)) > maxWireSize {
			return &limitError{resource: "ECH parameter", limit: maxWireSize}
		}
		var err error
		value, err = base64.StdEncoding.DecodeString(*ech)
		if err != nil {
			return fmt.Errorf("decode ECH configuration: %w", err)
		}
	}
	return r.setHTTPSParam(5, value)
}

func (r *ResourceRecord) setHTTPSParam(key uint16, value []byte) error {
	record, err := UnpackHTTPS(r.Data)
	if err != nil {
		return err
	}
	index := slices.IndexFunc(record.Params, func(param HTTPSParam) bool { return param.Key == key })
	if index >= 0 {
		if value == nil {
			record.Params = slices.Delete(record.Params, index, index+1)
		} else {
			record.Params[index].Value = value
		}
	} else if value != nil {
		record.Params = append(record.Params, HTTPSParam{Key: key, Value: value})
	}
	data, err := PackHTTPS(record)
	if err == nil {
		r.Data = data
	}
	return err
}
