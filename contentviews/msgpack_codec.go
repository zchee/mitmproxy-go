// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"reflect"

	msgpack "github.com/shamaton/msgpack/v3"
	"github.com/shamaton/msgpack/v3/def"
)

type msgpackValue struct {
	Code     byte
	Scalar   any
	Elements []msgpackValue
	Entries  []msgpackPair
	ExtType  int8
}

type msgpackPair struct {
	Key, Value msgpackValue
}

type msgpackDecoder struct {
	data     []byte
	position int
	budget   *viewBudget
}

func decodeMsgpackValue(data []byte, budget *viewBudget) (msgpackValue, error) {
	if err := budget.checkInput("MsgPack decoding", uint64(len(data))); err != nil {
		return msgpackValue{}, err
	}
	decoder := msgpackDecoder{data: data, budget: budget}
	value, err := decoder.value(0)
	if err == nil && decoder.position != len(data) {
		err = fmt.Errorf("MsgPack decoding: trailing bytes")
	}
	if err != nil {
		return msgpackValue{}, err
	}
	return value, nil
}

func (d *msgpackDecoder) take(size uint64) ([]byte, error) {
	if size > uint64(len(d.data)-d.position) {
		return nil, io.ErrUnexpectedEOF
	}
	start := d.position
	d.position += int(size)
	return d.data[start:d.position], nil
}

func (d *msgpackDecoder) length(size uint64) (uint64, error) {
	data, err := d.take(size)
	if err != nil {
		return 0, err
	}
	var value uint64
	for _, b := range data {
		value = value<<8 | uint64(b)
	}
	return value, nil
}

func msgpackContainer(code byte) (array, mapping bool) {
	return code >= def.FixArray && code < def.FixStr || code == def.Array16 || code == def.Array32,
		code >= def.FixMap && code < def.FixArray || code == def.Map16 || code == def.Map32
}

func (d *msgpackDecoder) value(depth int) (msgpackValue, error) {
	const stage = "MsgPack decoding"
	if err := d.budget.chargeNodes(stage, 1); err != nil {
		return msgpackValue{}, err
	}
	start := d.position
	header, err := d.take(1)
	if err != nil {
		return msgpackValue{}, err
	}
	code := header[0]
	value := msgpackValue{Code: code}
	array, mapping := msgpackContainer(code)
	if array || mapping {
		depth++
		if err := d.budget.checkDepth(stage, depth); err != nil {
			return msgpackValue{}, err
		}
		count := uint64(code & 15)
		if code == def.Array16 || code == def.Map16 {
			count, err = d.length(2)
		}
		if code == def.Array32 || code == def.Map32 {
			count, err = d.length(4)
		}
		if err != nil {
			return msgpackValue{}, err
		}
		children := count
		width := uint64(reflect.TypeFor[msgpackValue]().Size())
		if mapping {
			children *= 2
			width = uint64(reflect.TypeFor[msgpackPair]().Size())
		}
		if children > d.budget.limits.Nodes-d.budget.nodes {
			return msgpackValue{}, d.budget.refusal(stage, "logical nodes", d.budget.nodes, children, d.budget.limits.Nodes)
		}
		if children > uint64(len(d.data)-d.position) {
			return msgpackValue{}, io.ErrUnexpectedEOF
		}
		if err := d.budget.chargeMaterialization(stage, count*width); err != nil {
			return msgpackValue{}, err
		}
		if array {
			value.Elements = make([]msgpackValue, int(count))
			for index := range value.Elements {
				value.Elements[index], err = d.value(depth)
				if err != nil {
					return msgpackValue{}, err
				}
			}
		} else {
			value.Entries = make([]msgpackPair, int(count))
			for index := range value.Entries {
				value.Entries[index].Key, err = d.value(depth)
				if err != nil {
					return msgpackValue{}, err
				}
				value.Entries[index].Value, err = d.value(depth)
				if err != nil {
					return msgpackValue{}, err
				}
			}
		}
		return value, nil
	}
	var payload uint64
	materialized := false
	switch {
	case code <= def.PositiveFixIntMax || code >= 0xe0 || code == def.Nil || code == def.True || code == def.False:
	case code >= def.FixStr && code < def.Nil:
		payload, materialized = uint64(code&31), true
	case code == def.Str8 || code == def.Bin8:
		payload, err = d.length(1)
		materialized = true
	case code == def.Str16 || code == def.Bin16:
		payload, err = d.length(2)
		materialized = true
	case code == def.Str32 || code == def.Bin32:
		payload, err = d.length(4)
		materialized = true
	case code == def.Uint8 || code == def.Int8:
		payload = 1
	case code == def.Uint16 || code == def.Int16:
		payload = 2
	case code == def.Uint32 || code == def.Int32 || code == def.Float32:
		payload = 4
	case code == def.Uint64 || code == def.Int64 || code == def.Float64:
		payload = 8
	case code >= def.Ext8 && code <= def.Ext32 || code >= def.Fixext1 && code <= def.Fixext16:
		return msgpackValue{}, fmt.Errorf("MsgPack decoding: extension values are unsupported")
	default:
		return msgpackValue{}, fmt.Errorf("MsgPack decoding: invalid format code")
	}
	if err != nil {
		return msgpackValue{}, err
	}
	if payload > uint64(len(d.data)-d.position) {
		return msgpackValue{}, io.ErrUnexpectedEOF
	}
	if materialized {
		if err := d.budget.chargeMaterialization(stage, payload); err != nil {
			return msgpackValue{}, err
		}
	}
	if _, err := d.take(payload); err != nil {
		return msgpackValue{}, err
	}
	if err := msgpack.Unmarshal(d.data[start:d.position], &value.Scalar); err != nil {
		return msgpackValue{}, err
	}
	return value, nil
}

type msgpackOutput struct {
	bytes.Buffer
	budget *viewBudget
}

func (w *msgpackOutput) Write(data []byte) (int, error) {
	if err := w.budget.chargeOutput("MsgPack encoding", uint64(len(data))); err != nil {
		return 0, err
	}
	return w.Buffer.Write(data)
}

func encodeMsgpackValue(value msgpackValue, budget *viewBudget) ([]byte, error) {
	output := msgpackOutput{budget: budget}
	var encode func(msgpackValue, int) error
	encode = func(value msgpackValue, depth int) error {
		const stage = "MsgPack encoding"
		if err := budget.chargeNodes(stage, 1); err != nil {
			return err
		}
		array, mapping := msgpackContainer(value.Code)
		if array || mapping {
			if value.Scalar != nil || array && len(value.Entries) != 0 || mapping && len(value.Elements) != 0 {
				return fmt.Errorf("%s: inconsistent container", stage)
			}
			depth++
			if err := budget.checkDepth(stage, depth); err != nil {
				return err
			}
			count, fix, medium, large := len(value.Elements), byte(def.FixArray), byte(def.Array16), byte(def.Array32)
			if mapping {
				count, fix, medium, large = len(value.Entries), def.FixMap, def.Map16, def.Map32
			}
			if uint64(count) > math.MaxUint32 {
				return fmt.Errorf("%s: container is too large", stage)
			}
			var header [5]byte
			size := 1
			switch {
			case count < 16:
				header[0] = fix | byte(count)
			case count <= math.MaxUint16:
				header[0] = medium
				binary.BigEndian.PutUint16(header[1:], uint16(count))
				size = 3
			default:
				header[0] = large
				binary.BigEndian.PutUint32(header[1:], uint32(count))
				size = 5
			}
			if _, err := output.Write(header[:size]); err != nil {
				return err
			}
			for _, item := range value.Elements {
				if err := encode(item, depth); err != nil {
					return err
				}
			}
			for _, pair := range value.Entries {
				if err := encode(pair.Key, depth); err != nil {
					return err
				}
				if err := encode(pair.Value, depth); err != nil {
					return err
				}
			}
			return nil
		}
		if len(value.Elements) != 0 || len(value.Entries) != 0 {
			return fmt.Errorf("%s: inconsistent scalar", stage)
		}
		if value.Code >= def.Ext8 && value.Code <= def.Ext32 || value.Code >= def.Fixext1 && value.Code <= def.Fixext16 {
			return fmt.Errorf("%s: extension values are unsupported", stage)
		}
		switch scalar := value.Scalar.(type) {
		case nil, bool, int8, int16, int32, int64, uint8, uint16, uint32, uint64, float32, float64:
		case string:
			if err := budget.chargeMaterialization(stage, uint64(len(scalar))); err != nil {
				return err
			}
			if err := budget.checkOutput(stage, uint64(len(scalar))); err != nil {
				return err
			}
		case []byte:
			if err := budget.checkOutput(stage, uint64(len(scalar))); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: unsupported scalar type", stage)
		}
		return msgpack.MarshalWrite(&output, value.Scalar)
	}
	if err := encode(value, 0); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
