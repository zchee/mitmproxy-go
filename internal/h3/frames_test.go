// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h3

import (
	"bytes"
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestFrameParser(t *testing.T) {
	// quic-go v0.63.0 http3/frames_test.go supplies the wire vectors.
	tests := map[string]struct {
		wire []byte
		want frame
	}{
		"headers length":             {wire: []byte{1, 0x53, 0x37}, want: frame{kind: frameHeaders, length: 0x1337}},
		"data length":                {wire: []byte{0, 0x53, 0x37}, want: frame{kind: frameData, length: 0x1337}},
		"settings":                   {wire: []byte{4, 4, 13, 37, 6, 42}, want: frame{kind: frameSettings, length: 4, settings: map[uint64]uint64{13: 37, 6: 42}}},
		"empty settings":             {wire: []byte{4, 0}, want: frame{kind: frameSettings, settings: map[uint64]uint64{}}},
		"goaway":                     {wire: []byte{7, 1, 4}, want: frame{kind: frameGoAway, length: 1, id: 4}},
		"cancel push":                {wire: []byte{3, 1, 0}, want: frame{kind: frameCancelPush, length: 1}},
		"max push id":                {wire: []byte{13, 1, 0}, want: frame{kind: frameMaxPushID, length: 1}},
		"push promise":               {wire: []byte{5, 3, 0, 0, 0}, want: frame{kind: framePushPromise, length: 3}},
		"unknown and grease ignored": {wire: []byte{0x40, 0x21, 3, 'f', 'o', 'o', 0x40, 0x1f, 0, 1, 3}, want: frame{kind: frameHeaders, length: 3}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := readFrame(bytes.NewReader(test.wire))
			if err != nil {
				t.Fatalf("readFrame(%x): %v", test.wire, err)
			}
			if diff := gocmp.Diff(test.want, got, gocmp.AllowUnexported(frame{})); diff != "" {
				t.Fatalf("frame (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFrameParserErrors(t *testing.T) {
	tests := map[string]struct {
		wire []byte
		code ErrorCode
	}{
		"reserved priority":      {wire: []byte{2, 0}, code: ErrCodeFrameUnexpected},
		"reserved ping":          {wire: []byte{6, 0}, code: ErrCodeFrameUnexpected},
		"reserved window update": {wire: []byte{8, 0}, code: ErrCodeFrameUnexpected},
		"reserved continuation":  {wire: []byte{9, 0}, code: ErrCodeFrameUnexpected},
		"duplicate setting":      {wire: []byte{4, 4, 13, 0, 13, 0}, code: ErrCodeSettingsError},
		"reserved setting":       {wire: []byte{4, 2, 2, 0}, code: ErrCodeSettingsError},
		"invalid connect":        {wire: []byte{4, 2, 8, 2}, code: ErrCodeSettingsError},
		"invalid datagram":       {wire: []byte{4, 2, 0x33, 2}, code: ErrCodeSettingsError},
		"settings lacks value":   {wire: []byte{4, 1, 6}, code: ErrCodeFrameError},
		"truncated settings":     {wire: []byte{4, 2, 6}, code: ErrCodeFrameError},
		"oversized settings":     {wire: []byte{4, 0x60, 1}, code: ErrCodeExcessiveLoad},
		"empty goaway":           {wire: []byte{7, 0}, code: ErrCodeFrameError},
		"extra goaway payload":   {wire: []byte{7, 2, 4, 0}, code: ErrCodeFrameError},
		"oversized goaway":       {wire: []byte{7, 9}, code: ErrCodeFrameError},
		"truncated goaway":       {wire: []byte{7, 1}, code: ErrCodeFrameError},
		"oversized headers":      {wire: append(appendVarint(nil, frameHeaders), appendVarint(nil, MaxHeaderBytes+1)...), code: ErrCodeExcessiveLoad},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := readFrame(bytes.NewReader(test.wire))
			failure, ok := errors.AsType[*ConnectionError](err)
			if !ok || failure.Code != test.code {
				t.Fatalf("readFrame(%x): %v; want connection code %s", test.wire, err, test.code)
			}
		})
	}
}

func TestFrameParserTruncation(t *testing.T) {
	tests := map[string]struct {
		wire       []byte
		unexpected bool
	}{
		"empty stream":            {},
		"partial type":            {wire: []byte{0x40}, unexpected: true},
		"missing length":          {wire: []byte{1}, unexpected: true},
		"partial length":          {wire: []byte{1, 0x40}, unexpected: true},
		"truncated unknown frame": {wire: []byte{0x1f, 2, 0}, unexpected: true},
		"huge unknown length":     {wire: append([]byte{0x1f}, appendVarint(nil, (1<<62)-1)...), unexpected: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := readFrame(bytes.NewReader(test.wire))
			want := io.EOF
			if test.unexpected {
				want = io.ErrUnexpectedEOF
			}
			if !errors.Is(err, want) {
				t.Fatalf("readFrame(%x) = %v; want %v", test.wire, err, want)
			}
		})
	}
}

func TestQUICVarint(t *testing.T) {
	tests := map[string]struct {
		value uint64
		wire  []byte
	}{
		"one byte":    {value: 63, wire: []byte{0x3f}},
		"two bytes":   {value: 64, wire: []byte{0x40, 0x40}},
		"four bytes":  {value: 16384, wire: []byte{0x80, 0, 0x40, 0}},
		"eight bytes": {value: 1 << 30, wire: []byte{0xc0, 0, 0, 0, 0x40, 0, 0, 0}},
		"maximum":     {value: (1 << 62) - 1, wire: bytes.Repeat([]byte{0xff}, 8)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := appendVarint(nil, test.value); !bytes.Equal(got, test.wire) {
				t.Fatalf("encoded %d = %x, want %x", test.value, got, test.wire)
			}
			got, err := readVarint(bytes.NewReader(test.wire))
			if err != nil || got != test.value {
				t.Fatalf("decoded %x = %d, %v; want %d", test.wire, got, err, test.value)
			}
		})
	}
}

func TestQPACKStreamInstructions(t *testing.T) {
	tests := map[string]struct {
		encoder bool
		wire    []byte
		code    ErrorCode
	}{
		"zero capacity":                   {encoder: true, wire: []byte{0x20}},
		"nonzero capacity":                {encoder: true, wire: []byte{0x21}, code: ErrCodeQPACKEncoderStreamError},
		"insert with name reference":      {encoder: true, wire: []byte{0x80}, code: ErrCodeQPACKEncoderStreamError},
		"insert without name reference":   {encoder: true, wire: []byte{0x40}, code: ErrCodeQPACKEncoderStreamError},
		"duplicate dynamic entry":         {encoder: true, wire: []byte{0}, code: ErrCodeQPACKEncoderStreamError},
		"truncated capacity":              {encoder: true, wire: []byte{0x3f}, code: ErrCodeQPACKEncoderStreamError},
		"stream cancellation":             {wire: []byte{0x40}},
		"large stream cancellation":       {wire: []byte{0x7f, 0xff, 1}},
		"section acknowledgement":         {wire: []byte{0x80}, code: ErrCodeQPACKDecoderStreamError},
		"insert count increment":          {wire: []byte{1}, code: ErrCodeQPACKDecoderStreamError},
		"zero insert count increment":     {wire: []byte{0}, code: ErrCodeQPACKDecoderStreamError},
		"truncated stream cancellation":   {wire: []byte{0x7f}, code: ErrCodeQPACKDecoderStreamError},
		"overflowing stream cancellation": {wire: append([]byte{0x7f}, bytes.Repeat([]byte{0xff}, 10)...), code: ErrCodeQPACKDecoderStreamError},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := readQPACKInstruction(bytes.NewReader(test.wire), test.encoder)
			if test.code == 0 {
				if err != nil {
					t.Fatalf("instruction %x: %v", test.wire, err)
				}
				return
			}
			failure, ok := errors.AsType[*ConnectionError](err)
			if !ok || failure.Code != test.code {
				t.Fatalf("instruction %x: %v; want %s", test.wire, err, test.code)
			}
		})
	}
}
