// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package encoding decodes and encodes HTTP message bodies for the
// Content-Encoding values mitmproxy understands.
//
// The observable contract follows mitmproxy's mitmproxy/net/encoding.py:
// encoding names are case-insensitive, empty input decodes to empty output,
// gzip decoding tolerates a truncated stream and returns what was
// decompressed so far, deflate decoding accepts both zlib-wrapped and raw
// DEFLATE data, and unknown encodings are errors. Upstream's single-entry
// result cache is not replicated, and upstream's fallback to Python text
// codecs (such as "utf8") is not provided: those names are unknown here.
//
// No limit is placed on the decompressed size, as upstream places none; the
// zstd decoder keeps libzstd's default maximum window of 128 MiB.
package encoding

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zlib"
	"github.com/klauspost/compress/zstd"
)

// ErrUnknownEncoding is wrapped by the error Decode and Encode return for an
// encoding name they do not support.
var ErrUnknownEncoding = errors.New("unknown encoding")

// Error describes a failed Decode or Encode call.
type Error struct {
	// Op is "decoding" or "encoding".
	Op string
	// Encoding is the lowercased encoding name.
	Encoding string
	// Prefix holds at most the first 10 bytes of the input.
	Prefix []byte
	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("error when %s %q with %q: %v", e.Op, e.Prefix, e.Encoding, e.Err)
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error { return e.Err }

// encodings lists the supported names in upstream's table order.
var encodings = []string{"none", "identity", "gzip", "deflate", "deflateraw", "br", "zstd"}

// Encodings returns the encoding names Decode and Encode accept.
func Encodings() []string { return slices.Clone(encodings) }

// zstdWindowLimit matches libzstd's default ZSTD_WINDOWLOG_LIMIT_DEFAULT of
// 27, the limit Python's compression.zstd decoder applies.
const zstdWindowLimit = 1 << 27

var (
	zstdDecoder = sync.OnceValues(func() (*zstd.Decoder, error) {
		return zstd.NewReader(nil, zstd.WithDecoderMaxWindow(zstdWindowLimit))
	})
	zstdEncoder = sync.OnceValues(func() (*zstd.Encoder, error) {
		// Zero frames keep an empty body a valid zstd frame, as libzstd emits.
		return zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithZeroFrames(true))
	})
)

// Decode decodes data that was encoded with the named encoding.
//
// The identity encodings ("identity" and "none") return data itself. Every
// other encoding returns a newly allocated slice.
func Decode(data []byte, encoding string) ([]byte, error) {
	encoding = strings.ToLower(encoding)
	var (
		out []byte
		err error
	)
	switch encoding {
	case "none", "identity":
		return data, nil
	case "gzip":
		out, err = decodeGzip(data)
	case "deflate", "deflateraw":
		out, err = decodeDeflate(data)
	case "br":
		out, err = decodeBrotli(data)
	case "zstd":
		out, err = decodeZstd(data)
	default:
		err = ErrUnknownEncoding
	}
	if err != nil {
		return nil, newError("decoding", encoding, data, err)
	}
	return out, nil
}

// Encode encodes data with the named encoding.
//
// The identity encodings ("identity" and "none") return data itself. gzip,
// deflate and zstd use their fastest compression level and brotli uses
// quality 0, as upstream does. gzip output carries a zero modification time,
// so it is deterministic; deflate output is always zlib-wrapped.
func Encode(data []byte, encoding string) ([]byte, error) {
	encoding = strings.ToLower(encoding)
	var (
		out []byte
		err error
	)
	switch encoding {
	case "none", "identity":
		return data, nil
	case "gzip":
		out, err = encodeGzip(data)
	case "deflate", "deflateraw":
		out, err = encodeDeflate(data)
	case "br":
		out, err = encodeBrotli(data)
	case "zstd":
		out, err = encodeZstd(data)
	default:
		err = ErrUnknownEncoding
	}
	if err != nil {
		return nil, newError("encoding", encoding, data, err)
	}
	return out, nil
}

func newError(op, encoding string, data []byte, err error) *Error {
	return &Error{Op: op, Encoding: encoding, Prefix: slices.Clone(data[:min(len(data), 10)]), Err: err}
}

// truncated reports whether err signals that the input ended early.
func truncated(err error) bool {
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
}

// maxPrealloc bounds the buffer reserved up front from a size hint, so a
// forged hint cannot force a large allocation before any data is decoded.
const maxPrealloc = 64 << 20

// readAll drains r, keeping whatever was produced before an error. sizeHint
// is the expected decoded size.
func readAll(r io.Reader, sizeHint int) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(min(sizeHint, maxPrealloc) + bytes.MinRead)
	_, err := buf.ReadFrom(r)
	return buf.Bytes(), err
}

// decodeGzip decodes gzip or zlib data, detecting the wrapper from the
// header like zlib's windowBits 47 does. Only the first gzip member is
// decoded and trailing data is ignored. A stream that ends early yields the
// output decompressed so far, matching zlib's decompressobj.
func decodeGzip(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	src := bytes.NewReader(data)
	var r io.Reader
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		zr, err := gzip.NewReader(src)
		if err != nil {
			if truncated(err) {
				return []byte{}, nil
			}
			return nil, err
		}
		zr.Multistream(false)
		r = zr
	} else {
		zr, err := zlib.NewReader(src)
		if err != nil {
			if truncated(err) {
				return []byte{}, nil
			}
			return nil, err
		}
		r = zr
	}
	out, err := readAll(r, gzipSizeHint(data))
	if err != nil && !truncated(err) {
		return nil, err
	}
	return out, nil
}

// decodeDeflate decodes zlib-wrapped DEFLATE data and falls back to raw
// DEFLATE when that fails, since some servers omit the zlib header and
// checksum. Unlike decodeGzip, a truncated stream is an error.
func decodeDeflate(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	if zr, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
		if out, err := readAll(zr, len(data)*expansionGuess); err == nil {
			return out, nil
		}
	}
	// Closing a flate reader releases nothing, so it is left to the GC.
	return readAll(flate.NewReader(bytes.NewReader(data)), len(data)*expansionGuess)
}

func decodeBrotli(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	return readAll(brotli.NewReader(bytes.NewReader(data)), len(data)*expansionGuess)
}

func decodeZstd(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	dec, err := zstdDecoder()
	if err != nil {
		return nil, err
	}
	return dec.DecodeAll(data, nil)
}

func encodeGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	// The writer encodes ModTime.Unix() as is, so the zero time.Time would
	// not produce the zero MTIME upstream writes.
	zw.ModTime = time.Unix(0, 0)
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeDeflate(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeBrotli(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	// LGWin 22 is the window Python's brotli.compress uses by default.
	bw := brotli.NewWriterOptions(&buf, brotli.WriterOptions{Quality: 0, LGWin: 22})
	if _, err := bw.Write(data); err != nil {
		return nil, err
	}
	if err := bw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeZstd(data []byte) ([]byte, error) {
	enc, err := zstdEncoder()
	if err != nil {
		return nil, err
	}
	return enc.EncodeAll(data, nil), nil
}

// expansionGuess is the decoded-to-encoded size ratio assumed when the
// stream does not declare its decoded size; text bodies commonly compress
// by a factor of 3 to 5.
const expansionGuess = 4

// maxDeflateRatio is the largest decoded-to-encoded size ratio DEFLATE can
// reach, which bounds how far a gzip ISIZE trailer is believed.
const maxDeflateRatio = 1032

// gzipSizeHint returns the decoded size a gzip stream declares in its ISIZE
// trailer, or a guess from the encoded size when the trailer cannot be
// trusted (zlib data, a truncated stream, or a value DEFLATE cannot reach).
func gzipSizeHint(data []byte) int {
	const minGzipLen = 18 // 10-byte header, an empty block, 8-byte trailer.
	guess := len(data) * expansionGuess
	if len(data) < minGzipLen || data[0] != 0x1f || data[1] != 0x8b {
		return guess
	}
	isize := int(binary.LittleEndian.Uint32(data[len(data)-4:]))
	if isize > len(data)*maxDeflateRatio {
		return guess
	}
	return isize
}
