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
// [Decode] places no limit on the decompressed size, as upstream places
// none; its zstd decoder keeps libzstd's default maximum window of 128 MiB.
// [DecodeLimit] is the bounded variant for bodies from the network.
package encoding

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zlib"
	"github.com/klauspost/compress/zstd"
)

// ErrUnknownEncoding is wrapped by the error Decode and Encode return for an
// encoding name they do not support.
var ErrUnknownEncoding = errors.New("unknown encoding")

// ErrSizeLimit is wrapped by the error DecodeLimit returns when the decoded
// output would be larger than the limit, and when a zstd frame declares a
// window larger than the bound DecodeLimit allows for that limit.
var ErrSizeLimit = errors.New("decoded size exceeds the limit")

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

	// inputRepr is the start of the Python repr of the whole input. The
	// quote character of a bytes repr depends on every byte, so it is
	// computed while the whole input is still at hand.
	inputRepr string
}

// Error implements the error interface.
//
// The text has the shape of the ValueError mitmproxy's encoding.decode and
// encode raise, "<type> when decoding b'<input>' with '<encoding>':
// <type>('<message>')": the input is the first ten characters of its Python
// repr, and the type is the name of the exception upstream's codec raises
// for that encoding (LookupError for an unknown encoding, ValueError for
// gzip, error for deflate and brotli, ZstdError for zstd). The message of an
// unknown encoding matches upstream's; any other message is the Go
// decoder's.
func (e *Error) Error() string {
	input := e.inputRepr
	if input == "" {
		input = bytesReprPrefix(e.Prefix, e.Prefix)
	}
	name, msg := e.pyException()
	return fmt.Sprintf("%s when %s %s with %s: %s(%s)", name, e.Op, input, strRepr(e.Encoding), name, strRepr(msg))
}

// pyException returns the name of the exception upstream raises for e and
// the message it carries.
func (e *Error) pyException() (name, msg string) {
	if errors.Is(e.Err, ErrUnknownEncoding) {
		// codecs.lookup's message, which names the lowercased encoding.
		return "LookupError", "unknown encoding: " + e.Encoding
	}
	if e.Err != nil {
		msg = e.Err.Error()
	}
	switch e.Encoding {
	case "gzip":
		if e.Op == "decoding" && !errors.Is(e.Err, ErrSizeLimit) {
			// decode_gzip re-raises zlib.error as this ValueError. A size
			// limit is not a codec failure and has no upstream text.
			msg = "Decompression failed: " + msg
		}
		return "ValueError", msg
	case "deflate", "deflateraw", "br":
		// zlib.error and brotli.error are both named "error".
		return "error", msg
	case "zstd":
		return "ZstdError", msg
	default:
		return "ValueError", msg
	}
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
	return decode(data, encoding, unlimited)
}

// DecodeLimit is [Decode] with a bound on the decoded size. Once the output
// grows beyond limit bytes, it stops decoding and returns an error wrapping
// [ErrSizeLimit]; output of exactly limit bytes is accepted, and a negative
// limit is treated as zero. Under the limit the result is the same as
// Decode's.
//
// What DecodeLimit allocates depends on the limit and on the window the
// input declares, not on the decoded size the input claims. Measured per
// call on decompression bombs, the totals are:
//
//   - gzip and deflate: up to about 4 * limit, for the growing output
//     buffer, plus the decoder's 32 KiB window.
//   - br: up to about 32 MiB + 3 * limit. The decoder allocates a ring
//     buffer for the window the stream declares, up to 16 MiB, and grows it
//     once on the way.
//   - zstd: up to about 6 * max(limit, 8 MiB). A zstd frame may need its
//     declared window before any output is produced, so the bound for zstd
//     is at least the 8 MiB window RFC 9659 lets HTTP senders use, and the
//     decoder fills its output up to that bound before it refuses it.
//
// A zstd frame whose window is larger than max(limit, 8 MiB) is refused
// before it is decoded, with an error wrapping both ErrSizeLimit and
// [zstd.ErrWindowSizeExceeded].
func DecodeLimit(data []byte, encoding string, limit int64) ([]byte, error) {
	return decode(data, encoding, max(limit, 0))
}

// unlimited is the limit passed by Decode.
const unlimited = -1

// decode implements Decode and DecodeLimit. A negative limit means no limit.
func decode(data []byte, encoding string, limit int64) ([]byte, error) {
	encoding = strings.ToLower(encoding)
	var (
		out []byte
		err error
	)
	switch encoding {
	case "none", "identity":
		if limit >= 0 && int64(len(data)) > limit {
			err = sizeLimitError(limit)
			break
		}
		return data, nil
	case "gzip":
		out, err = decodeGzip(data, limit)
	case "deflate", "deflateraw":
		out, err = decodeDeflate(data, limit)
	case "br":
		out, err = decodeBrotli(data, limit)
	case "zstd":
		out, err = decodeZstd(data, limit)
	default:
		err = ErrUnknownEncoding
	}
	if err != nil {
		return nil, newError("decoding", encoding, data, err)
	}
	return out, nil
}

func sizeLimitError(limit int64) error {
	return fmt.Errorf("%w of %d bytes", ErrSizeLimit, limit)
}

// windowLimitError reports a zstd frame refused by DecodeLimit because its
// window is larger than the decoder memory bound used for the limit. It
// wraps ErrSizeLimit and the decoder's window error.
type windowLimitError struct {
	bound uint64
	limit int64
	err   error
}

func (e *windowLimitError) Error() string {
	return fmt.Sprintf("frame window exceeds the bound of %d bytes for a limit of %d bytes", e.bound, e.limit)
}

func (e *windowLimitError) Unwrap() []error {
	return []error{ErrSizeLimit, e.err}
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
	prefix := slices.Clone(data[:min(len(data), 10)])
	return &Error{Op: op, Encoding: encoding, Prefix: prefix, Err: err, inputRepr: bytesReprPrefix(prefix, data)}
}

// reprLimit is how many characters of the input's repr an error shows, as
// upstream's repr(encoded)[:10].
const reprLimit = 10

// bytesReprPrefix returns the first reprLimit characters of the Python repr
// of all, whose first bytes are prefix. prefix must hold at least the first
// reprLimit-2 bytes of all, or all of it: every byte takes at least one
// character after the two-character b' opening.
func bytesReprPrefix(prefix, all []byte) string {
	var b strings.Builder
	q := reprQuote(bytes.IndexByte(all, '\'') >= 0, bytes.IndexByte(all, '"') >= 0)
	b.WriteByte('b')
	b.WriteByte(q)
	for _, c := range prefix {
		switch {
		case c == q || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(&b, `\x%02x`, c)
		default:
			b.WriteByte(c)
		}
		if b.Len() >= reprLimit {
			break
		}
	}
	b.WriteByte(q)
	s := b.String()
	return s[:min(len(s), reprLimit)]
}

// strRepr returns the Python repr of s.
func strRepr(s string) string {
	var b strings.Builder
	q := reprQuote(strings.Contains(s, "'"), strings.Contains(s, `"`))
	b.WriteByte(q)
	for _, r := range s {
		switch {
		case r == rune(q) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < utf8.RuneSelf || unicode.IsPrint(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte(q)
	return b.String()
}

// reprQuote picks the quote Python's repr uses: a single quote unless the
// text contains a single quote and no double quote.
func reprQuote(hasSingle, hasDouble bool) byte {
	if hasSingle && !hasDouble {
		return '"'
	}
	return '\''
}

// truncated reports whether err signals that the input ended early.
func truncated(err error) bool {
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
}

// maxPrealloc bounds the buffer reserved up front from a size hint, so a
// forged hint cannot force a large allocation before any data is decoded.
const maxPrealloc = 64 << 20

// readAll drains r, keeping whatever was produced before an error. sizeHint
// is the expected decoded size. With a non-negative limit, reading stops
// once the output exceeds limit bytes and the error wraps ErrSizeLimit.
func readAll(r io.Reader, sizeHint int, limit int64) ([]byte, error) {
	if limit >= 0 {
		sizeHint = int(min(int64(sizeHint), limit))
	}
	if limit >= 0 && limit < math.MaxInt64 {
		// One byte beyond the limit tells an exact fit from an overrun.
		r = io.LimitReader(r, limit+1)
	}
	var buf bytes.Buffer
	buf.Grow(min(sizeHint, maxPrealloc) + bytes.MinRead)
	_, err := buf.ReadFrom(r)
	if limit >= 0 && int64(buf.Len()) > limit {
		return nil, sizeLimitError(limit)
	}
	return buf.Bytes(), err
}

// decodeGzip decodes gzip or zlib data, detecting the wrapper from the
// header like zlib's windowBits 47 does. Only the first gzip member is
// decoded and trailing data is ignored. A stream that ends early yields the
// output decompressed so far, matching zlib's decompressobj.
func decodeGzip(data []byte, limit int64) ([]byte, error) {
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
	out, err := readAll(r, gzipSizeHint(data), limit)
	if err != nil && !truncated(err) {
		return nil, err
	}
	return out, nil
}

// decodeDeflate decodes zlib-wrapped DEFLATE data and falls back to raw
// DEFLATE when that fails, since some servers omit the zlib header and
// checksum. Unlike decodeGzip, a truncated stream is an error. Output that
// exceeds limit as zlib data is not decoded again as raw DEFLATE.
func decodeDeflate(data []byte, limit int64) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	if zr, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
		out, err := readAll(zr, len(data)*expansionGuess, limit)
		if err == nil || errors.Is(err, ErrSizeLimit) {
			return out, err
		}
	}
	// Closing a flate reader releases nothing, so it is left to the GC.
	return readAll(flate.NewReader(bytes.NewReader(data)), len(data)*expansionGuess, limit)
}

func decodeBrotli(data []byte, limit int64) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	return readAll(brotli.NewReader(bytes.NewReader(data)), len(data)*expansionGuess, limit)
}

// zstdMinMemory is the smallest decoder memory bound DecodeLimit uses for
// zstd: RFC 9659 lets HTTP senders use a window of up to 8 MiB, and a
// smaller bound would refuse such a frame however short its content.
const zstdMinMemory = 8 << 20

func decodeZstd(data []byte, limit int64) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	if limit < 0 {
		dec, err := zstdDecoder()
		if err != nil {
			return nil, err
		}
		return dec.DecodeAll(data, nil)
	}
	// The decoder's memory bound is fixed when it is created, so a bounded
	// decode needs its own decoder. The bound caps both the output and the
	// window, and frames that declare a larger content size are refused
	// from their header.
	mem := max(uint64(limit), zstdMinMemory)
	dec, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxWindow(zstdWindowLimit),
		zstd.WithDecoderMaxMemory(mem),
	)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	out, err := dec.DecodeAll(data, nil)
	switch {
	case errors.Is(err, zstd.ErrDecoderSizeExceeded):
		return nil, sizeLimitError(limit)
	case errors.Is(err, zstd.ErrWindowSizeExceeded) && mem < zstdWindowLimit:
		// Decode would accept this window; the limit is what refuses it.
		return nil, &windowLimitError{bound: mem, limit: limit, err: err}
	case err != nil:
		return nil, err
	case int64(len(out)) > limit:
		return nil, sizeLimitError(limit)
	}
	return out, nil
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
