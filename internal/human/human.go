// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package human holds the display helpers of mitmproxy's
// mitmproxy/utils/human.py: byte sizes, durations, timestamps and socket
// addresses formatted for people, and the size parser behind options such
// as body_size_limit.
//
// Upstream formats timestamps in the process's local time zone; the
// functions here take the *time.Location explicitly, and callers that want
// upstream's behaviour pass time.Local.
package human

import (
	"errors"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// sizeUnits lists the suffixes ParseSize accepts, in the order upstream's
// SIZE_UNITS tries them.
var sizeUnits = [...]struct {
	suffix string
	factor int64
}{
	{"b", 1},
	{"k", 1 << 10},
	{"m", 1 << 20},
	{"g", 1 << 30},
	{"t", 1 << 40},
}

// ErrInvalidSize is returned by ParseSize for text that is neither an
// integer nor an integer followed by one of the suffixes b, k, m, g or t.
var ErrInvalidSize = errors.New("Invalid size specification.") //nolint:staticcheck // mitmproxy's message, shown to users verbatim.

// ErrSizeRange is returned by ParseSize for a well-formed size that does not
// fit in an int64. Upstream has no such error: Python integers are
// unbounded.
var ErrSizeRange = errors.New("size specification out of range")

// NoAddress is what upstream's format_address returns for a missing
// address (None). FormatAddress takes a host and port, so callers holding
// an optional address print NoAddress themselves when it is absent.
const NoAddress = "<no address>"

// PrettySize formats a byte count as a short human-readable string such as
// "100b", "1.5k" or "100m", as upstream's pretty_size does.
//
// The result is at most five characters long for sizes from 0 to 1024⁵
// bytes; negative sizes print as plain byte counts ("-2048b"), and sizes of
// 1024 TiB and more keep the "t" suffix ("8388608t").
func PrettySize(size int64) string {
	if size < 1024 {
		return strconv.FormatInt(size, 10) + "b"
	}
	s := float64(size)
	for _, suffix := range [...]string{"k", "m", "g", "t"} {
		s /= 1024
		if s < 99.95 {
			return strconv.FormatFloat(s, 'f', 1, 64) + suffix
		}
		if s < 1024 || suffix == "t" {
			return strconv.FormatFloat(s, 'f', 0, 64) + suffix
		}
	}
	panic("unreachable")
}

// ParseSize parses a size with an optional b, k, m, g or t suffix, which
// multiply it by a power of 1024, as upstream's parse_size does: "1k" is
// 1024 and "1m" is 1048576. The suffixes are lower case only.
//
// The number is read the way Python's int() reads it: surrounding
// whitespace is ignored, a leading sign is allowed, single underscores may
// separate digits, and any Unicode decimal digit counts ("١٢k" is 12288).
// Fractions ("1.5k") are rejected. Malformed text yields ErrInvalidSize,
// and a size outside the int64 range yields ErrSizeRange.
//
// ParseSize(PrettySize(n)) does not give back n in general: PrettySize
// rounds, and its fractional forms such as "1.5k" do not parse.
func ParseSize(s string) (int64, error) {
	if n, ok, err := parsePyInt(s); ok {
		return n, err
	}
	for _, u := range sizeUnits {
		num, found := strings.CutSuffix(s, u.suffix)
		if !found {
			continue
		}
		n, ok, err := parsePyInt(num)
		switch {
		case !ok:
			return 0, ErrInvalidSize
		case err != nil:
			return 0, err
		case n > math.MaxInt64/u.factor || n < math.MinInt64/u.factor:
			return 0, ErrSizeRange
		}
		return n * u.factor, nil
	}
	return 0, ErrInvalidSize
}

// ParseOptSize is ParseSize for an optional size: nil parses to nil, as
// upstream's parse_size(None) returns None.
func ParseOptSize(s *string) (*int64, error) {
	if s == nil {
		return nil, nil
	}
	n, err := ParseSize(*s)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// parsePyInt parses s as Python's int(s) does for base 10. ok reports
// whether s is a well-formed integer; err is ErrSizeRange when it is but
// does not fit in an int64.
func parsePyInt(s string) (n int64, ok bool, err error) {
	s = strings.TrimFunc(s, isPySpace)
	buf := make([]byte, 0, len(s))
	if s != "" && (s[0] == '+' || s[0] == '-') {
		buf = append(buf, s[0])
		s = s[1:]
	}
	// Python allows an underscore only between two digits.
	afterDigit := false
	for _, r := range s {
		if r == '_' {
			if !afterDigit {
				return 0, false, nil
			}
			afterDigit = false
			continue
		}
		d, isDigit := decimalValue(r)
		if !isDigit {
			return 0, false, nil
		}
		buf = append(buf, '0'+d)
		afterDigit = true
	}
	if !afterDigit {
		return 0, false, nil
	}
	n, err = strconv.ParseInt(string(buf), 10, 64)
	if err != nil {
		return 0, true, ErrSizeRange
	}
	return n, true, nil
}

// isPySpace reports whether Python's str.isspace() holds for r: the
// Unicode White_Space characters plus the ASCII separators U+001C to
// U+001F, which Python counts as whitespace through their bidirectional
// class.
func isPySpace(r rune) bool {
	return unicode.Is(unicode.White_Space, r) || ('\x1c' <= r && r <= '\x1f')
}

// decimalValue returns the value of r if it is a Unicode decimal digit
// (general category Nd). Unicode encodes every decimal digit set as a
// contiguous run from zero to nine, and adjacent runs are whole sets, so the
// value is the offset from the start of the surrounding run modulo ten.
func decimalValue(r rune) (byte, bool) {
	if '0' <= r && r <= '9' {
		return byte(r - '0'), true
	}
	if !unicode.IsDigit(r) {
		return 0, false
	}
	start := r
	for unicode.IsDigit(start - 1) {
		start--
	}
	return byte((r - start) % 10), true
}

// PrettyDuration formats a duration given in seconds, as upstream's
// pretty_duration does: "100s" from 100 seconds on, "10.0s" from 10, "1.00s"
// from 1, and whole milliseconds ("123ms") below one second.
//
// Non-finite values print the way Python formats them: NaN as "nanms",
// +Inf as "infs" and -Inf as "-infms".
func PrettyDuration(secs float64) string {
	switch {
	case secs >= 100:
		return pyFixed(secs, 0) + "s"
	case secs >= 10:
		return pyFixed(secs, 1) + "s"
	case secs >= 1:
		return pyFixed(secs, 2) + "s"
	}
	return pyFixed(secs*1000, 0) + "ms"
}

// PrettyOptDuration is PrettyDuration for an optional duration: nil formats
// as "", as upstream's pretty_duration(None) does.
func PrettyOptDuration(secs *float64) string {
	if secs == nil {
		return ""
	}
	return PrettyDuration(*secs)
}

// pyFixed formats f with prec decimals as Python's "{:.<prec>f}" does,
// which spells the non-finite values "nan", "inf" and "-inf".
func pyFixed(f float64, prec int) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	return strconv.FormatFloat(f, 'f', prec, 64)
}

// FormatTimestamp formats a Unix timestamp in seconds as
// "2006-01-02 15:04:05" in loc, as upstream's format_timestamp does in the
// local time zone. The fraction is dropped, rounding towards the past.
//
// ts must be finite; upstream raises for NaN, infinities and timestamps
// outside the years 1 to 9999.
func FormatTimestamp(ts float64, loc *time.Location) string {
	return time.Unix(int64(math.Floor(ts)), 0).In(loc).Format(time.DateTime)
}

// FormatTimestampWithMilli formats a Unix timestamp in seconds as
// "2006-01-02 15:04:05.000" in loc, as upstream's
// format_timestamp_with_milli does in the local time zone. Like Python's
// datetime.fromtimestamp, it first rounds the timestamp to the nearest
// microsecond, ties to even, and then drops the last three digits, so
// 1.9999999 prints as second 2 and -0.0005 as 23:59:59.999.
//
// ts must be finite, as for FormatTimestamp.
func FormatTimestampWithMilli(ts float64, loc *time.Location) string {
	sec, frac := math.Modf(ts)
	us := math.RoundToEven(frac * 1e6)
	switch {
	case us >= 1e6:
		us -= 1e6
		sec++
	case us < 0:
		us += 1e6
		sec--
	}
	return time.Unix(int64(sec), int64(us)*int64(time.Microsecond)).In(loc).Format("2006-01-02 15:04:05.000")
}

// FormatAddress formats a host and port as upstream's format_address does.
// An unspecified IP address (0.0.0.0, ::, ::ffff:0.0.0.0, with or without
// an IPv6 zone) prints as "*:port", an IPv4 or IPv4-mapped IPv6 address as
// "a.b.c.d:port", any other IPv6 address in brackets as "[addr]:port" in
// the canonical compressed form, and anything else, such as a domain name,
// as "host:port" unchanged.
func FormatAddress(host string, port int) string {
	p := strconv.Itoa(port)
	ip, err := netip.ParseAddr(host)
	// Python's ipaddress rejects a zone that itself contains "%"; netip
	// takes everything after the first one.
	if err != nil || strings.Contains(ip.Zone(), "%") {
		return host + ":" + p
	}
	unmapped := ip.Unmap()
	switch {
	case unmapped.WithZone("").IsUnspecified():
		return "*:" + p
	case unmapped.Is4():
		return unmapped.String() + ":" + p
	}
	return "[" + ip.String() + "]:" + p
}
