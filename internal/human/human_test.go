// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package human

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
	"unicode"

	gocmp "github.com/google/go-cmp/cmp"
)

// Expected values not taken from upstream's test_human.py come from running
// upstream's human.py at the pinned commit under Python 3.12 and 3.14.

func TestPrettySize(t *testing.T) {
	tests := map[string]struct {
		size int64
		want string
	}{
		"upstream: zero":                {size: 0, want: "0b"},
		"upstream: bytes":               {size: 100, want: "100b"},
		"upstream: one kibibyte":        {size: 1024, want: "1.0k"},
		"upstream: one and a half k":    {size: 1024 + 512, want: "1.5k"},
		"upstream: one mebibyte":        {size: 1024 * 1024, want: "1.0m"},
		"upstream: ten mebibytes":       {size: 10 * 1024 * 1024, want: "10.0m"},
		"upstream: hundred mebibytes":   {size: 100 * 1024 * 1024, want: "100m"},
		"edge: largest byte count":      {size: 1023, want: "1023b"},
		"edge: negative byte count":     {size: -1, want: "-1b"},
		"edge: negative stays in b":     {size: -2048, want: "-2048b"},
		"edge: one decimal below 99.95": {size: 102348, want: "99.9k"},
		"edge: rounds to 100k":          {size: 102349, want: "100k"},
		"edge: rounds up to 1024k":      {size: 1048575, want: "1024k"},
		"edge: 1023 kibibytes":          {size: 1023 * 1024, want: "1023k"},
		"edge: just under 100m":         {size: 104805171, want: "99.9m"},
		"edge: rounds up to 1024g":      {size: 1099511627775, want: "1024g"},
		"edge: 1023 tebibytes":          {size: 1023 << 40, want: "1023t"},
		"edge: t suffix keeps growing":  {size: 1024 << 40, want: "1024t"},
		"edge: max int64":               {size: math.MaxInt64, want: "8388608t"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, PrettySize(tt.size)); diff != "" {
				t.Errorf("PrettySize(%d) mismatch (-want +got):\n%s", tt.size, diff)
			}
		})
	}
}

func TestParseSize(t *testing.T) {
	tests := map[string]struct {
		in      string
		want    int64
		wantErr error
	}{
		"upstream: zero":                 {in: "0", want: 0},
		"upstream: zero bytes":           {in: "0b", want: 0},
		"upstream: one":                  {in: "1", want: 1},
		"upstream: one k":                {in: "1k", want: 1024},
		"upstream: one m":                {in: "1m", want: 1 << 20},
		"upstream: one g":                {in: "1g", want: 1 << 30},
		"upstream: unknown suffix":       {in: "1f", wantErr: ErrInvalidSize},
		"upstream: non-numeric k":        {in: "ak", wantErr: ErrInvalidSize},
		"suffix: t":                      {in: "2t", want: 2 << 40},
		"suffix: space before suffix":    {in: "1 k", want: 1024},
		"suffix: unicode space before":   {in: "1 k", want: 1024},
		"sign: plus":                     {in: "+5", want: 5},
		"sign: minus":                    {in: "-1", want: -1},
		"sign: minus with suffix":        {in: " -1k", want: -1024},
		"space: surrounding":             {in: " 7 ", want: 7},
		"space: tab and newline":         {in: "\t3\n", want: 3},
		"space: no-break space":          {in: "1 ", want: 1},
		"space: ASCII separators":        {in: "\x1c\x1d5\x1e\x1f", want: 5},
		"underscore: leading zero":       {in: "0_7", want: 7},
		"underscore: thousands":          {in: "1_000", want: 1000},
		"underscore: doubled":            {in: "1__0", wantErr: ErrInvalidSize},
		"underscore: leading":            {in: "_1", wantErr: ErrInvalidSize},
		"underscore: trailing":           {in: "1_", wantErr: ErrInvalidSize},
		"underscore: after sign":         {in: "+_1", wantErr: ErrInvalidSize},
		"digits: fullwidth":              {in: "１２", want: 12},
		"digits: arabic-indic with k":    {in: "١٢k", want: 12288},
		"digits: mathematical bold":      {in: "𝟏𝟐", want: 12},
		"invalid: empty":                 {in: "", wantErr: ErrInvalidSize},
		"invalid: blank":                 {in: "   ", wantErr: ErrInvalidSize},
		"invalid: sign only":             {in: "-", wantErr: ErrInvalidSize},
		"invalid: suffix only":           {in: "b", wantErr: ErrInvalidSize},
		"invalid: two suffixes":          {in: "1kb", wantErr: ErrInvalidSize},
		"invalid: upper-case suffix":     {in: "1K", wantErr: ErrInvalidSize},
		"invalid: fraction":              {in: "1.5k", wantErr: ErrInvalidSize},
		"invalid: hex":                   {in: "0x10", wantErr: ErrInvalidSize},
		"invalid: space after suffix":    {in: "1k ", wantErr: ErrInvalidSize},
		"invalid: space after sign":      {in: "- 1", wantErr: ErrInvalidSize},
		"range: max int64":               {in: "9223372036854775807", want: math.MaxInt64},
		"range: min int64":               {in: "-9223372036854775808", want: math.MinInt64},
		"range: largest t":               {in: "8388607t", want: 8388607 << 40},
		"range: smallest t":              {in: "-8388608t", want: math.MinInt64},
		"range: above max int64":         {in: "9223372036854775808", wantErr: ErrSizeRange},
		"range: suffix overflows":        {in: "8388608t", wantErr: ErrSizeRange},
		"range: number overflows before": {in: "99999999999999999999k", wantErr: ErrSizeRange},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ParseSize(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParseSize(%q) error = %v, want %v", tt.in, err, tt.wantErr)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseSize(%q) mismatch (-want +got):\n%s", tt.in, diff)
			}
		})
	}
}

func TestParseSizeErrorText(t *testing.T) {
	_, err := ParseSize("1f")
	if diff := gocmp.Diff("Invalid size specification.", err.Error()); diff != "" {
		t.Errorf("ParseSize error text mismatch (-want +got):\n%s", diff)
	}
}

func TestParseOptSize(t *testing.T) {
	tests := map[string]struct {
		in      *string
		want    *int64
		wantErr error
	}{
		"upstream: none":  {in: nil, want: nil},
		"success: size":   {in: new("1k"), want: new(int64(1024))},
		"error: invalid":  {in: new("ak"), wantErr: ErrInvalidSize},
		"error: overflow": {in: new("8388608t"), wantErr: ErrSizeRange},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ParseOptSize(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParseOptSize error = %v, want %v", err, tt.wantErr)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseOptSize mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDecimalValueRuns checks the property decimalValue relies on: every
// maximal run of Unicode decimal digits is a whole number of zero-to-nine
// sets.
func TestDecimalValueRuns(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !unicode.IsDigit(r) || unicode.IsDigit(r-1) {
			continue
		}
		end := r
		for unicode.IsDigit(end + 1) {
			end++
		}
		if n := end - r + 1; n%10 != 0 {
			t.Errorf("decimal digit run U+%04X..U+%04X has %d digits, want a multiple of 10", r, end, n)
		}
		if v, _ := decimalValue(r); v != 0 {
			t.Errorf("decimalValue(U+%04X) = %d, want 0 at the start of a run", r, v)
		}
		if v, _ := decimalValue(end); v != 9 {
			t.Errorf("decimalValue(U+%04X) = %d, want 9 at the end of a run", end, v)
		}
	}
}

func TestPrettyDuration(t *testing.T) {
	tests := map[string]struct {
		secs float64
		want string
	}{
		"upstream: 10 microseconds":     {secs: 0.00001, want: "0ms"},
		"upstream: 100 microseconds":    {secs: 0.0001, want: "0ms"},
		"upstream: 1 millisecond":       {secs: 0.001, want: "1ms"},
		"upstream: 10 milliseconds":     {secs: 0.01, want: "10ms"},
		"upstream: 100 milliseconds":    {secs: 0.1, want: "100ms"},
		"upstream: 1 second":            {secs: 1, want: "1.00s"},
		"upstream: 10 seconds":          {secs: 10, want: "10.0s"},
		"upstream: 100 seconds":         {secs: 100, want: "100s"},
		"upstream: 1000 seconds":        {secs: 1000, want: "1000s"},
		"upstream: 10000 seconds":       {secs: 10000, want: "10000s"},
		"upstream: 1.123 seconds":       {secs: 1.123, want: "1.12s"},
		"upstream: 123 milliseconds":    {secs: 0.123, want: "123ms"},
		"edge: half millisecond ties":   {secs: 0.0005, want: "0ms"},
		"edge: 1.5 milliseconds":        {secs: 0.0015, want: "2ms"},
		"edge: rounds up to 1000ms":     {secs: 0.9995, want: "1000ms"},
		"edge: rounds down to 999ms":    {secs: 0.99949, want: "999ms"},
		"edge: 9.995 seconds":           {secs: 9.995, want: "9.99s"},
		"edge: 99.95 seconds":           {secs: 99.95, want: "100.0s"},
		"edge: 99.949 seconds":          {secs: 99.949, want: "99.9s"},
		"edge: huge":                    {secs: 1e20, want: "100000000000000000000s"},
		"edge: negative":                {secs: -0.5, want: "-500ms"},
		"edge: negative zero":           {secs: math.Copysign(0, -1), want: "-0ms"},
		"edge: negative rounds to zero": {secs: -0.0004, want: "-0ms"},
		"edge: negative seconds":        {secs: -100, want: "-100000ms"},
		"edge: NaN":                     {secs: math.NaN(), want: "nanms"},
		"edge: negative NaN":            {secs: math.Copysign(math.NaN(), -1), want: "nanms"},
		"edge: +Inf":                    {secs: math.Inf(1), want: "infs"},
		"edge: -Inf":                    {secs: math.Inf(-1), want: "-infms"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, PrettyDuration(tt.secs)); diff != "" {
				t.Errorf("PrettyDuration(%v) mismatch (-want +got):\n%s", tt.secs, diff)
			}
		})
	}
}

func TestPrettyOptDuration(t *testing.T) {
	tests := map[string]struct {
		secs *float64
		want string
	}{
		"upstream: none": {secs: nil, want: ""},
		"success: value": {secs: new(1.123), want: "1.12s"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, PrettyOptDuration(tt.secs)); diff != "" {
				t.Errorf("PrettyOptDuration mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func loadLocation(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("time.LoadLocation(%q): %v", name, err)
	}
	return loc
}

func TestFormatTimestamp(t *testing.T) {
	tokyo := loadLocation(t, "Asia/Tokyo")
	newYork := loadLocation(t, "America/New_York")
	tests := map[string]struct {
		ts       float64
		loc      *time.Location
		want     string
		wantMill string
	}{
		"utc: epoch":                     {ts: 0, loc: time.UTC, want: "1970-01-01 00:00:00", wantMill: "1970-01-01 00:00:00.000"},
		"utc: fraction rounds to us":     {ts: 1.9999999, loc: time.UTC, want: "1970-01-01 00:00:01", wantMill: "1970-01-01 00:00:02.000"},
		"utc: negative half second":      {ts: -0.5, loc: time.UTC, want: "1969-12-31 23:59:59", wantMill: "1969-12-31 23:59:59.500"},
		"utc: negative one and a half":   {ts: -1.5, loc: time.UTC, want: "1969-12-31 23:59:58", wantMill: "1969-12-31 23:59:58.500"},
		"utc: negative half millisecond": {ts: -0.0005, loc: time.UTC, want: "1969-12-31 23:59:59", wantMill: "1969-12-31 23:59:59.999"},
		"utc: microseconds truncated":    {ts: 1700000000.123456, loc: time.UTC, want: "2023-11-14 22:13:20", wantMill: "2023-11-14 22:13:20.123"},
		"utc: half millisecond":          {ts: 1700000000.0005, loc: time.UTC, want: "2023-11-14 22:13:20", wantMill: "2023-11-14 22:13:20.000"},
		"utc: carries into next second":  {ts: 1700000000.9999996, loc: time.UTC, want: "2023-11-14 22:13:20", wantMill: "2023-11-14 22:13:21.000"},
		"utc: just under a millisecond":  {ts: 1700000000.0004995, loc: time.UTC, want: "2023-11-14 22:13:20", wantMill: "2023-11-14 22:13:20.000"},
		"utc: 1.5 milliseconds":          {ts: 1e9 + 0.0015, loc: time.UTC, want: "2001-09-09 01:46:40", wantMill: "2001-09-09 01:46:40.001"},
		"utc: last second of 9999":       {ts: 253402300799, loc: time.UTC, want: "9999-12-31 23:59:59", wantMill: "9999-12-31 23:59:59.000"},
		"zone: tokyo":                    {ts: 1700000000.5, loc: tokyo, want: "2023-11-15 07:13:20", wantMill: "2023-11-15 07:13:20.500"},
		"zone: new york first 1am":       {ts: 1699160400, loc: newYork, want: "2023-11-05 01:00:00", wantMill: "2023-11-05 01:00:00.000"},
		"zone: new york second 1am":      {ts: 1699164000.25, loc: newYork, want: "2023-11-05 01:00:00", wantMill: "2023-11-05 01:00:00.250"},
		"zone: new york after fall-back": {ts: 1699167600, loc: newYork, want: "2023-11-05 02:00:00", wantMill: "2023-11-05 02:00:00.000"},
		"zone: new york spring-forward":  {ts: 1678604400, loc: newYork, want: "2023-03-12 03:00:00", wantMill: "2023-03-12 03:00:00.000"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, FormatTimestamp(tt.ts, tt.loc)); diff != "" {
				t.Errorf("FormatTimestamp(%v) mismatch (-want +got):\n%s", tt.ts, diff)
			}
			if diff := gocmp.Diff(tt.wantMill, FormatTimestampWithMilli(tt.ts, tt.loc)); diff != "" {
				t.Errorf("FormatTimestampWithMilli(%v) mismatch (-want +got):\n%s", tt.ts, diff)
			}
		})
	}
}

// TestFormatTimestampNow ports upstream's tests, which format time.time()
// and only check that the result is not empty; here the result must also
// parse back to the same instant.
func TestFormatTimestampNow(t *testing.T) {
	now := time.Now()
	ts := float64(now.UnixMicro()) / 1e6
	tests := map[string]struct {
		format func(float64, *time.Location) string
		layout string
		trunc  time.Duration
	}{
		"upstream: format_timestamp":            {format: FormatTimestamp, layout: time.DateTime, trunc: time.Second},
		"upstream: format_timestamp_with_milli": {format: FormatTimestampWithMilli, layout: "2006-01-02 15:04:05.000", trunc: time.Millisecond},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := tt.format(ts, time.Local)
			got, err := time.ParseInLocation(tt.layout, s, time.Local)
			if err != nil {
				t.Fatalf("time.ParseInLocation(%q, %q): %v", tt.layout, s, err)
			}
			want := now.Truncate(tt.trunc)
			if d := want.Sub(got); d < -tt.trunc || d > tt.trunc {
				t.Errorf("%q parses to %v, want within %v of %v", s, got, tt.trunc, want)
			}
		})
	}
}

func TestFormatAddress(t *testing.T) {
	tests := map[string]struct {
		host string
		port int
		want string
	}{
		"upstream: IPv6 loopback":              {host: "::1", port: 54010, want: "[::1]:54010"},
		"upstream: IPv4-mapped IPv6":           {host: "::ffff:127.0.0.1", port: 54010, want: "127.0.0.1:54010"},
		"upstream: IPv4":                       {host: "127.0.0.1", port: 54010, want: "127.0.0.1:54010"},
		"upstream: domain name":                {host: "example.com", port: 54010, want: "example.com:54010"},
		"upstream: IPv6 unspecified":           {host: "::", port: 8080, want: "*:8080"},
		"upstream: IPv4 unspecified":           {host: "0.0.0.0", port: 8080, want: "*:8080"},
		"unspecified: mapped IPv4":             {host: "::ffff:0.0.0.0", port: 1, want: "*:1"},
		"unspecified: mapped IPv4 with zone":   {host: "::ffff:0.0.0.0%eth0", port: 443, want: "*:443"},
		"unspecified: mapped hex with zone":    {host: "::ffff:0:0%x", port: 1, want: "*:1"},
		"unspecified: IPv6 with zone":          {host: "::%eth0", port: 1, want: "*:1"},
		"unspecified: uncompressed":            {host: "0:0:0:0:0:0:0:0", port: 443, want: "*:443"},
		"unspecified: padded":                  {host: "0000:0000::0000", port: 443, want: "*:443"},
		"mapped: zone dropped":                 {host: "::ffff:1.2.3.4%en0", port: 1, want: "1.2.3.4:1"},
		"mapped: broadcast":                    {host: "::ffff:255.255.255.255", port: 443, want: "255.255.255.255:443"},
		"mapped: negative port":                {host: "::ffff:1.2.3.4", port: -1, want: "1.2.3.4:-1"},
		"IPv6: zone kept":                      {host: "fe80::1%eth0", port: 80, want: "[fe80::1%eth0]:80"},
		"IPv6: zone case kept":                 {host: "FE80::1%ETH0", port: 443, want: "[fe80::1%ETH0]:443"},
		"IPv6: zone with space":                {host: "fe80::1%eth 0", port: 443, want: "[fe80::1%eth 0]:443"},
		"IPv6: zone with non-ASCII":            {host: "fe80::1%é", port: 443, want: "[fe80::1%é]:443"},
		"IPv6: zone of digits":                 {host: "fe80::1%25", port: 443, want: "[fe80::1%25]:443"},
		"IPv6: upper case lowered":             {host: "FE80::A", port: 1, want: "[fe80::a]:1"},
		"IPv6: IPv4-compatible as hex":         {host: "::1.2.3.4", port: 1, want: "[::102:304]:1"},
		"IPv6: embedded IPv4 as hex":           {host: "1::1.2.3.4", port: 1, want: "[1::102:304]:1"},
		"IPv6: NAT64 prefix":                   {host: "64:ff9b::1.2.3.4", port: 1, want: "[64:ff9b::102:304]:1"},
		"IPv6: single zero group kept":         {host: "1:0:2:3:4:5:6:7", port: 1, want: "[1:0:2:3:4:5:6:7]:1"},
		"IPv6: leading zeros dropped":          {host: "0001::1", port: 1, want: "[1::1]:1"},
		"IPv6: trailing double colon":          {host: "1:2:3:4:5:6:7::", port: 1, want: "[1:2:3:4:5:6:7:0]:1"},
		"IPv6: leading double colon":           {host: "::2:3:4:5:6:7:8", port: 1, want: "[0:2:3:4:5:6:7:8]:1"},
		"IPv6: longest zero run compressed":    {host: "1:0:0:2:0:0:0:3", port: 1, want: "[1:0:0:2::3]:1"},
		"fallback: IPv4 with zone":             {host: "1.2.3.4%eth0", port: 80, want: "1.2.3.4%eth0:80"},
		"fallback: unspecified IPv4 with zone": {host: "0.0.0.0%x", port: 443, want: "0.0.0.0%x:443"},
		"fallback: empty zone":                 {host: "fe80::1%", port: 1, want: "fe80::1%:1"},
		"fallback: empty zone mapped":          {host: "::ffff:1.2.3.4%", port: 443, want: "::ffff:1.2.3.4%:443"},
		"fallback: empty zone unspecified":     {host: "::%", port: 443, want: "::%:443"},
		"fallback: percent in zone":            {host: "fe80::1%a%b", port: 443, want: "fe80::1%a%b:443"},
		"fallback: IPv4 leading zero":          {host: "01.2.3.4", port: 1, want: "01.2.3.4:1"},
		"fallback: mapped leading zero":        {host: "::ffff:01.2.3.4", port: 443, want: "::ffff:01.2.3.4:443"},
		"fallback: three octets":               {host: "1.2.3", port: 443, want: "1.2.3:443"},
		"fallback: five octets":                {host: "1.2.3.4.5", port: 443, want: "1.2.3.4.5:443"},
		"fallback: octet out of range":         {host: "1.2.3.256", port: 443, want: "1.2.3.256:443"},
		"fallback: nine groups":                {host: "1:2:3:4:5:6:7:8:9", port: 443, want: "1:2:3:4:5:6:7:8:9:443"},
		"fallback: two double colons":          {host: "::1::", port: 443, want: "::1:::443"},
		"fallback: bracketed":                  {host: "[::1]", port: 1, want: "[::1]:1"},
		"fallback: leading space":              {host: " 1.2.3.4", port: 443, want: " 1.2.3.4:443"},
		"fallback: trailing space":             {host: "1.2.3.4 ", port: 443, want: "1.2.3.4 :443"},
		"fallback: empty host":                 {host: "", port: 0, want: ":0"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, FormatAddress(tt.host, tt.port)); diff != "" {
				t.Errorf("FormatAddress(%q, %d) mismatch (-want +got):\n%s", tt.host, tt.port, diff)
			}
		})
	}
}

// FuzzParseSize checks what upstream guarantees about PrettySize and
// ParseSize together: a whole-number result parses back to within half a
// unit of the input (or overflows int64 after rounding), a result with a
// fraction does not parse, and results stay within five characters below
// 1024⁵ bytes.
func FuzzParseSize(f *testing.F) {
	for _, n := range []int64{0, 1, 1023, 1024, 1536, 102348, 102349, 1048575, 1 << 40, 1023 << 40, math.MaxInt64, -1, math.MinInt64} {
		f.Add(n)
	}
	f.Fuzz(func(t *testing.T, n int64) {
		s := PrettySize(n)
		if 0 <= n && n < 1<<50 && len(s) > 5 {
			t.Errorf("PrettySize(%d) = %q, longer than 5 characters", n, s)
		}
		got, err := ParseSize(s)
		if strings.Contains(s, ".") {
			if !errors.Is(err, ErrInvalidSize) {
				t.Errorf("ParseSize(PrettySize(%d) = %q) = %d, %v; want ErrInvalidSize", n, s, got, err)
			}
			return
		}
		half := int64(0)
		if !strings.HasSuffix(s, "b") {
			unit, err := ParseSize("1" + s[len(s)-1:])
			if err != nil {
				t.Fatalf("ParseSize unit of %q: %v", s, err)
			}
			half = unit / 2
		}
		if errors.Is(err, ErrSizeRange) && n > math.MaxInt64-half {
			return
		}
		if err != nil {
			t.Fatalf("ParseSize(PrettySize(%d) = %q): %v", n, s, err)
		}
		// float64 holds n exactly only up to 2⁵³, so allow its rounding
		// error on top of half a unit.
		if diff := got - n; diff < -half-1024 || diff > half+1024 {
			t.Errorf("ParseSize(PrettySize(%d) = %q) = %d, off by %d, more than %d", n, s, got, diff, half)
		}
	})
}

// FuzzParseSizeText checks that ParseSize never panics and agrees with the
// suffix rules on arbitrary text.
func FuzzParseSizeText(f *testing.F) {
	for _, s := range []string{"0", "1k", " -1k", "1_000", "１２", "١٢k", "8388608t", "1.5k", "", "_", "+", "1__0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := ParseSize(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidSize) && !errors.Is(err, ErrSizeRange) {
				t.Errorf("ParseSize(%q) returned unexpected error %v", s, err)
			}
			return
		}
		for _, u := range sizeUnits {
			num, found := strings.CutSuffix(s, u.suffix)
			if !found {
				continue
			}
			base, err := ParseSize(num)
			if err == nil && base*u.factor != n {
				t.Errorf("ParseSize(%q) = %d, but ParseSize(%q)*%d = %d", s, n, num, u.factor, base*u.factor)
			}
			break
		}
	})
}
