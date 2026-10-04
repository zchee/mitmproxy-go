// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tnetstring

import (
	"math"
	"strconv"
	"testing"
)

// TestFormatFloat compares against repr(float) as printed by CPython 3.14.
func TestFormatFloat(t *testing.T) {
	tests := map[string]struct {
		in   float64
		want string
	}{
		"zero":                     {in: 0.0, want: "0.0"},
		"negative zero":            {in: math.Copysign(0, -1), want: "-0.0"},
		"one and a half":           {in: 1.5, want: "1.5"},
		"timestamp":                {in: 1759600000.123456, want: "1759600000.123456"},
		"1e16 switches to exp":     {in: 1e16, want: "1e+16"},
		"1e-5 switches to exp":     {in: 1e-5, want: "1e-05"},
		"rounded 17 digit integer": {in: 123456789012345680.0, want: "1.2345678901234568e+17"},
		"1e22":                     {in: 1e22, want: "1e+22"},
		"max float":                {in: math.MaxFloat64, want: "1.7976931348623157e+308"},
		"smallest denormal":        {in: 5e-324, want: "5e-324"},
		"smallest normal":          {in: 2.2250738585072014e-308, want: "2.2250738585072014e-308"},
		"one tenth":                {in: 0.1, want: "0.1"},
		"one third":                {in: 1.0 / 3, want: "0.3333333333333333"},
		"1e15 stays positional":    {in: 1e15, want: "1000000000000000.0"},
		"largest positional":       {in: 9999999999999998.0, want: "9999999999999998.0"},
		"17 digits at exponent 16": {in: 12345678901234567.0, want: "1.2345678901234568e+16"},
		"1e-4 stays positional":    {in: 1e-4, want: "0.0001"},
		"small with digits":        {in: 0.00001234, want: "1.234e-05"},
		"integral":                 {in: 100.0, want: "100.0"},
		"2 to the 53":              {in: 1 << 53, want: "9007199254740992.0"},
		"large exponent":           {in: 1.5e300, want: "1.5e+300"},
		"1e100":                    {in: 1e100, want: "1e+100"},
		"negative small":           {in: -1e-7, want: "-1e-07"},
		"negative with digits":     {in: -2.5e-5, want: "-2.5e-05"},
		"plain decimal":            {in: 123.456, want: "123.456"},
		"inf":                      {in: math.Inf(1), want: "inf"},
		"negative inf":             {in: math.Inf(-1), want: "-inf"},
		"nan":                      {in: math.NaN(), want: "nan"},
		"negative nan":             {in: math.Copysign(math.NaN(), -1), want: "nan"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := FormatFloat(tt.in)
			if got != tt.want {
				t.Errorf("FormatFloat(%v) = %q, want %q", tt.in, got, tt.want)
			}
			enc, err := Dumps(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if want := strconv.Itoa(len(tt.want)) + ":" + tt.want + "^"; string(enc) != want {
				t.Errorf("Dumps(%v) = %q, want %q", tt.in, enc, want)
			}
			back, err := Loads(enc)
			if err != nil {
				t.Fatal(err)
			}
			f := back.(float64)
			if math.Float64bits(f) != math.Float64bits(tt.in) && !(math.IsNaN(f) && math.IsNaN(tt.in)) {
				t.Errorf("Loads(%q) = %v, want %v bit for bit", enc, f, tt.in)
			}
		})
	}
}
