// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package state

import (
	"math"
	"math/big"
	"regexp"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestDecoder(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		build   func() *Map
		read    func(d *Decoder) any
		want    any
		wantErr string
	}{
		"success: all scalar kinds": {
			build: func() *Map {
				m := NewMap(6)
				m.Set("s", "x")
				m.Set("b", []byte("y"))
				m.Set("i", int64(3))
				m.Set("f", int64(2))
				m.Set("t", true)
				m.Set("n", nil)
				return m
			},
			read: func(d *Decoder) any {
				return []any{d.String("s"), d.Bytes("b"), d.Int("i"), d.Float("f"), d.Bool("t"), d.OptString("n")}
			},
			want: []any{"x", []byte("y"), int64(3), 2.0, true, (*string)(nil)},
		},
		"success: float truncates to int": {
			build: func() *Map {
				m := NewMap(1)
				m.Set("i", 3.9)
				return m
			},
			read: func(d *Decoder) any { return d.Int("i") },
			want: int64(3),
		},
		"success: typed nil bytes is empty, not None": {
			build: func() *Map {
				m := NewMap(1)
				m.Set("b", []byte(nil))
				return m
			},
			read: func(d *Decoder) any { return d.OptBytes("b") != nil },
			want: true,
		},
		"error: first error sticks": {
			build: func() *Map {
				m := NewMap(2)
				m.Set("a", int64(1))
				m.Set("b", "ok")
				return m
			},
			read: func(d *Decoder) any {
				d.String("a")
				return d.String("b")
			},
			want:    "",
			wantErr: `T.set_state: field "a": expected str, got int`,
		},
		"error: leftover keys in order": {
			build: func() *Map {
				m := NewMap(3)
				m.Set("z", nil)
				m.Set("a", nil)
				m.Set("k", nil)
				return m
			},
			read:    func(d *Decoder) any { return d.Any("a") },
			want:    nil,
			wantErr: "unexpected fields in T.set_state: [z k]",
		},
		"error: nil state": {
			build:   func() *Map { return nil },
			read:    func(d *Decoder) any { return d.Any("a") },
			want:    nil,
			wantErr: "T.set_state: state is None, expected a dict",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := NewDecoder(tt.build(), "T")
			got := tt.read(d)
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("value mismatch (-want +got):\n%s", diff)
			}
			err := d.Finish()
			var gotErr string
			if err != nil {
				gotErr = err.Error()
			}
			if gotErr != tt.wantErr {
				t.Errorf("Finish() = %q, want %q", gotErr, tt.wantErr)
			}
		})
	}
}

func TestCopy(t *testing.T) {
	t.Parallel()

	inner := NewMap(1)
	inner.Set("k", []byte("v"))
	orig := NewMap(2)
	orig.Set("list", []any{[]byte("a"), inner})
	orig.Set("n", int64(1))

	cp := CopyMap(orig)
	if diff := gocmp.Diff(orig, cp); diff != "" {
		t.Fatalf("copy differs (-orig +copy):\n%s", diff)
	}
	l, _ := cp.Get("list")
	l.([]any)[0].([]byte)[0] = 'X'
	l.([]any)[1].(*Map).Set("k2", nil)
	if diff := gocmp.Diff([]any{[]byte("a"), inner}, mustGet(orig, "list")); diff != "" || inner.Len() != 1 {
		t.Errorf("mutating the copy changed the original:\n%s", diff)
	}
}

func mustGet(m *Map, k string) any {
	v, _ := m.Get(k)
	return v
}

func TestNewID(t *testing.T) {
	t.Parallel()

	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for range 100 {
		id := NewID()
		if !re.MatchString(id) {
			t.Fatalf("NewID() = %q, not a version 4 UUID", id)
		}
		if seen[id] {
			t.Fatalf("NewID() repeated %q", id)
		}
		seen[id] = true
	}
}

func TestEqual(t *testing.T) {
	t.Parallel()

	ab := NewMap(2)
	ab.Set("a", int64(1))
	ab.Set("b", []any{[]byte("x")})
	ba := NewMap(2)
	ba.Set("b", []any{[]byte("x")})
	ba.Set("a", 1.0)
	other := NewMap(2)
	other.Set("a", int64(1))
	other.Set("b", []any{"x"})

	tests := map[string]struct {
		a, b any
		want bool
	}{
		"success: dict order ignored, int equals float": {a: ab, b: ba, want: true},
		"success: bytes differ from str":                {a: ab, b: other, want: false},
		"success: nil equals nil":                       {a: nil, b: nil, want: true},
		"success: nil differs from empty bytes":         {a: nil, b: []byte{}, want: false},
		"success: list length differs":                  {a: []any{int64(1)}, b: []any{}, want: false},
		"success: bool differs from str":                {a: true, b: "true", want: false},
		"success: int equals int64":                     {a: 1, b: int64(1), want: true},
		"success: int64 equals int":                     {a: int64(1), b: 1, want: true},
		"success: int equals float":                     {a: 2, b: 2.0, want: true},
		"success: float equals int":                     {a: 2.0, b: 2, want: true},
		"success: int differs from int64":               {a: 1, b: int64(2), want: false},
		"success: big ints compare by value":            {a: two64(), b: two64(), want: true},
		"success: big int differs from big int":         {a: two64(), b: new(big.Int).Neg(two64()), want: false},
		"success: big int in int64 range equals int64":  {a: big.NewInt(5), b: int64(5), want: true},
		"success: int64 equals big int in range":        {a: int64(5), b: big.NewInt(5), want: true},
		"success: int equals big int in range":          {a: 5, b: big.NewInt(5), want: true},
		"success: big int equals float of its value":    {a: two64(), b: 1.8446744073709552e19, want: true},
		"success: float equals big int of its value":    {a: 1.8446744073709552e19, b: two64(), want: true},
		"success: big int compares with float exactly":  {a: new(big.Int).Add(two64(), big.NewInt(1)), b: 1.8446744073709552e19, want: false},
		"success: big int differs from infinity":        {a: two64(), b: math.Inf(1), want: false},
		"success: big int differs from str":             {a: two64(), b: "18446744073709551616", want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := Equal(tt.a, tt.b); got != tt.want {
				t.Errorf("Equal(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestAsInt(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in      any
		want    int64
		wantErr string
	}{
		"success: int64":                       {in: int64(-7), want: -7},
		"success: int":                         {in: 7, want: 7},
		"success: float truncates toward zero": {in: -3.9, want: -3},
		"success: largest float below 2**63":   {in: math.Nextafter(1<<63, 0), want: 1<<63 - 1024},
		"success: -2**63 fits":                 {in: -(1 << 63) * 1.0, want: math.MinInt64},
		"error: NaN":                           {in: math.NaN(), wantErr: "cannot convert float NaN to integer"},
		"error: positive infinity":             {in: math.Inf(1), wantErr: "cannot convert float infinity to integer"},
		"error: negative infinity":             {in: math.Inf(-1), wantErr: "cannot convert float infinity to integer"},
		"error: 2**63 does not fit":            {in: 1 << 63 * 1.0, wantErr: "integer 9223372036854775808 does not fit in 64 bits"},
		"error: below -2**63":                  {in: -1e19, wantErr: "integer -10000000000000000000 does not fit in 64 bits"},
		"error: str":                           {in: "1", wantErr: "expected int, got str"},
		"error: integer beyond int64":          {in: new(big.Int).Lsh(big.NewInt(1), 64), wantErr: "integer 18446744073709551616 does not fit in 64 bits"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := AsInt(tt.in)
			var gotErr string
			if err != nil {
				gotErr = err.Error()
			}
			if gotErr != tt.wantErr {
				t.Fatalf("AsInt(%v) error = %q, want %q", tt.in, gotErr, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("AsInt(%v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// two64 returns 2**64, an integer that does not fit in an int64.
func two64() *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), 64)
}

func TestBigInt(t *testing.T) {
	t.Parallel()

	if got := TypeName(two64()); got != "int" {
		t.Errorf("TypeName(2**64) = %q, want %q", got, "int")
	}
	if _, err := AsFloat(two64()); err == nil || err.Error() != "integer 18446744073709551616 does not fit in 64 bits" {
		t.Errorf("AsFloat(2**64) error = %v, want the integer refused", err)
	}

	orig := NewMap(1)
	orig.Set("k", two64())
	cp := CopyMap(orig)
	if !Equal(orig, cp) {
		t.Fatalf("CopyMap = %v, want a map equal to %v", cp, orig)
	}
	c, _ := cp.Get("k")
	c.(*big.Int).SetInt64(1)
	if o, _ := orig.Get("k"); o.(*big.Int).Cmp(two64()) != 0 {
		t.Errorf("mutating the copied *big.Int changed the original to %v", o)
	}
}
