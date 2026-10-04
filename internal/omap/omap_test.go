// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package omap

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"slices"
	"strconv"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

type op struct {
	kind string // "set", "del" or "pop"
	key  string
	val  int
}

func apply(m *Map[int], ops []op) {
	for _, o := range ops {
		switch o.kind {
		case "set":
			m.Set(o.key, o.val)
		case "del":
			m.Delete(o.key)
		case "pop":
			m.Pop(o.key)
		}
	}
}

func set(k string, v int) op { return op{kind: "set", key: k, val: v} }
func del(k string) op        { return op{kind: "del", key: k} }

// manyKeys returns set operations for keys k0..k(n-1), enough to push a map
// over the hash index threshold.
func manyKeys(n int) []op {
	ops := make([]op, n)
	for i := range n {
		ops[i] = set("k"+strconv.Itoa(i), i)
	}
	return ops
}

func keyRange(lo, hi int) []string {
	keys := make([]string, 0, hi-lo)
	for i := lo; i < hi; i++ {
		keys = append(keys, "k"+strconv.Itoa(i))
	}
	return keys
}

func TestMapOrder(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		ops      []op
		wantKeys []string
		wantVals map[string]int
	}{
		"success: empty map has no keys": {
			ops:      nil,
			wantKeys: nil,
			wantVals: map[string]int{},
		},
		"success: keys keep insertion order, not sorted order": {
			ops:      []op{set("version", 21), set("type", 1), set("id", 2), set("error", 3)},
			wantKeys: []string{"version", "type", "id", "error"},
			wantVals: map[string]int{"version": 21, "type": 1, "id": 2, "error": 3},
		},
		"success: overwrite keeps the original position": {
			ops:      []op{set("a", 1), set("b", 2), set("c", 3), set("a", 10)},
			wantKeys: []string{"a", "b", "c"},
			wantVals: map[string]int{"a": 10, "b": 2, "c": 3},
		},
		"success: delete removes the key from the order": {
			ops:      []op{set("a", 1), set("b", 2), set("c", 3), del("b")},
			wantKeys: []string{"a", "c"},
			wantVals: map[string]int{"a": 1, "c": 3},
		},
		"success: re-adding a deleted key appends it at the end": {
			ops:      []op{set("a", 1), set("b", 2), set("c", 3), del("a"), set("a", 4)},
			wantKeys: []string{"b", "c", "a"},
			wantVals: map[string]int{"b": 2, "c": 3, "a": 4},
		},
		"success: deleting an absent key is a no-op": {
			ops:      []op{set("a", 1), del("missing")},
			wantKeys: []string{"a"},
			wantVals: map[string]int{"a": 1},
		},
		"success: indexed map keeps order across middle deletes": {
			ops:      append(manyKeys(20), del("k5"), del("k0"), set("k3", 33), set("k20", 20)),
			wantKeys: append(append(append([]string{}, keyRange(1, 5)...), keyRange(6, 20)...), "k20"),
			wantVals: func() map[string]int {
				m := map[string]int{"k20": 20}
				for i := 1; i < 20; i++ {
					if i != 5 {
						m["k"+strconv.Itoa(i)] = i
					}
				}
				m["k3"] = 33
				return m
			}(),
		},
		"success: shrinking below the index threshold keeps lookups working": {
			ops: func() []op {
				ops := manyKeys(indexThreshold + 2)
				for i := range indexThreshold {
					ops = append(ops, del("k"+strconv.Itoa(i)))
				}
				return append(ops, set("z", 99))
			}(),
			wantKeys: []string{"k" + strconv.Itoa(indexThreshold), "k" + strconv.Itoa(indexThreshold+1), "z"},
			wantVals: map[string]int{
				"k" + strconv.Itoa(indexThreshold):   indexThreshold,
				"k" + strconv.Itoa(indexThreshold+1): indexThreshold + 1,
				"z":                                  99,
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m := New[int]()
			apply(m, tt.ops)

			if diff := gocmp.Diff(tt.wantKeys, m.Keys()); diff != "" {
				t.Errorf("Keys() mismatch (-want +got):\n%s", diff)
			}
			if got, want := m.Len(), len(tt.wantKeys); got != want {
				t.Errorf("Len() = %d, want %d", got, want)
			}
			for k, want := range tt.wantVals {
				got, ok := m.Get(k)
				if !ok || got != want {
					t.Errorf("Get(%q) = (%d, %t), want (%d, true)", k, got, ok, want)
				}
				if !m.Has(k) {
					t.Errorf("Has(%q) = false, want true", k)
				}
			}
			if _, ok := m.Get("never-set"); ok {
				t.Errorf("Get(%q) reported a value for a key that was never set", "never-set")
			}

			var iterKeys []string
			for k, v := range m.All() {
				iterKeys = append(iterKeys, k)
				if want := tt.wantVals[k]; v != want {
					t.Errorf("All() yielded %q=%d, want %d", k, v, want)
				}
			}
			if diff := gocmp.Diff(tt.wantKeys, iterKeys); diff != "" {
				t.Errorf("All() order mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMapPop(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		size     int
		pop      string
		wantVal  int
		wantOK   bool
		wantKeys []string
	}{
		"success: pop from a small map": {
			size:     3,
			pop:      "k1",
			wantVal:  1,
			wantOK:   true,
			wantKeys: []string{"k0", "k2"},
		},
		"success: pop the first key of an indexed map": {
			size:     12,
			pop:      "k0",
			wantVal:  0,
			wantOK:   true,
			wantKeys: keyRange(1, 12),
		},
		"error: pop an absent key": {
			size:     3,
			pop:      "nope",
			wantVal:  0,
			wantOK:   false,
			wantKeys: []string{"k0", "k1", "k2"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m := New[int]()
			apply(m, manyKeys(tt.size))
			got, ok := m.Pop(tt.pop)
			if got != tt.wantVal || ok != tt.wantOK {
				t.Errorf("Pop(%q) = (%d, %t), want (%d, %t)", tt.pop, got, ok, tt.wantVal, tt.wantOK)
			}
			if diff := gocmp.Diff(tt.wantKeys, m.Keys()); diff != "" {
				t.Errorf("Keys() after Pop mismatch (-want +got):\n%s", diff)
			}
			for _, k := range tt.wantKeys {
				if _, ok := m.Get(k); !ok {
					t.Errorf("Get(%q) after Pop lost the key", k)
				}
			}
		})
	}
}

func TestMapNilAndZero(t *testing.T) {
	t.Parallel()

	var nilMap *Map[int]
	if got := nilMap.Len(); got != 0 {
		t.Errorf("nil Len() = %d, want 0", got)
	}
	if _, ok := nilMap.Get("a"); ok {
		t.Error("nil Get reported a value")
	}
	if nilMap.Has("a") {
		t.Error("nil Has reported a key")
	}
	if keys := nilMap.Keys(); keys != nil {
		t.Errorf("nil Keys() = %v, want nil", keys)
	}
	for k := range nilMap.All() {
		t.Errorf("nil All() yielded %q", k)
	}
	if c := nilMap.Clone(); c != nil {
		t.Errorf("nil Clone() = %v, want nil", c)
	}
	nilMap.Delete("a")
	if _, ok := nilMap.Pop("a"); ok {
		t.Error("nil Pop reported a value")
	}

	var zero Map[int]
	zero.Set("b", 2)
	zero.Set("a", 1)
	if diff := gocmp.Diff([]string{"b", "a"}, zero.Keys()); diff != "" {
		t.Errorf("zero-value map Keys() mismatch (-want +got):\n%s", diff)
	}
}

func TestNewWithCapacity(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		capacity int
		size     int
	}{
		"success: fills up to the capacity":              {capacity: 4, size: 4},
		"success: grows past the capacity and indexes":   {capacity: 2, size: 20},
		"success: negative capacity behaves like New":    {capacity: -1, size: 3},
		"success: large capacity with few entries works": {capacity: 64, size: 1},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m := NewWithCapacity[int](tt.capacity)
			apply(m, manyKeys(tt.size))
			if diff := gocmp.Diff(keyRange(0, tt.size), m.Keys()); diff != "" {
				t.Errorf("Keys() mismatch (-want +got):\n%s", diff)
			}
			for i, k := range keyRange(0, tt.size) {
				if got, ok := m.Get(k); !ok || got != i {
					t.Errorf("Get(%q) = (%d, %t), want (%d, true)", k, got, ok, i)
				}
			}
		})
	}
}

func TestMapAllStopsEarly(t *testing.T) {
	t.Parallel()

	m := New[int]()
	apply(m, manyKeys(5))
	var seen []string
	for k := range m.All() {
		seen = append(seen, k)
		if len(seen) == 2 {
			break
		}
	}
	if diff := gocmp.Diff([]string{"k0", "k1"}, seen); diff != "" {
		t.Errorf("All() with break mismatch (-want +got):\n%s", diff)
	}
}

func TestMapClone(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		size int
	}{
		"success: clone of a small map is independent":    {size: 3},
		"success: clone of an indexed map is independent": {size: 20},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			orig := New[int]()
			apply(orig, manyKeys(tt.size))
			clone := orig.Clone()

			clone.Set("k0", 100)
			clone.Set("extra", 1)
			clone.Delete("k1")

			if got, _ := orig.Get("k0"); got != 0 {
				t.Errorf("original k0 = %d after modifying the clone, want 0", got)
			}
			if orig.Has("extra") {
				t.Error("original gained a key added to the clone")
			}
			if !orig.Has("k1") {
				t.Error("original lost a key deleted from the clone")
			}
			if diff := gocmp.Diff(keyRange(0, tt.size), orig.Keys()); diff != "" {
				t.Errorf("original Keys() mismatch (-want +got):\n%s", diff)
			}
			wantClone := append(append([]string{"k0"}, keyRange(2, tt.size)...), "extra")
			if diff := gocmp.Diff(wantClone, clone.Keys()); diff != "" {
				t.Errorf("clone Keys() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func anyMap(kv ...any) *Map[any] {
	m := New[any]()
	for i := 0; i < len(kv); i += 2 {
		m.Set(kv[i].(string), kv[i+1])
	}
	return m
}

func TestMapEqual(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		a, b *Map[any]
		want bool
	}{
		"success: same keys, same order, same values": {
			a:    anyMap("a", int64(1), "b", []byte("x")),
			b:    anyMap("a", int64(1), "b", []byte("x")),
			want: true,
		},
		"success: nil equals empty": {
			a:    nil,
			b:    New[any](),
			want: true,
		},
		"success: nested maps and lists compare by content": {
			a:    anyMap("l", []any{anyMap("x", "1"), []byte{}}, "n", nil),
			b:    anyMap("l", []any{anyMap("x", "1"), []byte(nil)}, "n", nil),
			want: true,
		},
		"error: same entries in a different order": {
			a:    anyMap("a", int64(1), "b", int64(2)),
			b:    anyMap("b", int64(2), "a", int64(1)),
			want: false,
		},
		"error: different value types": {
			a:    anyMap("a", int64(1)),
			b:    anyMap("a", 1.0),
			want: false,
		},
		"error: None differs from an empty list": {
			a:    anyMap("a", nil),
			b:    anyMap("a", []any{}),
			want: false,
		},
		"error: nested map order differs": {
			a:    anyMap("m", anyMap("x", 1, "y", 2)),
			b:    anyMap("m", anyMap("y", 2, "x", 1)),
			want: false,
		},
		"error: different lengths": {
			a:    anyMap("a", 1),
			b:    anyMap("a", 1, "b", 2),
			want: false,
		},
		"error: byte-string key differs from text key": {
			a:    anyMap("a", 1),
			b:    bytesKeyMap("a", 1),
			want: false,
		},
		"success: byte-string keys compare equal": {
			a:    bytesKeyMap("a", 1),
			b:    bytesKeyMap("a", 1),
			want: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := tt.a.Equal(tt.b); got != tt.want {
				t.Errorf("Equal() = %t, want %t\na: %v\nb: %v", got, tt.want, tt.a, tt.b)
			}
			if got := tt.b.Equal(tt.a); got != tt.want {
				t.Errorf("reverse Equal() = %t, want %t", got, tt.want)
			}
			// go-cmp must use the Equal method instead of panicking on the
			// unexported fields.
			if got := gocmp.Equal(tt.a, tt.b); got != tt.want {
				t.Errorf("gocmp.Equal() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestMapJSONMarshal(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in   *Map[any]
		want string
	}{
		"success: members in insertion order": {
			in:   anyMap("zeta", 1, "alpha", "x", "mid", true),
			want: `{"zeta":1,"alpha":"x","mid":true}`,
		},
		"success: nested ordered maps keep their order": {
			in:   anyMap("outer", anyMap("b", nil, "a", []any{1, "two"})),
			want: `{"outer":{"b":null,"a":[1,"two"]}}`,
		},
		"success: empty map": {
			in:   New[any](),
			want: `{}`,
		},
		"success: nil map is null": {
			in:   nil,
			want: `null`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if diff := gocmp.Diff(tt.want, string(got)); diff != "" {
				t.Errorf("json.Marshal() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMapJSONMarshalStructField(t *testing.T) {
	t.Parallel()

	type wrapper struct {
		Meta  *Map[int] `json:"meta,omitzero"`
		Plain Map[int]  `json:"plain"`
	}
	w := wrapper{Meta: New[int]()}
	w.Meta.Set("y", 1)
	w.Meta.Set("x", 2)
	w.Plain.Set("b", 3)
	w.Plain.Set("a", 4)

	got, err := json.Marshal(&w)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	want := `{"meta":{"y":1,"x":2},"plain":{"b":3,"a":4}}`
	if diff := gocmp.Diff(want, string(got)); diff != "" {
		t.Errorf("json.Marshal() mismatch (-want +got):\n%s", diff)
	}
}

func TestMapJSONUnmarshal(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in       string
		want     *Map[any]
		wantKeys []string
		wantErr  bool
	}{
		"success: members keep document order": {
			in:       `{"zeta":1,"alpha":"x","mid":true}`,
			want:     anyMap("zeta", 1.0, "alpha", "x", "mid", true),
			wantKeys: []string{"zeta", "alpha", "mid"},
		},
		"success: nested objects decode as ordered maps": {
			in:       `{"o":{"b":null,"a":[{"y":1,"x":2},"s"]}}`,
			want:     anyMap("o", anyMap("b", nil, "a", []any{anyMap("y", 1.0, "x", 2.0), "s"})),
			wantKeys: []string{"o"},
		},
		"success: empty object": {
			in:       `{}`,
			want:     New[any](),
			wantKeys: nil,
		},
		"success: empty nested array": {
			in:       `{"a":[]}`,
			want:     anyMap("a", []any{}),
			wantKeys: []string{"a"},
		},
		"error: duplicate member names are rejected": {
			in:      `{"a":1,"a":2}`,
			wantErr: true,
		},
		"error: array is not an object": {
			in:      `[1,2]`,
			wantErr: true,
		},
		"error: truncated object": {
			in:      `{"a":1`,
			wantErr: true,
		},
		"error: truncated nested array": {
			in:      `{"a":[1,`,
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := New[any]()
			err := json.Unmarshal([]byte(tt.in), got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("json.Unmarshal(%s) error = %v, wantErr %t", tt.in, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("json.Unmarshal() mismatch (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(tt.wantKeys, got.Keys()); diff != "" {
				t.Errorf("Keys() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMapJSONUnmarshalTyped(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		start    *Map[int]
		in       string
		wantKeys []string
		wantVals []int
		wantErr  bool
	}{
		"success: typed values decode into V": {
			start:    New[int](),
			in:       `{"b":2,"a":1}`,
			wantKeys: []string{"b", "a"},
			wantVals: []int{2, 1},
		},
		"success: existing entries are merged in place": {
			start: func() *Map[int] {
				m := New[int]()
				m.Set("a", 1)
				m.Set("c", 3)
				return m
			}(),
			in:       `{"c":30,"d":4}`,
			wantKeys: []string{"a", "c", "d"},
			wantVals: []int{1, 30, 4},
		},
		"success: null clears the map": {
			start: func() *Map[int] {
				m := New[int]()
				m.Set("a", 1)
				return m
			}(),
			in:       `null`,
			wantKeys: nil,
			wantVals: nil,
		},
		"error: value of the wrong type": {
			start:   New[int](),
			in:      `{"a":"x"}`,
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dec := jsontext.NewDecoder(strings.NewReader(tt.in))
			err := tt.start.UnmarshalJSONFrom(dec)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalJSONFrom(%s) error = %v, wantErr %t", tt.in, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := gocmp.Diff(tt.wantKeys, tt.start.Keys()); diff != "" {
				t.Errorf("Keys() mismatch (-want +got):\n%s", diff)
			}
			var vals []int
			for _, v := range tt.start.All() {
				vals = append(vals, v)
			}
			if diff := gocmp.Diff(tt.wantVals, vals); diff != "" {
				t.Errorf("values mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMapJSONRoundTrip(t *testing.T) {
	t.Parallel()

	orig := anyMap(
		"version", 21.0,
		"type", "http",
		"metadata", anyMap("z", "last", "a", "first"),
		"list", []any{anyMap("k", true), nil, "s"},
	)
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	got := New[any]()
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if diff := gocmp.Diff(orig, got); diff != "" {
		t.Errorf("round trip mismatch (-want +got):\n%s\nJSON: %s", diff, b)
	}
}

func TestMapString(t *testing.T) {
	t.Parallel()

	m := anyMap("b", 1, "a", "x")
	if got, want := m.String(), `{"b": 1, "a": x}`; got != want {
		t.Errorf("String() = %s, want %s", got, want)
	}
}

func BenchmarkMapSetGet(b *testing.B) {
	for _, size := range []int{4, 13, 64} {
		keys := slices.Collect(func(yield func(string) bool) {
			for i := range size {
				if !yield("key_" + strconv.Itoa(i)) {
					return
				}
			}
		})
		b.Run("size="+strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				m := New[int]()
				for i, k := range keys {
					m.Set(k, i)
				}
				for _, k := range keys {
					if _, ok := m.Get(k); !ok {
						b.Fatalf("missing %q", k)
					}
				}
			}
		})
	}
}

func BenchmarkMapPopAll(b *testing.B) {
	for _, size := range []int{13, 64} {
		keys := make([]string, size)
		for i := range size {
			keys[i] = "key_" + strconv.Itoa(i)
		}
		b.Run("size="+strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				m := NewWithCapacity[int](len(keys))
				for i, k := range keys {
					m.Set(k, i)
				}
				for _, k := range keys {
					m.Pop(k)
				}
			}
		})
	}
}

func BenchmarkMapJSONMarshal(b *testing.B) {
	m := New[any]()
	for i := range 16 {
		m.Set("key_"+strconv.Itoa(i), int64(i))
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := json.Marshal(m); err != nil {
			b.Fatal(err)
		}
	}
}

// bytesKeyMap is anyMap with every key a byte-string key.
func bytesKeyMap(kv ...any) *Map[any] {
	m := New[any]()
	for i := 0; i < len(kv); i += 2 {
		m.SetBytesKey(kv[i].(string), kv[i+1])
	}
	return m
}

func TestMapBytesKey(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		size int
	}{
		"success: small map":   {size: 2},
		"success: indexed map": {size: 20},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m := New[int]()
			apply(m, manyKeys(tt.size))
			m.SetBytesKey("\xff", 1)
			m.SetBytesKey("k0", 2)
			m.Set("\xff", 3)

			kinds := map[string]bool{}
			for k := range m.All() {
				kinds[k] = m.IsBytesKey(k)
			}
			want := map[string]bool{"\xff": true}
			for _, k := range keyRange(0, tt.size) {
				want[k] = k == "k0"
			}
			if diff := gocmp.Diff(want, kinds); diff != "" {
				t.Errorf("key kinds mismatch (-want +got):\n%s", diff)
			}
			if v, _ := m.Get("\xff"); v != 3 {
				t.Errorf("Get(\\xff) = %d after Set, want 3", v)
			}
			wantKeys := append(keyRange(0, tt.size), "\xff")
			if diff := gocmp.Diff(wantKeys, m.Keys()); diff != "" {
				t.Errorf("SetBytesKey moved a key (-want +got):\n%s", diff)
			}

			c := m.Clone()
			if !c.IsBytesKey("k0") || !c.Equal(m) {
				t.Error("Clone lost a byte-string key")
			}
			m.Pop("k0")
			m.Set("k0", 0)
			if m.IsBytesKey("k0") {
				t.Error("a key set again after Pop is still a byte-string key")
			}
			if !c.IsBytesKey("k0") {
				t.Error("changing the original changed the clone's key kind")
			}
		})
	}

	var nilMap *Map[int]
	if nilMap.IsBytesKey("k") || New[int]().IsBytesKey("k") {
		t.Error("IsBytesKey reported an absent key")
	}
	if got, want := bytesKeyMap("k", 1).String(), `{b"k": 1}`; got != want {
		t.Errorf("String() = %s, want %s", got, want)
	}
}
