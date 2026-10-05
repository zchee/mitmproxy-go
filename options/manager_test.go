// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package options

import (
	"context"
	"errors"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

func mustAdd(t testing.TB, m *Manager, name string, typ Type, def any, help string, opts ...AddOption) {
	t.Helper()
	if err := m.Add(t.Context(), name, typ, def, help, opts...); err != nil {
		t.Fatalf("Add(%q): %v", name, err)
	}
}

// newTO mirrors the TO fixture of mitmproxy's test_optmanager.py.
func newTO(t testing.TB) *Manager {
	m := NewManager()
	mustAdd(t, m, "one", TypeOptInt, nil, "help")
	mustAdd(t, m, "two", TypeOptInt, 2, "help")
	mustAdd(t, m, "bool", TypeBool, false, "help")
	mustAdd(t, m, "required_int", TypeInt, 2, "help")
	return m
}

// newTD2 mirrors the TD2 fixture of mitmproxy's test_optmanager.py.
func newTD2(t testing.TB) *Manager {
	m := NewManager()
	mustAdd(t, m, "one", TypeStr, "done", "help")
	mustAdd(t, m, "two", TypeStr, "dtwo", "help")
	mustAdd(t, m, "three", TypeStr, "dthree", "help")
	mustAdd(t, m, "four", TypeStr, "dfour", "help")
	return m
}

// newTTypes mirrors the TTypes fixture of mitmproxy's test_optmanager.py,
// without the float option, which has no Go option type.
func newTTypes(t testing.TB) *Manager {
	m := NewManager()
	mustAdd(t, m, "str", TypeStr, "str", "help")
	mustAdd(t, m, "choices", TypeStr, "foo", "help", WithChoices("foo", "bar", "baz"))
	mustAdd(t, m, "optstr", TypeOptStr, "optstr", "help")
	mustAdd(t, m, "bool", TypeBool, false, "help")
	mustAdd(t, m, "bool_on", TypeBool, true, "help")
	mustAdd(t, m, "int", TypeInt, 0, "help")
	mustAdd(t, m, "optint", TypeOptInt, 0, "help")
	mustAdd(t, m, "seqstr", TypeSeq, []string{}, "help")
	return m
}

func TestDefaults(t *testing.T) {
	m := newTD2(t)
	want := map[string]string{"one": "done", "two": "dtwo", "three": "dthree", "four": "dfour"}
	for k, v := range want {
		if got := m.Default(k); got != v {
			t.Errorf("Default(%q) = %v, want %q", k, got, v)
		}
	}
	if m.HasChanged("one") {
		t.Fatal("HasChanged(one) = true before any update")
	}

	newvals := map[string]any{"one": "xone", "two": "xtwo", "three": "xthree", "four": "xfour"}
	if err := m.Update(t.Context(), newvals); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !m.HasChanged("one") {
		t.Error("HasChanged(one) = false after update")
	}
	for k, v := range newvals {
		if got := m.Str(k); got != v {
			t.Errorf("Str(%q) = %q, want %q", k, got, v)
		}
	}

	if err := m.Reset(t.Context()); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	for _, k := range m.Keys() {
		if m.HasChanged(k) {
			t.Errorf("HasChanged(%q) = true after Reset", k)
		}
	}
}

func TestOptions(t *testing.T) {
	m := newTO(t)
	if diff := gocmp.Diff([]string{"one", "two", "bool", "required_int"}, m.Keys()); diff != "" {
		t.Errorf("Keys() mismatch (-want +got):\n%s", diff)
	}
	if got := m.OptInt("one"); got != nil {
		t.Errorf("OptInt(one) = %v, want nil", *got)
	}
	if got := m.OptInt("two"); got == nil || *got != 2 {
		t.Errorf("OptInt(two) = %v, want 2", got)
	}
	if err := m.Update(t.Context(), map[string]any{"one": 1}); err != nil {
		t.Fatalf("Update(one=1): %v", err)
	}
	if got := m.OptInt("one"); got == nil || *got != 1 {
		t.Errorf("OptInt(one) = %v, want 1", got)
	}

	var unknownErr *UnknownOptionError
	if err := m.Update(t.Context(), map[string]any{"nonexistent": "value"}); !errors.As(err, &unknownErr) || !strings.Contains(err.Error(), "Unknown options") {
		t.Errorf("Update(nonexistent) = %v, want *UnknownOptionError", err)
	}
	unknown, err := m.UpdateKnown(t.Context(), map[string]any{"nonexistent": "value"})
	if err != nil {
		t.Fatalf("UpdateKnown: %v", err)
	}
	if diff := gocmp.Diff(map[string]any{"nonexistent": "value"}, unknown); diff != "" {
		t.Errorf("UpdateKnown unknown mismatch (-want +got):\n%s", diff)
	}

	var rec []int
	m.Subscribe(func(context.Context, map[string]struct{}) error {
		rec = append(rec, *m.OptInt("one"))
		return nil
	})
	if err := m.Update(t.Context(), map[string]any{"one": 90}); err != nil {
		t.Fatal(err)
	}
	if err := m.Update(t.Context(), map[string]any{"one": 3}); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]int{90, 3}, rec); diff != "" {
		t.Errorf("subscriber saw (-want +got):\n%s", diff)
	}
}

func TestUpdateAppliesKnownDespiteUnknown(t *testing.T) {
	m := newTO(t)
	err := m.Update(t.Context(), map[string]any{"one": 5, "zzz": 1, "aaa": 2})
	var unknownErr *UnknownOptionError
	if !errors.As(err, &unknownErr) {
		t.Fatalf("Update = %v, want *UnknownOptionError", err)
	}
	if diff := gocmp.Diff([]string{"aaa", "zzz"}, unknownErr.Names); diff != "" {
		t.Errorf("unknown names (-want +got):\n%s", diff)
	}
	if got := m.OptInt("one"); got == nil || *got != 5 {
		t.Errorf("OptInt(one) = %v, want 5: upstream applies the known options first", got)
	}
}

func TestUpdateTypeCheckIsAtomic(t *testing.T) {
	m := newTO(t)
	calls := 0
	m.Subscribe(func(context.Context, map[string]struct{}) error { calls++; return nil })
	err := m.Update(t.Context(), map[string]any{"two": 7, "bool": "yes"})
	var typeErr *TypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("Update = %v, want *TypeError", err)
	}
	if typeErr.Name != "bool" || typeErr.Type != TypeBool {
		t.Errorf("TypeError = %+v, want bool/TypeBool", typeErr)
	}
	if want := "Expected bool for bool, but got string."; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	if got := *m.OptInt("two"); got != 2 {
		t.Errorf("OptInt(two) = %d, want 2 (unchanged)", got)
	}
	if calls != 0 {
		t.Errorf("subscriber called %d times, want 0", calls)
	}
}

func TestCoerce(t *testing.T) {
	tests := map[string]struct {
		typ     Type
		in      any
		want    any
		wantErr bool
	}{
		"success: bool":                     {typ: TypeBool, in: true, want: true},
		"error: int for bool":               {typ: TypeBool, in: 1, wantErr: true},
		"success: int":                      {typ: TypeInt, in: 42, want: 42},
		"success: int64 from decoder":       {typ: TypeInt, in: int64(42), want: 42},
		"success: uint8":                    {typ: TypeInt, in: uint8(7), want: 7},
		"error: bool for int":               {typ: TypeInt, in: true, wantErr: true},
		"error: float for int":              {typ: TypeInt, in: 1.0, wantErr: true},
		"error: string for int":             {typ: TypeInt, in: "1", wantErr: true},
		"error: nil for int":                {typ: TypeInt, in: nil, wantErr: true},
		"success: str":                      {typ: TypeStr, in: "x", want: "x"},
		"error: nil for str":                {typ: TypeStr, in: nil, wantErr: true},
		"success: seq from []string":        {typ: TypeSeq, in: []string{"a", "b"}, want: []string{"a", "b"}},
		"success: seq from decoded list":    {typ: TypeSeq, in: []any{"a", "b"}, want: []string{"a", "b"}},
		"success: seq from nil slice":       {typ: TypeSeq, in: []string(nil), want: []string{}},
		"error: seq with non-string":        {typ: TypeSeq, in: []any{"a", 1}, wantErr: true},
		"error: string for seq":             {typ: TypeSeq, in: "a", wantErr: true},
		"success: optstr nil":               {typ: TypeOptStr, in: nil, want: (*string)(nil)},
		"success: optstr string":            {typ: TypeOptStr, in: "x", want: new("x")},
		"success: optstr pointer":           {typ: TypeOptStr, in: new("y"), want: new("y")},
		"success: optstr typed nil pointer": {typ: TypeOptStr, in: (*string)(nil), want: (*string)(nil)},
		"error: int for optstr":             {typ: TypeOptStr, in: 1, wantErr: true},
		"success: optint nil":               {typ: TypeOptInt, in: nil, want: (*int)(nil)},
		"success: optint int":               {typ: TypeOptInt, in: 8080, want: new(8080)},
		"success: optint pointer":           {typ: TypeOptInt, in: new(1), want: new(1)},
		"error: string for optint":          {typ: TypeOptInt, in: "1", wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := coerce("opt", tt.typ, tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("coerce(%v, %#v) error = %v, wantErr %v", tt.typ, tt.in, err, tt.wantErr)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("coerce(%v, %#v) mismatch (-want +got):\n%s", tt.typ, tt.in, diff)
			}
		})
	}
}

func TestAddRejectsBadDefault(t *testing.T) {
	m := NewManager()
	var typeErr *TypeError
	if err := m.Add(t.Context(), "test", TypeStr, 1, "help"); !errors.As(err, &typeErr) {
		t.Fatalf("Add(str, 1) = %v, want *TypeError", err)
	}
	if m.Has("test") {
		t.Error("option registered despite a bad default")
	}
}

func TestAddNotifiesAndNormalisesHelp(t *testing.T) {
	m := NewManager()
	var got []map[string]struct{}
	m.Subscribe(func(_ context.Context, u map[string]struct{}) error { got = append(got, u); return nil })
	mustAdd(t, m, "x", TypeBool, false, `
            First line
            second line.
            `)
	if diff := gocmp.Diff([]map[string]struct{}{{"x": {}}}, got); diff != "" {
		t.Errorf("notifications (-want +got):\n%s", diff)
	}
	o, ok := m.Lookup("x")
	if !ok {
		t.Fatal("Lookup(x) not found")
	}
	if want := "First line second line."; o.Help() != want {
		t.Errorf("Help() = %q, want %q", o.Help(), want)
	}
}

func TestGetters(t *testing.T) {
	m := newTTypes(t)
	if got := m.Str("str"); got != "str" {
		t.Errorf("Str = %q", got)
	}
	if got := m.OptStr("optstr"); got == nil || *got != "optstr" {
		t.Errorf("OptStr = %v", got)
	}
	if got := m.Bool("bool_on"); !got {
		t.Error("Bool(bool_on) = false")
	}
	if got := m.Int("int"); got != 0 {
		t.Errorf("Int = %d", got)
	}
	if got := m.OptInt("optint"); got == nil || *got != 0 {
		t.Errorf("OptInt = %v", got)
	}
	if got := m.Seq("seqstr"); got == nil || len(got) != 0 {
		t.Errorf("Seq = %#v, want non-nil empty slice", got)
	}
	if got := Get[string](m, "choices"); got != "foo" {
		t.Errorf("Get[string](choices) = %q", got)
	}
}

func TestGettersReturnCopies(t *testing.T) {
	m := NewManager()
	mustAdd(t, m, "seq", TypeSeq, []string{"a"}, "help")
	mustAdd(t, m, "os", TypeOptStr, "x", "help")
	s := m.Seq("seq")
	s[0] = "mutated"
	p := m.OptStr("os")
	*p = "mutated"
	if got := m.Seq("seq"); got[0] != "a" {
		t.Errorf("Seq after mutating a returned copy = %v", got)
	}
	if got := *m.OptStr("os"); got != "x" {
		t.Errorf("OptStr after mutating a returned copy = %q", got)
	}
	if m.HasChanged("seq") || m.HasChanged("os") {
		t.Error("HasChanged reports a change made through a returned copy")
	}
}

func TestGetterPanics(t *testing.T) {
	m := newTO(t)
	tests := map[string]struct {
		call func()
		want string
	}{
		"panic: unknown option": {call: func() { m.Bool("unknown") }, want: "No such option: unknown"},
		"panic: type mismatch":  {call: func() { m.Str("bool") }, want: "option bool has type bool, not string"},
		"panic: generic get":    {call: func() { Get[int](m, "one") }, want: "option one has type optional int, not int"},
		"panic: Current":        {call: func() { m.Current("nope") }, want: "No such option: nope"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("no panic")
				}
				if got, _ := r.(string); got != tt.want {
					t.Errorf("panic = %v, want %q", r, tt.want)
				}
			}()
			tt.call()
		})
	}
}

func TestItems(t *testing.T) {
	m := newTTypes(t)
	if err := m.Update(t.Context(), map[string]any{"int": 5}); err != nil {
		t.Fatal(err)
	}
	items := m.Items()
	names := make([]string, len(items))
	for i, o := range items {
		names[i] = o.Name()
	}
	if diff := gocmp.Diff(m.Keys(), names); diff != "" {
		t.Errorf("Items order (-want +got):\n%s", diff)
	}
	byName := make(map[string]Option)
	for _, o := range items {
		byName[o.Name()] = o
	}
	if o := byName["int"]; o.Current() != 5 || o.Default() != 0 || !o.HasChanged() || o.Type() != TypeInt {
		t.Errorf("int option snapshot = %+v", o)
	}
	if diff := gocmp.Diff([]string{"foo", "bar", "baz"}, byName["choices"].Choices()); diff != "" {
		t.Errorf("Choices (-want +got):\n%s", diff)
	}
	if byName["str"].Choices() != nil {
		t.Errorf("Choices of str = %v, want nil", byName["str"].Choices())
	}
}

// TestRollback ports test_rollback: a subscriber that rejects a change with
// an OptionsError restores the previous values, every subscriber sees both
// the rejected change and the rollback, and error subscribers are told.
func TestRollback(t *testing.T) {
	m := newTO(t)

	type seen struct {
		One  *int
		Bool bool
	}
	var rec []seen
	m.Subscribe(func(context.Context, map[string]struct{}) error {
		rec = append(rec, seen{One: m.OptInt("one"), Bool: m.Bool("bool")})
		return nil
	})
	m.Subscribe(func(context.Context, map[string]struct{}) error {
		if one := m.OptInt("one"); one != nil && *one == 10 {
			return &OptionsError{}
		}
		if m.Bool("bool") {
			return Errorf("bool rejected")
		}
		return nil
	})
	var errored []error
	m.OnError(func(err error) { errored = append(errored, err) })

	var oe *OptionsError
	if err := m.Update(t.Context(), map[string]any{"one": 10}); !errors.As(err, &oe) {
		t.Fatalf("Update(one=10) = %v, want *OptionsError", err)
	}
	if got := m.OptInt("one"); got != nil {
		t.Errorf("one = %d after rollback, want nil", *got)
	}
	if err := m.Update(t.Context(), map[string]any{"bool": true}); !errors.As(err, &oe) || err.Error() != "bool rejected" {
		t.Fatalf("Update(bool=true) = %v, want *OptionsError(bool rejected)", err)
	}
	if m.Bool("bool") {
		t.Error("bool = true after rollback")
	}

	want := []seen{
		{One: new(10), Bool: false},
		{One: nil, Bool: false},
		{One: nil, Bool: true},
		{One: nil, Bool: false},
	}
	if diff := gocmp.Diff(want, rec); diff != "" {
		t.Errorf("subscriber observations (-want +got):\n%s", diff)
	}
	if len(errored) != 2 {
		t.Fatalf("OnError called %d times, want 2", len(errored))
	}
	for _, err := range errored {
		if !errors.As(err, &oe) {
			t.Errorf("OnError got %T, want *OptionsError", err)
		}
	}
}

func TestRollbackOnlyForOptionsError(t *testing.T) {
	m := newTO(t)
	plain := errors.New("plain failure")
	m.Subscribe(func(context.Context, map[string]struct{}) error { return plain })
	if err := m.Update(t.Context(), map[string]any{"required_int": 9}); !errors.Is(err, plain) {
		t.Fatalf("Update = %v, want %v", err, plain)
	}
	if got := m.Int("required_int"); got != 9 {
		t.Errorf("required_int = %d, want 9: errors other than OptionsError do not roll back", got)
	}
}

func TestRollbackWrappedOptionsError(t *testing.T) {
	m := newTO(t)
	m.Subscribe(func(context.Context, map[string]struct{}) error {
		return errors.Join(errors.New("context"), Errorf("wrapped"))
	})
	if err := m.Update(t.Context(), map[string]any{"required_int": 9}); err == nil {
		t.Fatal("Update succeeded")
	}
	if got := m.Int("required_int"); got != 2 {
		t.Errorf("required_int = %d, want 2 (rolled back)", got)
	}
}

func TestSubscribeCancel(t *testing.T) {
	m := newTO(t)
	var got []map[string]struct{}
	cancel := m.Subscribe(func(_ context.Context, u map[string]struct{}) error { got = append(got, u); return nil })
	if err := m.Update(t.Context(), map[string]any{"one": 1, "two": 3}); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := m.Update(t.Context(), map[string]any{"one": 2}); err != nil {
		t.Fatal(err)
	}
	want := []map[string]struct{}{{"one": {}, "two": {}}}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Errorf("notifications (-want +got):\n%s", diff)
	}
}

func TestReentrantUpdateFromSubscriber(t *testing.T) {
	m := newTO(t)
	m.Subscribe(func(_ context.Context, u map[string]struct{}) error {
		if _, ok := u["one"]; ok {
			return m.Update(t.Context(), map[string]any{"two": *m.OptInt("one") * 2})
		}
		return nil
	})
	if err := m.Update(t.Context(), map[string]any{"one": 21}); err != nil {
		t.Fatal(err)
	}
	if got := *m.OptInt("two"); got != 42 {
		t.Errorf("two = %d, want 42", got)
	}
}

// TestNestedUpdateRollback pins how a rejected update interacts with an
// update a subscriber made from inside the notification. The expectations
// were produced by running the same subscribers against mitmproxy's
// OptManager (mitmproxy/optmanager.py, update_known and rollback): a
// rollback restores the snapshot taken when the rejected update started, so
// it also reverts a nested update that had succeeded, and it re-announces
// only the names of the rejected update.
func TestNestedUpdateRollback(t *testing.T) {
	type event struct {
		Sub     string
		Updated []string
		A, B    int
	}
	type subscriberFunc func(ctx context.Context, m *Manager, updated map[string]struct{}, log *[]event) error
	record := func(name string, m *Manager, updated map[string]struct{}, log *[]event) {
		*log = append(*log, event{Sub: name, Updated: slices.Sorted(maps.Keys(updated)), A: m.Int("a"), B: m.Int("b")})
	}
	tests := map[string]struct {
		first, second subscriberFunc
		wantErr       bool
		wantA, wantB  int
		wantLog       []event
	}{
		"error: rejecting the outer update reverts a nested update that succeeded": {
			first: func(ctx context.Context, m *Manager, updated map[string]struct{}, log *[]event) error {
				record("first", m, updated, log)
				if _, ok := updated["a"]; ok && m.Int("a") == 1 {
					return m.Update(ctx, map[string]any{"b": 2})
				}
				return nil
			},
			second: func(_ context.Context, m *Manager, updated map[string]struct{}, log *[]event) error {
				record("second", m, updated, log)
				if _, ok := updated["a"]; ok && m.Int("a") == 1 && m.Int("b") == 2 {
					return Errorf("reject")
				}
				return nil
			},
			wantErr: true,
			wantA:   0,
			wantB:   0,
			wantLog: []event{
				{Sub: "first", Updated: []string{"a"}, A: 1, B: 0},
				{Sub: "first", Updated: []string{"b"}, A: 1, B: 2},
				{Sub: "second", Updated: []string{"b"}, A: 1, B: 2},
				{Sub: "second", Updated: []string{"a"}, A: 1, B: 2},
				// The rollback restores b as well but announces only a.
				{Sub: "first", Updated: []string{"a"}, A: 0, B: 0},
				{Sub: "second", Updated: []string{"a"}, A: 0, B: 0},
			},
		},
		"success: a rejected nested update rolls back to its own snapshot": {
			first: func(ctx context.Context, m *Manager, updated map[string]struct{}, log *[]event) error {
				record("first", m, updated, log)
				if _, ok := updated["a"]; ok && m.Int("a") == 1 {
					// The subscriber handles the rejection itself, so the
					// outer update goes on.
					var oe *OptionsError
					if err := m.Update(ctx, map[string]any{"b": 2}); !errors.As(err, &oe) {
						return err
					}
				}
				return nil
			},
			second: func(_ context.Context, m *Manager, updated map[string]struct{}, log *[]event) error {
				record("second", m, updated, log)
				if m.Int("b") == 2 {
					return Errorf("reject b")
				}
				return nil
			},
			wantA: 1,
			wantB: 0,
			wantLog: []event{
				{Sub: "first", Updated: []string{"a"}, A: 1, B: 0},
				{Sub: "first", Updated: []string{"b"}, A: 1, B: 2},
				{Sub: "second", Updated: []string{"b"}, A: 1, B: 2},
				// The nested rollback keeps a, which the outer update set
				// before the nested one started.
				{Sub: "first", Updated: []string{"b"}, A: 1, B: 0},
				{Sub: "second", Updated: []string{"b"}, A: 1, B: 0},
				{Sub: "second", Updated: []string{"a"}, A: 1, B: 0},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := NewManager()
			mustAdd(t, m, "a", TypeInt, 0, "help")
			mustAdd(t, m, "b", TypeInt, 0, "help")
			var log []event
			m.Subscribe(func(ctx context.Context, u map[string]struct{}) error { return tt.first(ctx, m, u, &log) })
			m.Subscribe(func(ctx context.Context, u map[string]struct{}) error { return tt.second(ctx, m, u, &log) })

			err := m.Update(t.Context(), map[string]any{"a": 1})
			var oe *OptionsError
			switch {
			case tt.wantErr && !errors.As(err, &oe):
				t.Fatalf("Update(a=1) = %v, want *OptionsError", err)
			case !tt.wantErr && err != nil:
				t.Fatalf("Update(a=1) = %v, want nil", err)
			}
			if got := m.Int("a"); got != tt.wantA {
				t.Errorf("a = %d, want %d", got, tt.wantA)
			}
			if got := m.Int("b"); got != tt.wantB {
				t.Errorf("b = %d, want %d", got, tt.wantB)
			}
			if diff := gocmp.Diff(tt.wantLog, log); diff != "" {
				t.Errorf("subscriber calls (-want +got):\n%s", diff)
			}
		})
	}
}

// TestConcurrentReads checks the documented concurrency contract: reads may
// run on any goroutine while a single goroutine makes the changes.
func TestConcurrentReads(t *testing.T) {
	m := newTO(t)
	var wg sync.WaitGroup
	wg.Go(func() {
		for j := range 1000 {
			if err := m.Update(t.Context(), map[string]any{"required_int": j}); err != nil {
				t.Error(err)
				return
			}
		}
	})
	for range 8 {
		wg.Go(func() {
			for range 200 {
				_ = m.Int("required_int")
				_ = m.Items()
				_ = m.HasChanged("required_int")
			}
		})
	}
	wg.Wait()
}

func TestUpdateDeferred(t *testing.T) {
	m := newTD2(t)
	if err := m.UpdateDeferred(t.Context(), map[string]any{"one": "x", "later": []any{"a"}}); err != nil {
		t.Fatal(err)
	}
	if got := m.Str("one"); got != "x" {
		t.Errorf("one = %q", got)
	}
	if diff := gocmp.Diff(map[string]any{"later": []any{"a"}}, m.Deferred()); diff != "" {
		t.Errorf("Deferred (-want +got):\n%s", diff)
	}
	mustAdd(t, m, "later", TypeSeq, []string{}, "help")
	if err := m.ProcessDeferred(t.Context()); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]string{"a"}, m.Seq("later")); diff != "" {
		t.Errorf("later (-want +got):\n%s", diff)
	}
	if len(m.Deferred()) != 0 {
		t.Errorf("Deferred = %v, want empty", m.Deferred())
	}
}

func TestPyRepr(t *testing.T) {
	tests := map[string]struct {
		in   string
		want string
	}{
		"success: plain":                {in: "foo", want: "'foo'"},
		"success: single quote":         {in: "it's", want: `"it's"`},
		"success: both quotes":          {in: `it's "x"`, want: `'it\'s "x"'`},
		"success: control characters":   {in: "a\tb\nc\x01", want: `'a\tb\nc\x01'`},
		"success: backslash":            {in: `a\b`, want: `'a\\b'`},
		"success: printable non-ascii":  {in: "café", want: "'café'"},
		"success: non-printable latin1": {in: "\u0085", want: `'\x85'`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := pyrepr.Str(tt.in); got != tt.want {
				t.Errorf("pyrepr.Str(%q) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
	if got, want := pyListRepr([]string{"foo", "bar"}), "['foo', 'bar']"; got != want {
		t.Errorf("pyListRepr = %s, want %s", got, want)
	}
}

func TestTypeString(t *testing.T) {
	got := make(map[string]string)
	for _, typ := range []Type{TypeBool, TypeInt, TypeStr, TypeSeq, TypeOptStr, TypeOptInt, Type(0)} {
		got[typ.String()] = ""
	}
	want := []string{"Type(0)", "bool", "int", "optional int", "optional str", "sequence of str", "str"}
	if diff := gocmp.Diff(want, slices.Sorted(maps.Keys(got)), cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("Type names (-want +got):\n%s", diff)
	}
}

type ctxKey struct{}

// TestSubscribersReceiveCallerContext checks that every method announcing a
// change hands its context to the subscribers unchanged, including the
// second notification of a rollback.
func TestSubscribersReceiveCallerContext(t *testing.T) {
	m := newTO(t)
	var seen []any
	m.Subscribe(func(ctx context.Context, u map[string]struct{}) error {
		seen = append(seen, ctx.Value(ctxKey{}))
		if _, ok := u["required_int"]; ok && m.Int("required_int") == 13 {
			return Errorf("unlucky")
		}
		return nil
	})
	ctx := context.WithValue(t.Context(), ctxKey{}, "caller")
	confdir := t.TempDir()
	conf := filepath.Join(confdir, "config.yaml")
	writeFile(t, conf, "one: 8\n")
	if err := m.SetDeferred(t.Context(), "late=true"); err != nil {
		t.Fatal(err)
	}
	mustAdd(t, m, "late", TypeBool, false, "help")
	calls := map[string]func() error{
		"Add":             func() error { return m.Add(ctx, "added", TypeInt, 0, "help") },
		"Update":          func() error { return m.Update(ctx, map[string]any{"one": 1}) },
		"UpdateKnown":     func() error { _, err := m.UpdateKnown(ctx, map[string]any{"one": 2}); return err },
		"UpdateDeferred":  func() error { return m.UpdateDeferred(ctx, map[string]any{"one": 3}) },
		"Set":             func() error { return m.Set(ctx, "one=4") },
		"SetDeferred":     func() error { return m.SetDeferred(ctx, "one=5") },
		"ProcessDeferred": func() error { return m.ProcessDeferred(ctx) },
		"Reset":           func() error { return m.Reset(ctx) },
		"Load":            func() error { return m.Load(ctx, "one: 6\n") },
		"LoadPaths":       func() error { return m.LoadPaths(ctx, conf) },
		"LoadAll":         func() error { return m.LoadAll(ctx, []string{"two=7"}, confdir, nil) },
	}
	for name, call := range calls {
		seen = nil
		if err := call(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(seen) == 0 {
			t.Errorf("%s: no notification", name)
		}
		for _, v := range seen {
			if v != "caller" {
				t.Errorf("%s: subscriber saw context value %v, want caller", name, v)
			}
		}
	}

	seen = nil
	var oe *OptionsError
	if err := m.Update(ctx, map[string]any{"required_int": 13}); !errors.As(err, &oe) {
		t.Fatalf("Update(required_int=13) = %v, want *OptionsError", err)
	}
	if diff := gocmp.Diff([]any{"caller", "caller"}, seen); diff != "" {
		t.Errorf("contexts seen around a rollback (-want +got):\n%s", diff)
	}
}
