// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package options

import (
	"errors"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

// TestSet ports test_set of mitmproxy's test_optmanager.py. The steps share
// one Manager because several of them (toggle, the sequence resets) depend
// on the state the previous step left.
func TestSet(t *testing.T) {
	m := newTTypes(t)
	steps := []struct {
		name    string
		specs   []string
		option  string
		want    any
		wantErr string // substring of the expected *OptionsError; empty for success
	}{
		{name: "success: str", specs: []string{"str=foo"}, option: "str", want: "foo"},
		{name: "error: str requires a value", specs: []string{"str"}, option: "str", want: "foo", wantErr: "Option is required: str"},
		{name: "success: optstr", specs: []string{"optstr=foo"}, option: "optstr", want: new("foo")},
		{name: "success: bare optstr is None", specs: []string{"optstr"}, option: "optstr", want: (*string)(nil)},
		{name: "success: empty optstr is empty string", specs: []string{"optstr="}, option: "optstr", want: new("")},
		{name: "error: optstr multiple values", specs: []string{"optstr=foo", "optstr=bar"}, option: "optstr", want: new(""), wantErr: "Received multiple values for optstr: ['foo', 'bar']"},
		{name: "success: bool false", specs: []string{"bool=false"}, option: "bool", want: false},
		{name: "success: bare bool is true", specs: []string{"bool"}, option: "bool", want: true},
		{name: "success: bool true", specs: []string{"bool=true"}, option: "bool", want: true},
		{name: "error: bool garbage", specs: []string{"bool=wobble"}, option: "bool", want: true, wantErr: "Failed to parse option bool: "},
		{name: "success: bool toggle off", specs: []string{"bool=toggle"}, option: "bool", want: false},
		{name: "success: bool toggle on", specs: []string{"bool=toggle"}, option: "bool", want: true},
		{name: "error: bool multiple values", specs: []string{"bool=false", "bool="}, option: "bool", want: true, wantErr: "Received multiple values for bool: ['false', '']"},
		{name: "success: bool false again", specs: []string{"bool=false"}, option: "bool", want: false},
		{name: "success: empty bool is true", specs: []string{"bool="}, option: "bool", want: true},
		{name: "success: int", specs: []string{"int=1"}, option: "int", want: 1},
		{name: "error: int garbage", specs: []string{"int=wobble"}, option: "int", want: 1, wantErr: "Failed to parse option int: not an integer: wobble"},
		{name: "error: int requires a value", specs: []string{"int"}, option: "int", want: 1, wantErr: "Option is required: int"},
		{name: "error: empty int requires a value", specs: []string{"int="}, option: "int", want: 1, wantErr: "Option is required: int"},
		{name: "success: int with python syntax", specs: []string{"int= -1_000 "}, option: "int", want: -1000},
		{name: "success: bare optint is None", specs: []string{"optint"}, option: "optint", want: (*int)(nil)},
		{name: "success: optint", specs: []string{"optint=8080"}, option: "optint", want: new(8080)},
		{name: "success: empty optint is None", specs: []string{"optint="}, option: "optint", want: (*int)(nil)},
		{name: "success: seq single", specs: []string{"seqstr=foo"}, option: "seqstr", want: []string{"foo"}},
		{name: "success: seq accumulates", specs: []string{"seqstr=foo", "seqstr=bar"}, option: "seqstr", want: []string{"foo", "bar"}},
		{name: "success: bare seq is empty", specs: []string{"seqstr"}, option: "seqstr", want: []string{}},
		{name: "success: seq value with equals sign", specs: []string{"seqstr=a=b", "seqstr"}, option: "seqstr", want: []string{"a=b"}},
		{name: "success: choices are not enforced", specs: []string{"choices=qux"}, option: "choices", want: "qux"},
		{name: "error: unknown option", specs: []string{"deferredoption=wobble", "other"}, option: "str", want: "foo", wantErr: "Unknown option(s): deferredoption, other"},
	}
	for _, st := range steps {
		err := m.Set(t.Context(), st.specs...)
		switch {
		case st.wantErr == "" && err != nil:
			t.Fatalf("%s: Set(%q) = %v", st.name, st.specs, err)
		case st.wantErr != "":
			var oe *OptionsError
			if !errors.As(err, &oe) || !strings.Contains(err.Error(), st.wantErr) {
				t.Fatalf("%s: Set(%q) = %v, want *OptionsError containing %q", st.name, st.specs, err, st.wantErr)
			}
		}
		if diff := gocmp.Diff(st.want, m.Current(st.option)); diff != "" {
			t.Fatalf("%s: %s after Set(%q) mismatch (-want +got):\n%s", st.name, st.option, st.specs, diff)
		}
	}
}

func TestSetDeferred(t *testing.T) {
	m := newTTypes(t)
	if err := m.SetDeferred(t.Context(), "deferredoption=wobble", "str=now"); err != nil {
		t.Fatal(err)
	}
	if got := m.Str("str"); got != "now" {
		t.Errorf("known option set by SetDeferred = %q, want now", got)
	}
	if _, ok := m.Deferred()["deferredoption"]; !ok {
		t.Fatal("deferredoption not deferred")
	}
	if err := m.ProcessDeferred(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Deferred()["deferredoption"]; !ok {
		t.Fatal("deferredoption processed before it was registered")
	}
	mustAdd(t, m, "deferredoption", TypeStr, "default", "help")
	if err := m.ProcessDeferred(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Deferred()["deferredoption"]; ok {
		t.Error("deferredoption still deferred after ProcessDeferred")
	}
	if got := m.Str("deferredoption"); got != "wobble" {
		t.Errorf("deferredoption = %q, want wobble", got)
	}

	if err := m.SetDeferred(t.Context(), "deferredsequenceoption=a", "deferredsequenceoption=b"); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(map[string]any{"deferredsequenceoption": Unparsed{"a", "b"}}, m.Deferred()); diff != "" {
		t.Errorf("Deferred (-want +got):\n%s", diff)
	}
	if err := m.ProcessDeferred(t.Context()); err != nil {
		t.Fatal(err)
	}
	mustAdd(t, m, "deferredsequenceoption", TypeSeq, []string{}, "help")
	if err := m.ProcessDeferred(t.Context()); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]string{"a", "b"}, m.Seq("deferredsequenceoption")); diff != "" {
		t.Errorf("deferredsequenceoption (-want +got):\n%s", diff)
	}
	if len(m.Deferred()) != 0 {
		t.Errorf("Deferred = %v, want empty", m.Deferred())
	}
}

func TestSetDeferredParsesWithRegisteredType(t *testing.T) {
	m := NewManager()
	if err := m.SetDeferred(t.Context(), "flag", "port=bad"); err != nil {
		t.Fatal(err)
	}
	mustAdd(t, m, "flag", TypeBool, false, "help")
	mustAdd(t, m, "port", TypeInt, 1, "help")
	err := m.ProcessDeferred(t.Context())
	var oe *OptionsError
	if !errors.As(err, &oe) || !strings.Contains(err.Error(), "not an integer: bad") {
		t.Fatalf("ProcessDeferred = %v, want *OptionsError about port", err)
	}
	if m.Bool("flag") {
		t.Error("flag applied although ProcessDeferred failed")
	}
	if len(m.Deferred()) != 2 {
		t.Errorf("Deferred = %v, want both entries kept", m.Deferred())
	}
}

func TestParseSetVal(t *testing.T) {
	m := newTO(t)
	tests := map[string]struct {
		name    string
		values  []string
		want    any
		wantErr bool
	}{
		"error: required int without value": {name: "required_int", values: []string{}, wantErr: true},
		"success: required int":             {name: "required_int", values: []string{"5"}, want: 5},
		"success: optional int":             {name: "one", values: []string{"5"}, want: new(5)},
		"success: toggle reads current":     {name: "bool", values: []string{"toggle"}, want: true},
		"error: unknown option":             {name: "nope", values: []string{"1"}, wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := m.ParseSetVal(tt.name, tt.values)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSetVal(%q, %q) error = %v, wantErr %v", tt.name, tt.values, err, tt.wantErr)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseSetVal mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPyInt(t *testing.T) {
	tests := map[string]struct {
		in     string
		want   int
		wantOK bool
	}{
		"success: plain":                 {in: "42", want: 42, wantOK: true},
		"success: negative":              {in: "-7", want: -7, wantOK: true},
		"success: plus sign":             {in: "+7", want: 7, wantOK: true},
		"success: surrounding space":     {in: " \t8\n", want: 8, wantOK: true},
		"success: underscores":           {in: "1_000_000", want: 1000000, wantOK: true},
		"success: leading zeros decimal": {in: "010", want: 10, wantOK: true},
		"error: empty":                   {in: "", wantOK: false},
		"error: sign only":               {in: "-", wantOK: false},
		"error: double sign":             {in: "+-1", wantOK: false},
		"error: leading underscore":      {in: "_1", wantOK: false},
		"error: trailing underscore":     {in: "1_", wantOK: false},
		"error: double underscore":       {in: "1__0", wantOK: false},
		"error: hex":                     {in: "0x10", wantOK: false},
		"error: float":                   {in: "1.5", wantOK: false},
		"error: inner space":             {in: "1 0", wantOK: false},
		"error: overflow":                {in: "99999999999999999999999", wantOK: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := pyInt(tt.in)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("pyInt(%q) = (%d, %v), want (%d, %v)", tt.in, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
