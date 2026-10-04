// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command

import (
	"fmt"
	"reflect"
)

// Type is the identity of a command parameter or return type, the Go
// counterpart of an entry in mitmproxy's CommandTypes registry.
//
// Identities are compared with ==. The basic identities are the *Type
// variables of this package; a choice is a [ChoiceType] value and two choices
// are equal when they name the same options command.
type Type interface {
	// Name returns the identity name, for example "Path" or "StrSeq".
	Name() string
	// Display returns the user-facing type name upstream prints in signature
	// help, for example "path" or "str[]".
	Display() string
}

// basicType is an identity bound to at most one Go type. A nil goType means
// the identity cannot appear in a command signature.
type basicType struct {
	name    string
	display string
	goType  reflect.Type
}

// Name implements [Type].
func (t *basicType) Name() string { return t.name }

// Display implements [Type].
func (t *basicType) Display() string { return t.display }

// String returns the identity name.
func (t *basicType) String() string { return t.name }

// Go types for the identities that need a type of their own in a command
// signature. They mirror the annotation classes of mitmproxy.types.
type (
	// Path is a filesystem path argument.
	Path string

	// Cmd is the name of another command.
	Cmd string

	// CmdArgs is an argument passed through to the command named by a [Cmd]
	// parameter.
	CmdArgs string

	// Marker is a flow marker: "true", "false" or an emoji shortcode.
	Marker string

	// CutSpec is a list of flow attribute selectors for the cut addon, such
	// as "request.host" or "response.header[content-type]".
	CutSpec []string

	// Data is a table of rows whose cells are each a string or a []byte.
	Data [][]any
)

// The type identities registered with mitmproxy's CommandTypes.
//
// FlowType and FlowsType carry no Go binding yet: a command whose signature
// needs them cannot be registered until the flow model provides one.
var (
	ArgType     Type = &basicType{name: "Arg", display: "arg", goType: reflect.TypeFor[CmdArgs]()}
	BoolType    Type = &basicType{name: "Bool", display: "bool", goType: reflect.TypeFor[bool]()}
	BytesType   Type = &basicType{name: "Bytes", display: "bytes", goType: reflect.TypeFor[[]byte]()}
	CmdType     Type = &basicType{name: "Cmd", display: "cmd", goType: reflect.TypeFor[Cmd]()}
	CutSpecType Type = &basicType{name: "CutSpec", display: "cut[]", goType: reflect.TypeFor[CutSpec]()}
	DataType    Type = &basicType{name: "Data", display: "data[][]", goType: reflect.TypeFor[Data]()}
	FlowType    Type = &basicType{name: "Flow", display: "flow"}
	FlowsType   Type = &basicType{name: "Flows", display: "flow[]"}
	IntType     Type = &basicType{name: "Int", display: "int", goType: reflect.TypeFor[int]()}
	MarkerType  Type = &basicType{name: "Marker", display: "marker", goType: reflect.TypeFor[Marker]()}
	PathType    Type = &basicType{name: "Path", display: "path", goType: reflect.TypeFor[Path]()}
	StrType     Type = &basicType{name: "Str", display: "str", goType: reflect.TypeFor[string]()}
	StrSeqType  Type = &basicType{name: "StrSeq", display: "str[]", goType: reflect.TypeFor[[]string]()}
)

// ChoiceType is a string parameter restricted to the values returned by
// another command.
type ChoiceType struct {
	// OptionsCommand names the command that returns the valid choices.
	OptionsCommand string
}

// Choice returns the identity of a string parameter whose valid values are
// returned by the command named optionsCommand. Attach it to a parameter
// with [WithArgument].
func Choice(optionsCommand string) Type {
	return ChoiceType{OptionsCommand: optionsCommand}
}

// Name implements [Type].
func (ChoiceType) Name() string { return "Choice" }

// Display implements [Type].
func (ChoiceType) Display() string { return "choice" }

// byGoType maps each Go type a command signature may use to its identity.
var byGoType = func() map[reflect.Type]Type {
	m := make(map[reflect.Type]Type)
	for _, t := range []Type{ArgType, BoolType, BytesType, CmdType, CutSpecType, DataType, IntType, MarkerType, PathType, StrType, StrSeqType} {
		m[t.(*basicType).goType] = t
	}
	return m
}()

// TypeFor returns the identity of the Go type rt, the type a command
// parameter or return value of that Go type is registered with. It returns
// an error wrapping [ErrSignature] when rt has no identity.
func TypeFor(rt reflect.Type) (Type, error) {
	if t, ok := byGoType[rt]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("%w: unsupported type: %v", ErrSignature, rt)
}

// goTypeOf returns the Go type a parameter must have to carry the identity
// t, or nil when no parameter can.
func goTypeOf(t Type) reflect.Type {
	switch t := t.(type) {
	case *basicType:
		return t.goType
	case ChoiceType:
		return reflect.TypeFor[string]()
	default:
		return nil
	}
}
