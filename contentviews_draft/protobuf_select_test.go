// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestProtobufDescriptorSelection(t *testing.T) {
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    new("selection.proto"),
		Syntax:  new("proto3"),
		Package: new("example"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: new("First")},
			{Name: new("Request")},
			{Name: new("Response"), NestedType: []*descriptorpb.DescriptorProto{{Name: new("Nested")}}},
			{Name: new("Direct")},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{
			{Name: new("Other"), Method: []*descriptorpb.MethodDescriptorProto{{Name: new("FirstCall"), InputType: new(".example.Request"), OutputType: new(".example.First")}}},
			{Name: new("Service"), Method: []*descriptorpb.MethodDescriptorProto{
				{Name: new("Method"), InputType: new(".example.Request"), OutputType: new(".example.Response")},
				{Name: new("Nested"), InputType: new(".example.Request"), OutputType: new(".example.Response.Nested")},
			}},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		path    string
		request bool
		want    string
	}{
		"request":              {"/example.Service/Method", true, "example.Request"},
		"response":             {"/example.Service/Method", false, "example.Response"},
		"nested response":      {"/example.Service/Nested", false, "example.Response.Nested"},
		"top-level message":    {"/example.Service/Direct", false, "example.Direct"},
		"missing service":      {"/example.Missing/Direct", false, "example.Direct"},
		"empty path":           {"", false, "example.First"},
		"query fallback":       {"/example.Service/Method?x=1", false, "example.First"},
		"extra slash fallback": {"/example.Service/Method/more", false, "example.First"},
		"missing method":       {"/example.Service/Other", false, "example.First"},
		"wrong package":        {"/different.Service/Method", false, "example.First"},
		"no package":           {"/Service/Method", false, "example.First"},
		"leading slashes":      {"///example.Service/Method", false, "example.Response"},
		"fallback input":       {"/missing/method", true, "example.Request"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := selectProtobufMessage([]protoreflect.FileDescriptor{file}, tt.path, tt.request)
			if got == nil {
				t.Fatal("no descriptor selected")
			}
			if diff := cmp.Diff(tt.want, string(got.FullName())); diff != "" {
				t.Fatalf("descriptor mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProtobufDescriptorFallbackOrder(t *testing.T) {
	empty, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{Name: new("empty.proto"), Syntax: new("proto3")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: new("messages.proto"), Syntax: new("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: new("First")}, {Name: new("Second")}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		files []protoreflect.FileDescriptor
		path  string
		want  string
	}{
		"none":                 {},
		"empty first file":     {files: []protoreflect.FileDescriptor{empty, messages}},
		"message fallback":     {files: []protoreflect.FileDescriptor{messages}, want: "First"},
		"match in second file": {files: []protoreflect.FileDescriptor{empty, messages}, path: "/Unused/Second", want: "Second"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := selectProtobufMessage(tt.files, tt.path, false)
			if tt.want == "" {
				if got != nil {
					t.Fatalf("unexpected descriptor: %s", got.FullName())
				}
				return
			}
			if got == nil || string(got.FullName()) != tt.want {
				t.Fatalf("got %v, want %s", got, tt.want)
			}
		})
	}
}
