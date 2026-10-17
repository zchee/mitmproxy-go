// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build ignore

package dumper

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

type definitionMetadataView struct{ contentviews.Raw }

func (definitionMetadataView) Name() string { return "DefinitionMetadata" }

func (definitionMetadataView) Prettify(_ []byte, metadata contentviews.Metadata) (string, error) {
	return fmt.Sprintf("%s|%t", metadata.ProtobufDefinitions, metadata.HTTPRequest != nil), nil
}

func TestContentviewDefinitions(t *testing.T) {
	fixture, err := filepath.Abs(filepath.Join("..", "..", "testdata", "mitmproxy-rs", "contentviews", "protobuf", "simple.proto"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fixture); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		value  *string
		change bool
		after  *string
		want   string
	}{
		"unset":                      {},
		"empty":                      {value: new("")},
		"relative":                   {value: new("schema.proto"), want: "schema.proto"},
		"existing fixture":           {value: new(fixture), want: fixture},
		"home stays unchanged":       {value: new("~"), want: "~"},
		"home child stays unchanged": {value: new("~" + string(os.PathSeparator) + "schema.proto"), want: "~" + string(os.PathSeparator) + "schema.proto"},
		"changed between renders":    {value: new(fixture), change: true, after: new("next.proto"), want: "next.proto"},
		"cleared between renders":    {value: new(fixture), change: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d, manager, _ := setup(t)
			if err := configure(t, manager, map[string]any{"protobuf_definitions": tt.value, "dumper_default_contentview": "DefinitionMetadata"}); err != nil {
				t.Fatal(err)
			}
			f := testflow.TFlow(testflow.WithResponse)
			f.Response.SetContent([]byte("body"))
			if tt.change {
				_ = d.contentviewMetadata(f)
				if err := configure(t, manager, map[string]any{"protobuf_definitions": tt.after}); err != nil {
					t.Fatal(err)
				}
			}
			got := d.contentviewMetadata(f)
			if got.Flow != f {
				t.Fatal("metadata lost the flow identity")
			}
			got.Flow = nil
			if diff := cmp.Diff(contentviews.Metadata{ProtobufDefinitions: tt.want}, got); diff != "" {
				t.Fatalf("definition metadata differs (-want +got):\n%s", diff)
			}
			registry := contentviews.NewRegistry()
			registry.Register(definitionMetadataView{})
			pretty := d.prettifyContentview(f.Response, f, registry)
			if pretty.Err != nil {
				t.Fatal(pretty.Err)
			}
			if diff := cmp.Diff(tt.want+"|false", pretty.Text); diff != "" {
				t.Fatalf("response metadata did not reach the view (-want +got):\n%s", diff)
			}
			request := d.prettifyContentview(f.Request, f, registry)
			if request.Err != nil {
				t.Fatal(request.Err)
			}
			if diff := cmp.Diff(tt.want+"|true", request.Text); diff != "" {
				t.Fatalf("request metadata did not reach the view (-want +got):\n%s", diff)
			}
			if string(f.Response.RawContent) != "body" {
				t.Fatal("render mutated message bytes")
			}
			configured := tt.value
			if tt.change {
				configured = tt.after
			}
			if diff := cmp.Diff(configured, d.options.OptStr("protobuf_definitions")); diff != "" {
				t.Fatalf("render mutated option (-want +got):\n%s", diff)
			}
		})
	}
}
