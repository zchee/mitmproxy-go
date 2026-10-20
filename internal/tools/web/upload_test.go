// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"io"
	"mime/multipart"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

type uploadPart struct {
	field, filename string
	body            []byte
}

func multipartBody(t *testing.T, parts []uploadPart) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.SetBoundary("owned-upload-boundary"); err != nil {
		t.Fatal(err)
	}
	for _, part := range parts {
		var target io.Writer
		var err error
		if part.filename == "" {
			target, err = writer.CreateFormField(part.field)
		} else {
			target, err = writer.CreateFormFile(part.field, part.filename)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := target.Write(part.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes(), writer.FormDataContentType()
}

func dumpBody(t *testing.T, ids ...string) []byte {
	t.Helper()
	var body bytes.Buffer
	writer := flowio.NewWriter(&body)
	for _, id := range ids {
		value := testflow.TFlow(testflow.WithResponse)
		value.ID = id
		if err := writer.Add(value); err != nil {
			t.Fatal(err)
		}
	}
	return body.Bytes()
}

func testWebMultipartContent(t *testing.T, h *routeHarness) {
	body := []byte("--somefancyboundary\r\nContent-Disposition: form-data; name=\"a\"; filename=\"a.txt\"\r\n\r\nsuch multipart. very wow.\r\n--somefancyboundary--\r\n")
	h.status(t, "POST", "/flows/42/request/content.data", body, `multipart/form-data; boundary="somefancyboundary"`, 200)
	h.do(t, func(context.Context) error {
		value := h.app.view.GetByID("42")
		if diff := gocmp.Diff([]byte("such multipart. very wow."), value.(*flow.HTTPFlow).Request.ContentOrRaw()); diff != "" {
			t.Fatal(diff)
		}
		if !value.Modified() {
			t.Fatal("multipart upload did not back up the flow")
		}
		return value.Revert()
	})
}

func testWebFormArguments(t *testing.T) {
	tests := map[string]struct {
		path, form, text string
		emptyDump        bool
	}{
		"lines_from_form":          {path: "/flows/42/request/content/raw", form: "lines=1", text: "foo\n"},
		"first_form_value":         {path: "/flows/42/request/content/raw", form: "lines=1&lines=2", text: "foo\n"},
		"query_before_form":        {path: "/flows/42/request/content/raw?lines=2", form: "lines=1", text: "foo\nbar"},
		"filter_from_form":         {path: "/flows/dump", form: "filter=foo", emptyDump: true},
		"filter_query_before_form": {path: "/flows/dump?filter=foo", form: "filter=~all", emptyDump: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h := newRouteHarness(t)
			body := h.status(t, "GET", test.path, []byte(test.form), "application/x-www-form-urlencoded", 200)
			if test.emptyDump {
				if len(body) != 0 {
					t.Fatalf("filtered dump has %d bytes", len(body))
				}
				return
			}
			var value map[string]any
			if err := json.Unmarshal(body, &value); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(test.text, value["text"]); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func testWebUploadContracts(t *testing.T) {
	tests := map[string]struct {
		parts       []uploadPart
		raw         []byte
		contentType string
		dump        bool
		want        []byte
		ids         []string
	}{
		"content_raw":                    {raw: []byte("raw body"), contentType: "application/octet-stream", want: []byte("raw body")},
		"content_form_raw_fallback":      {raw: []byte("payload=raw%20body&x=1+2"), contentType: "application/x-www-form-urlencoded", want: []byte("payload=raw%20body&x=1+2")},
		"content_multipart_raw_fallback": {parts: []uploadPart{{field: "text", body: []byte("only a field")}}},
		"content_file_order_a":           {parts: []uploadPart{{field: "a", filename: "a.txt", body: []byte("first a")}, {field: "b", filename: "b.txt", body: []byte("second b")}}, want: []byte("first a")},
		"content_file_order_b":           {parts: []uploadPart{{field: "b", filename: "b.txt", body: []byte("first b")}, {field: "a", filename: "a.txt", body: []byte("second a")}}, want: []byte("first b")},
		"content_value_before_file":      {parts: []uploadPart{{field: "text", body: []byte("not a file")}, {field: "b", filename: "b.txt", body: []byte("selected file")}, {field: "a", filename: "a.txt", body: []byte("ignored file")}}, want: []byte("selected file")},
		"dump_raw":                       {dump: true, ids: []string{"a1", "a2"}},
		"dump_multipart":                 {dump: true, ids: []string{"a1", "a2"}, parts: []uploadPart{{field: "flows", filename: "flows.mitm"}}},
		"dump_file_order":                {dump: true, ids: []string{"a1"}, parts: []uploadPart{{field: "b", filename: "first.mitm"}, {field: "a", filename: "second.mitm", body: dumpBody(t, "b1")}}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h := newRouteHarness(t)
			body, contentType := test.raw, test.contentType
			if test.dump {
				body = dumpBody(t, test.ids...)
				if contentType == "" {
					contentType = "application/octet-stream"
				}
			}
			if test.parts != nil {
				if test.dump {
					test.parts[0].body = body
				}
				body, contentType = multipartBody(t, test.parts)
			}
			path := "/flows/42/request/content.data"
			if test.dump {
				path = "/flows/dump"
			}
			if got := h.status(t, "POST", path, body, contentType, 200); len(got) != 0 {
				t.Fatalf("upload response=%q", got)
			}
			h.do(t, func(context.Context) error {
				if test.dump {
					got := make([]string, 0, h.app.view.Len())
					for _, value := range h.app.view.Flows() {
						got = append(got, value.Common().ID)
					}
					if diff := gocmp.Diff(test.ids, got); diff != "" {
						t.Fatal(diff)
					}
					return nil
				}
				expected := test.want
				if expected == nil {
					expected = body
				}
				value := h.app.view.GetByID("42")
				if diff := gocmp.Diff(expected, value.(*flow.HTTPFlow).Request.ContentOrRaw()); diff != "" {
					t.Fatal(diff)
				}
				if !value.Modified() {
					t.Fatal("upload did not preserve a revert backup")
				}
				return nil
			})
		})
	}
}
