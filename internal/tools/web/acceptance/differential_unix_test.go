// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest && unix

package acceptance_test

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

type webCapturedReply struct {
	Status      int
	ContentType string
	Body        []byte
}

type webCapturedFlow struct {
	JSON     any
	Get      webCapturedReply
	Request  *webCapturedReply
	Response *webCapturedReply
}

type webCapturedFixture struct {
	Flows   []webCapturedFlow
	Replies map[string]webCapturedReply
	Values  map[string]any
	State   map[string]any
}

func TestMitmwebDifferential(t *testing.T) {
	recordPythonWebProvenance(t)
	binary := buildWebExecutable(t)
	artifacts := filepath.Join(filepath.Dir(testutil.FixturePath(t, ".")), "_test", "web-differential")
	if override := os.Getenv("MITMPROXY_TEST_WEB_ARTIFACTS"); override != "" {
		artifacts = override
	}
	if !filepath.IsAbs(artifacts) {
		t.Fatal("differential artifacts must use an absolute owned path")
	}
	t.Setenv("MITMPROXY_TEST_WEB_ARTIFACTS", artifacts)
	tests := map[string]struct{ fixture string }{
		"corrupted_gzip_body.mitm": {"corrupted_gzip_body.mitm"},
		"diff_data.mitm":           {"diff_data.mitm"},
		"error_log.mitm":           {"error_log.mitm"},
		"event_stream.mitm":        {"event_stream.mitm"},
		"incomplete_log.mitm":      {"incomplete_log.mitm"},
		"successful_log.mitm":      {"successful_log.mitm"},
		"websocket.mitm":           {"websocket.mitm"},
	}
	for name, tt := range tests {
		t.Run("fixtures/"+name, func(t *testing.T) {
			fixture := "mitmproxy/flows/" + tt.fixture
			count := webFixtureFlowCount(t, testutil.Fixture(t, fixture))
			tuple := newWebInputTuple(t, testutil.FixturePath(t, fixture))
			uv, arguments := pythonWebCommand(t, tuple)
			python := captureWebFixture(t, startWebProcess(t, uv, arguments, "python"), tuple, count, false)
			resetWebConfdir(t, tuple)
			goResult := captureWebFixture(t, startWebProcess(t, binary, tuple.goArgs(), "go"), tuple, count, true)
			if diff := gocmp.Diff(python.Flows, goResult.Flows); diff != "" {
				t.Errorf("flows, same-id GET or raw body routes differ (-python +go):\n%s", diff)
			}
			if diff := gocmp.Diff(python.Replies, goResult.Replies); diff != "" {
				t.Errorf("endpoint status/content type differs (-python +go):\n%s", diff)
			}
			if diff := gocmp.Diff(python.Values, goResult.Values); diff != "" {
				t.Errorf("endpoint JSON differs (-python +go):\n%s", diff)
			}
			if !gocmp.Equal(python.State, goResult.State) {
				t.Error("state contentViews/servers differ; secret-bearing snapshots are not logged")
			}
		})
	}
	t.Run("live_flows_add", func(t *testing.T) {
		testLiveWebFlows(t, binary)
	})
}

func webFixtureFlowCount(t *testing.T, raw []byte) int {
	t.Helper()
	ids := make(map[string]struct{})
	for value, err := range flowio.NewReader(bytes.NewReader(raw)).All() {
		if err != nil {
			t.Fatal(err)
		}
		ids[value.Common().ID] = struct{}{}
	}
	if len(ids) == 0 {
		t.Fatal("differential fixture has no flows")
	}
	return len(ids)
}

func captureWebFixture(t *testing.T, process *webProcess, tuple webInputTuple, count int, goRuntime bool) webCapturedFixture {
	t.Helper()
	defer func() {
		process.stop(t)
		verifyWebPortsReleased(t, tuple)
	}()
	client := webClient(t)
	waitWebReady(t, process, client, tuple, func(state []byte) bool {
		if !expectedWebListener(state) {
			return false
		}
		status, _, raw, err := requestWeb(t.Context(), client, tuple, http.MethodGet, "/flows", nil)
		var flows []jsontext.Value
		return err == nil && status == http.StatusOK && json.Unmarshal(raw, &flows) == nil && len(flows) == count
	})
	result := webCapturedFixture{Replies: make(map[string]webCapturedReply), Values: make(map[string]any), State: make(map[string]any)}
	flowsReply := captureWebReply(t, client, tuple, "/flows")
	if flowsReply.Status != http.StatusOK {
		t.Fatalf("flows endpoint status=%d", flowsReply.Status)
	}
	result.Replies["/flows"] = webCapturedReply{Status: flowsReply.Status, ContentType: flowsReply.ContentType}
	var flows []jsontext.Value
	if err := json.Unmarshal(flowsReply.Body, &flows); err != nil || len(flows) != count {
		t.Fatalf("flow inventory count=%d expected=%d decode_error=%v", len(flows), count, err)
	}
	normalizer := new(webBijections)
	seen := make(map[string]struct{})
	for _, raw := range flows {
		if err := decodeFlowSchema(raw); err != nil {
			t.Fatal(err)
		}
		var identity struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &identity); err != nil {
			t.Fatal(err)
		}
		if _, duplicate := seen[identity.ID]; duplicate {
			t.Fatal("flow collection contains duplicate ids")
		}
		seen[identity.ID] = struct{}{}
		value, err := normalizer.flow(raw)
		if err != nil {
			t.Fatal(err)
		}
		path := "/flows/" + url.PathEscape(identity.ID)
		captured := webCapturedFlow{JSON: value, Get: captureWebReply(t, client, tuple, path)}
		if captured.Get.Status != http.StatusMethodNotAllowed {
			t.Fatalf("GET /flows/<id> status=%d, want upstream method-not-allowed", captured.Get.Status)
		}
		if identity.Type == "http" {
			var fields map[string]jsontext.Value
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			for _, part := range []string{"request", "response"} {
				body, exists := fields[part]
				if !exists || body.Kind() == 'n' {
					continue
				}
				reply := captureWebReply(t, client, tuple, path+"/"+part+"/content.data")
				if part == "request" {
					captured.Request = &reply
				} else {
					captured.Response = &reply
				}
			}
		}
		result.Flows = append(result.Flows, captured)
	}
	for _, route := range []string{"/filter-help", "/commands", "/options", "/state"} {
		reply := captureWebReply(t, client, tuple, route)
		if reply.Status != http.StatusOK {
			t.Fatalf("endpoint %s status=%d", route, reply.Status)
		}
		value, err := decodeWebComparable(reply.Body)
		if err != nil {
			t.Fatalf("endpoint %s did not return valid comparable JSON", route)
		}
		result.Replies[route] = webCapturedReply{Status: reply.Status, ContentType: reply.ContentType}
		if route == "/state" {
			state, ok := value.(map[string]any)
			if !ok {
				t.Fatal("state must be a JSON object")
			}
			for _, name := range []string{"contentViews", "servers"} {
				field, exists := state[name]
				if !exists {
					t.Fatalf("state is missing %s", name)
				}
				result.State[name] = field
			}
		} else {
			result.Values[route] = value
		}
	}
	adaptWebFixtureMetadata(t, result.Values, goRuntime)
	return result
}

func captureWebReply(t *testing.T, client *http.Client, tuple webInputTuple, route string) webCapturedReply {
	t.Helper()
	status, contentType, raw, err := requestWeb(t.Context(), client, tuple, http.MethodGet, route, nil)
	if err != nil {
		t.Fatalf("endpoint %s: %v", route, err)
	}
	return webCapturedReply{Status: status, ContentType: contentType, Body: raw}
}

func adaptWebFixtureMetadata(t *testing.T, values map[string]any, goRuntime bool) {
	t.Helper()
	options, ok := values["/options"].(map[string]any)
	if !ok {
		t.Fatal("options must be a JSON object")
	}
	commands, ok := values["/commands"].(map[string]any)
	if !ok {
		t.Fatal("commands must be a JSON object")
	}
	if goRuntime {
		for line := range strings.Lines(string(testutil.Fixture(t, "options-go-only.txt"))) {
			name, _, exists := strings.Cut(line, "\t")
			if exists {
				delete(options, name)
			}
		}
		return
	}
	delete(options, "scripts")
	delete(commands, "script.run")
	browser, ok := commands["browser.start"].(map[string]any)
	if !ok {
		t.Fatal("pinned Python registry is missing browser.start")
	}
	wantParameters := []any{map[string]any{"name": "browser", "type": "str", "kind": "POSITIONAL_OR_KEYWORD"}}
	if !gocmp.Equal(browser["parameters"], wantParameters) || browser["signature_help"] != "browser.start browser" {
		t.Fatal("browser.start metadata no longer matches the named compatibility adapter")
	}
	browser["parameters"] = []any{map[string]any{"name": "arg0", "type": "str", "kind": "VAR_POSITIONAL"}}
	browser["signature_help"] = "browser.start *arg0"
	export, ok := commands["export"].(map[string]any)
	if !ok || export["return_type"] != "str" || export["signature_help"] != "export format f -> str" {
		t.Fatal("export metadata no longer matches the named byte-result adapter")
	}
	export["return_type"] = "bytes"
	export["signature_help"] = "export format f -> bytes"
}
