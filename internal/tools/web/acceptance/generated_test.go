// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package acceptance_test

import (
	json "encoding/json/v2"
	"encoding/pem"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/contentviews/highlight"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio/flowjson"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/options"
)

// The upstream generators are references, never executable build steps. These
// checks bind their output vocabulary to the Go codecs, registry and mode types.
func TestWebGeneratedBindings(t *testing.T) {
	tests := map[string]struct{ check func(*testing.T) }{
		"backend_consts.py": {checkBackendConstants},
		"options_js.py":     {checkGeneratedOptions},
		"state_js.py":       {checkGeneratedState},
		"tflow_js.py":       {checkGeneratedFlows},
		"web_columns.py":    {checkGeneratedColumns},
	}
	for name, tt := range tests {
		t.Run("upstream/test_generated_files/"+name, tt.check)
	}
}

func checkBackendConstants(t *testing.T) {
	source := string(testutil.Fixture(t, "mitmproxy/web/src/js/backends/consts.ts"))
	enums := regexp.MustCompile(`(?s)export enum (\w+) \{(.*?)\}`).FindAllStringSubmatch(source, -1)
	if len(enums) != 2 {
		t.Fatalf("enum count = %d, want 2", len(enums))
	}
	entry := regexp.MustCompile(`(?m)^    (\w+) = "([^"]+)",$`)
	for _, enum := range enums {
		var values []string
		for _, value := range entry.FindAllStringSubmatch(enum[2], -1) {
			if value[1] != strings.ToUpper(value[2]) {
				t.Errorf("enum key %q disagrees with %q", value[1], value[2])
			}
			values = append(values, value[2])
		}
		switch enum[1] {
		case "SyntaxHighlight":
			if diff := cmp.Diff(highlight.Languages(), values); diff != "" {
				t.Errorf("syntax vocabulary (-Go +frontend):\n%s", diff)
			}
		case "ReverseProxyProtocols":
			if len(values) != 9 {
				t.Fatalf("reverse schemes = %v, want all 9", values)
			}
			for _, scheme := range values {
				mode, err := modespec.Parse("reverse:" + scheme + "://example.test:443")
				if err != nil {
					t.Fatal(err)
				}
				reverse, ok := mode.(modespec.ReverseMode)
				if !ok || reverse.Scheme != scheme {
					t.Fatalf("reverse scheme %s: mode=%v", scheme, mode)
				}
			}
		default:
			t.Fatalf("unexpected enum %s", enum[1])
		}
	}
}

func checkGeneratedOptions(t *testing.T) {
	source := string(testutil.Fixture(t, "mitmproxy/web/src/js/ducks/_options_gen.ts"))
	declarations := regexp.MustCompile(`(?m)^    (\w+): ([^;\n]+);$`).FindAllStringSubmatch(source, -1)
	defaults := regexp.MustCompile(`(?m)^    (\w+): ([^\n]+),$`).FindAllStringSubmatch(source, -1)
	if len(declarations) != 103 || len(defaults) != 103 {
		t.Fatalf("WebMaster option inventory: declarations=%d defaults=%d, want 103 each", len(declarations), len(defaults))
	}
	type row struct{ typ, value string }
	manifest := make(map[string]row)
	for line := range strings.SplitSeq(strings.TrimSpace(string(testutil.Fixture(t, "options-upstream.txt"))), "\n") {
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) != 4 {
			t.Fatalf("malformed option manifest row %q", line)
		}
		manifest[parts[0]] = row{parts[1], parts[2]}
	}
	types := map[string]string{"bool": "boolean", "int": "number", "str": "string", "optional str": "string | undefined", "optional int": "number | undefined", "sequence of str": "string[]"}
	seen := make(map[string]bool)
	core := options.New()
	for i, declaration := range declarations {
		name, typ := declaration[1], declaration[2]
		want, exists := manifest[name]
		if !exists || types[want.typ] != typ || defaults[i][1] != name || seen[name] {
			t.Fatalf("generated option %q: type=%q manifest=%+v default=%v duplicate=%v", name, typ, want, defaults[i], seen[name])
		}
		seen[name] = true
		value := strings.ReplaceAll(defaults[i][2], "undefined", "null")
		var gotValue, wantValue any
		if err := json.Unmarshal([]byte(value), &gotValue); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(want.value), &wantValue); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(wantValue, gotValue); diff != "" {
			t.Errorf("%s default (-manifest +generated):\n%s", name, diff)
		}
		if option, exists := core.Lookup(name); exists {
			raw, err := json.Marshal(option.Default())
			if err != nil {
				t.Fatal(err)
			}
			var goValue any
			if err := json.Unmarshal(raw, &goValue); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(wantValue, goValue); diff != "" {
				t.Errorf("core %s default (-frontend +Go):\n%s", name, diff)
			}
			if option.Type().String() != want.typ {
				t.Errorf("core %s type = %s, want %s", name, option.Type(), want.typ)
			}
		}
	}
	var omitted []string
	for name := range manifest {
		if !seen[name] {
			omitted = append(omitted, name)
		}
	}
	slices.Sort(omitted)
	wantOmitted := []string{"console_default_contentview", "console_eventlog_verbosity", "console_flowlist_layout", "console_layout", "console_layout_headers", "console_mouse", "console_palette", "console_palette_transparent", "console_quickhelp_visible", "console_strip_trailing_newlines", "dumper_default_contentview", "dumper_filter", "flow_detail", "keepserving"}
	if diff := cmp.Diff(wantOmitted, omitted); diff != "" {
		t.Errorf("non-WebMaster option inventory (-want +got):\n%s", diff)
	}
}

type generatedServerState struct {
	Description   string          `json:"description"`
	FullSpec      string          `json:"full_spec"`
	IsRunning     bool            `json:"is_running"`
	LastException *string         `json:"last_exception"`
	ListenAddrs   []schemaAddress `json:"listen_addrs"`
	Type          string          `json:"type"`
	TunName       *string         `json:"tun_name,omitzero"`
}

func checkGeneratedState(t *testing.T) {
	source := string(testutil.Fixture(t, "mitmproxy/web/src/js/__tests__/ducks/_tbackendstate.ts"))
	_, object, exists := strings.Cut(source, "    return ")
	if !exists {
		t.Fatal("generated state has no return object")
	}
	object, _, exists = strings.Cut(object, "\n}")
	if !exists {
		t.Fatal("generated state has no function terminator")
	}
	var state struct {
		Available            bool                            `json:"available"`
		ContentViews         []string                        `json:"contentViews"`
		LocalModeUnavailable *string                         `json:"localModeUnavailable"`
		Platform             string                          `json:"platform"`
		Servers              map[string]generatedServerState `json:"servers"`
		Version              string                          `json:"version"`
	}
	if err := json.Unmarshal([]byte(object), &state, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if !state.Available || state.Version != "1.2.3" || state.Platform != "darwin" || state.LocalModeUnavailable != nil {
		t.Fatalf("generated state constants = %+v", state)
	}
	if diff := cmp.Diff([]string{"auto", "Raw"}, state.ContentViews); diff != "" {
		t.Error(diff)
	}
	if _, ok := contentviews.NewRegistry().Get("Raw"); !ok {
		t.Fatal("generated Raw view absent from Go registry")
	}
	if diff := cmp.Diff([]string{"regular", "reverse:example.com", "socks5", "tun"}, slices.Sorted(maps.Keys(state.Servers))); diff != "" {
		t.Error(diff)
	}
	for spec, server := range state.Servers {
		mode, err := modespec.Parse(spec)
		if err != nil {
			t.Fatal(err)
		}
		if server.FullSpec != spec || server.Type != mode.Name() || server.Description != mode.Description() {
			t.Errorf("%s vocabulary: frontend=%+v Go=%v", spec, server, mode)
		}
	}
	regular := state.Servers["regular"]
	if !regular.IsRunning || len(regular.ListenAddrs) != 2 || state.Servers["reverse:example.com"].LastException == nil || state.Servers["tun"].TunName == nil || *state.Servers["tun"].TunName != "tun0" {
		t.Fatalf("generated running/error/special-field fixtures incomplete: %+v", state.Servers)
	}
}

func checkGeneratedFlows(t *testing.T) {
	source := testutil.Fixture(t, "mitmproxy/web/src/js/__tests__/ducks/_tflow.ts")
	functions := regexp.MustCompile(`(?ms)^export function T(HTTP|TCP|UDP|DNS)Flow\(\): Required<\w+> \{\n    return (.*?)^\}`).FindAllSubmatch(source, -1)
	if len(functions) != 4 {
		t.Fatalf("generated flow inventory = %d, want 4", len(functions))
	}
	flows := map[string]flow.Flow{
		"HTTP": testflow.TFlow(testflow.WithResponse, testflow.WithError, testflow.WithWebSocket),
		"TCP":  testflow.TTCPFlow(testflow.WithError),
		"UDP":  testflow.TUDPFlow(testflow.WithError),
		"DNS":  testflow.TDNSFlow(testflow.WithResponse, testflow.WithError),
	}
	// The fixture's certificate bytes differ; only its typed output vocabulary is
	// compared here. Exact HTTP values are the separate live-Python contract.
	block, _ := pem.Decode(testutil.Fixture(t, "mitmproxy/confdir/mitmproxy-ca-cert.pem"))
	if block == nil {
		t.Fatal("fixture CA has no certificate")
	}
	httpFlow := flows["HTTP"].(*flow.HTTPFlow)
	httpFlow.ServerConn.CertificateList = [][]byte{pem.EncodeToMemory(block)}
	httpFlow.Response.Trailers.Add("trailer", "qvalue")
	for _, function := range functions {
		name := string(function[1])
		raw := []byte(strings.ReplaceAll(string(function[2]), ": undefined", ": null"))
		if err := decodeFlowSchema(raw); err != nil {
			t.Fatalf("frontend %s: %v", name, err)
		}
		object, err := flowjson.Flow(flows[name])
		if err != nil {
			t.Fatal(err)
		}
		goRaw, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		var expected, actual any
		if err := json.Unmarshal(raw, &expected); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(goRaw, &actual); err != nil {
			t.Fatal(err)
		}
		if err := compareGeneratedShape(expected, actual, name); err != nil {
			t.Error(err)
		}
	}
}

func compareGeneratedShape(expected, actual any, path string) error {
	if reflect.TypeOf(expected) != reflect.TypeOf(actual) {
		return fmt.Errorf("%s: frontend type %T differs from Go %T", path, expected, actual)
	}
	switch expected := expected.(type) {
	case map[string]any:
		actual := actual.(map[string]any)
		if diff := cmp.Diff(slices.Sorted(maps.Keys(expected)), slices.Sorted(maps.Keys(actual))); diff != "" {
			return fmt.Errorf("%s keys (-frontend +Go):\n%s", path, diff)
		}
		for key, value := range expected {
			if err := compareGeneratedShape(value, actual[key], path+"/"+key); err != nil {
				return err
			}
		}
	case []any:
		actual := actual.([]any)
		// Lists may contain different numbers of headers, SANs or DNS records;
		// every emitted element must implement the pinned element vocabulary.
		if len(expected) != 0 {
			for i, value := range actual {
				shape := expected[min(i, len(expected)-1)]
				if err := compareGeneratedShape(shape, value, fmt.Sprintf("%s/%d", path, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkGeneratedColumns(t *testing.T) {
	source := string(testutil.Fixture(t, "mitmproxy/web/src/js/components/FlowTable/FlowColumns.tsx"))
	_, list, ok := strings.Cut(source, "// parsed by web/gen/web_columns\n")
	if !ok {
		t.Fatal("column generator marker absent")
	}
	list, _, ok = strings.Cut(list, "}")
	if !ok {
		t.Fatal("column export terminator absent")
	}
	var frontend []string
	for part := range strings.SplitSeq(list, ",") {
		if name := strings.TrimSpace(part); name != "" {
			frontend = append(frontend, name)
		}
	}
	backend := testutil.Fixture(t, "mitmproxy/tools/web/web_columns.py")
	_, raw, ok := strings.Cut(string(backend), "AVAILABLE_WEB_COLUMNS = ")
	if !ok {
		t.Fatal("generated column vocabulary absent")
	}
	var columns []string
	// The generator emits one trailing comma before the closing bracket.
	raw = strings.ReplaceAll(raw, ",\n]", "\n]")
	if err := json.Unmarshal([]byte(raw), &columns); err != nil {
		t.Fatal(err)
	}
	if len(columns) != 12 {
		t.Fatalf("column count = %d, want 12", len(columns))
	}
	if diff := cmp.Diff(columns, frontend); diff != "" {
		t.Errorf("column vocabulary (-backend +frontend):\n%s", diff)
	}
	if len(slices.Compact(slices.Sorted(slices.Values(columns)))) != len(columns) {
		t.Fatal("duplicate generated column")
	}
}
