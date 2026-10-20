// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest && unix

package acceptance_test

import (
	"bytes"
	json "encoding/json/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/zchee/gows"
)

func TestMitmwebLiveTrace(t *testing.T) {
	tests := map[string]struct {
		opcode   gows.Opcode
		raw      string
		resource string
		command  string
		flowID   string
	}{
		"success: flow add metadata only": {
			opcode: gows.OpcodeText, raw: `{"type":"flows/add","payload":{"flow":{"id":"flow-a","request":{"headers":[["Authorization","do-not-record"]]}}}}`,
			resource: "flows", command: "add", flowID: "flow-a",
		},
		"success: flow update metadata only": {
			opcode: gows.OpcodeText, raw: `{"type":"flows/update","payload":{"flow":{"id":"flow-b","comment":"do-not-record"}}}`,
			resource: "flows", command: "update", flowID: "flow-b",
		},
		"success: multibyte payload length": {
			opcode: gows.OpcodeText, raw: `{"type":"flows/update","payload":{"flow":{"id":"flow-α"}}}`,
			resource: "flows", command: "update", flowID: "flow-α",
		},
		"success: removed flow id": {
			opcode: gows.OpcodeText, raw: `{"type":"flows/remove","payload":"flow-c"}`,
			resource: "flows", command: "remove", flowID: "flow-c",
		},
		"success: state values omitted": {
			opcode: gows.OpcodeText, raw: `{"type":"state/update","payload":{"servers":{"private_key":"do-not-record"}}}`,
			resource: "state", command: "update",
		},
		"success: event message omitted": {
			opcode: gows.OpcodeText, raw: `{"type":"events/add","payload":{"id":17,"message":"do-not-record"}}`,
			resource: "events", command: "add",
		},
		"success: malformed envelope still records length": {
			opcode: gows.OpcodeText, raw: `do-not-record`,
		},
		"success: binary payload omitted": {
			opcode: gows.OpcodeBinary, raw: `do-not-record`,
		},
		"success: empty payload records zero length": {
			opcode: gows.OpcodeText,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			trace := newWebLiveTrace(t, filepath.Join(t.TempDir(), "go-live.log"))
			trace.frame("initial_flows_add", tt.opcode, []byte(tt.raw))
			raw, err := os.ReadFile(trace.file.Name())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte("do-not-record")) {
				t.Fatal("trace retained payload content outside the permitted metadata")
			}
			var got webLiveTraceEvent
			if err := json.Unmarshal(raw, &got, json.RejectUnknownMembers(true)); err != nil {
				t.Fatal(err)
			}
			if got.ElapsedNS < 0 {
				t.Fatalf("negative monotonic elapsed offset: %d", got.ElapsedNS)
			}
			got.ElapsedNS = 0
			want := webLiveTraceEvent{Event: "updates_frame", Phase: "initial_flows_add", Opcode: new(tt.opcode), Bytes: new(len(tt.raw)), Resource: tt.resource, Command: tt.command, FlowID: tt.flowID}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Errorf("trace metadata mismatch (-want +got):\n%s", diff)
			}
			info, err := os.Stat(trace.file.Name())
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("trace mode=%o, want 600", info.Mode().Perm())
			}
		})
	}
}

func TestMitmwebLiveTraceMonotonic(t *testing.T) {
	tests := map[string]struct{ offset time.Duration }{
		"success: future deadline":  {5 * time.Second},
		"success: elapsed deadline": {-time.Second},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			trace := newWebLiveTrace(t, filepath.Join(t.TempDir(), "python-live.log"))
			deadline := trace.started.Add(tt.offset)
			want := []webLiveTraceEvent{
				{Event: "handshake_complete"},
				{Event: "http_sent", Method: http.MethodPost, Path: "/flows/dump"},
				{Event: "http_response", Method: http.MethodPost, Path: "/flows/dump", Status: new(http.StatusOK)},
				{Event: "wait_start", Phase: "initial_flows_add", DeadlineNS: new(deadline.Sub(trace.started).Nanoseconds())},
				{Event: "read_error", Phase: "initial_flows_add", ErrorType: "*net.OpError"},
			}
			for _, event := range want {
				trace.record(event)
			}
			raw, err := os.ReadFile(trace.file.Name())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasSuffix(raw, []byte{'\n'}) {
				t.Fatal("trace lacks a complete JSONL terminator")
			}
			var got []webLiveTraceEvent
			previous := int64(-1)
			for line := range strings.Lines(string(raw)) {
				var event webLiveTraceEvent
				if err := json.Unmarshal([]byte(line), &event, json.RejectUnknownMembers(true)); err != nil {
					t.Fatal(err)
				}
				if event.ElapsedNS < previous {
					t.Fatalf("monotonic offset moved backwards: %d after %d", event.ElapsedNS, previous)
				}
				previous = event.ElapsedNS
				event.ElapsedNS = 0
				got = append(got, event)
			}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Errorf("ordered trace mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
