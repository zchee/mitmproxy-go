// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest && unix

package acceptance_test

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zchee/gows"
)

type webLiveTraceEvent struct {
	Event      string       `json:"event"`
	ElapsedNS  int64        `json:"elapsed_ns"`
	Phase      string       `json:"phase,omitzero"`
	Method     string       `json:"method,omitzero"`
	Path       string       `json:"path,omitzero"`
	Status     *int         `json:"status,omitzero"`
	DeadlineNS *int64       `json:"deadline_ns,omitzero"`
	Opcode     *gows.Opcode `json:"opcode,omitzero"`
	Bytes      *int         `json:"bytes,omitzero"`
	Resource   string       `json:"resource,omitzero"`
	Command    string       `json:"cmd,omitzero"`
	FlowID     string       `json:"flow_id,omitzero"`
	ErrorType  string       `json:"error_type,omitzero"`
}

// The live harness owns one reader, so its trace needs no concurrent writer.
// Elapsed and deadline offsets share a monotonic origin, not wall-clock time.
type webLiveTrace struct {
	t       *testing.T
	file    *os.File
	started time.Time
}

func newWebLiveTrace(t *testing.T, processLog string) *webLiveTrace {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(filepath.Dir(processLog), "updates-trace.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("close live updates trace: %v", err)
		}
	})
	return &webLiveTrace{t: t, file: file, started: time.Now()}
}

func (trace *webLiveTrace) record(event webLiveTraceEvent) {
	trace.t.Helper()
	event.ElapsedNS = time.Since(trace.started).Nanoseconds()
	body, err := json.Marshal(event)
	if err != nil {
		trace.t.Fatalf("encode live updates trace: %v", err)
	}
	// Write each event immediately so a failed wait retains the preceding trace.
	if _, err := trace.file.Write(append(body, '\n')); err != nil {
		trace.t.Fatalf("write live updates trace: %v", err)
	}
}

func (trace *webLiveTrace) frame(phase string, opcode gows.Opcode, raw []byte) {
	trace.t.Helper()
	event := webLiveTraceEvent{Event: "updates_frame", Phase: phase, Opcode: new(opcode), Bytes: new(len(raw))}
	var envelope struct {
		Type    string         `json:"type"`
		Payload jsontext.Value `json:"payload"`
	}
	if opcode == gows.OpcodeText && json.Unmarshal(raw, &envelope) == nil {
		event.Resource, event.Command, _ = strings.Cut(envelope.Type, "/")
		if envelope.Payload.Kind() == '{' {
			var payload struct {
				Flow struct {
					ID string `json:"id"`
				} `json:"flow"`
			}
			if json.Unmarshal(envelope.Payload, &payload) == nil {
				event.FlowID = payload.Flow.ID
			}
		} else if envelope.Type == "flows/remove" {
			var id string
			if json.Unmarshal(envelope.Payload, &id) == nil {
				event.FlowID = id
			}
		}
	}
	trace.record(event)
}
