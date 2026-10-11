// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build h2load

package httplayer

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestHTTP3LoadSetupReceiptContract(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ row string }{
		"error: large transfer setup emits one complete receipt": {row: "TestHTTP3LoadLargeTransfer"},
		"error: sibling setup emits one complete receipt":        {row: "TestHTTP3LoadUnrelatedResponse"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^"+test.row+"$", "-test.v", "-test.timeout=15s")
			cmd.Env = append(os.Environ(), "MITMPROXY_GO_HTTP2_LOAD=0")
			output, err := cmd.CombinedOutput()
			if _, ok := errors.AsType[*exec.ExitError](err); !ok {
				t.Fatalf("setup child did not retain fatal failure: %v\n%s", err, output)
			}
			text := string(output)
			if !strings.Contains(text, "h2load requires MITMPROXY_GO_HTTP2_LOAD=1 and an isolated runner") {
				t.Fatalf("original setup failure text was lost:\n%s", output)
			}
			if got := strings.Count(text, "HTTP3_TERMINAL "); got != 1 {
				t.Fatalf("terminal receipt count = %d, want 1\n%s", got, output)
			}
			_, data, _ := strings.Cut(text, "HTTP3_TERMINAL ")
			data, _, _ = strings.Cut(data, "\n")
			var fields map[string]jsontext.Value
			if err := json.Unmarshal([]byte(data), &fields); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"phase", "stream", "expected_bytes", "actual_read_bytes", "validated_payload_bytes", "elapsed_ns", "last_progress_offset", "terminal_cause_type", "terminal_cause", "client_quic", "origin_quic"} {
				if _, ok := fields[field]; !ok {
					t.Fatalf("terminal receipt lacks %s:\n%s", field, output)
				}
			}
			if string(fields["phase"]) != `"setup-opt-in"` || string(fields["stream"]) != `"unavailable"` || string(fields["client_quic"]) != `"unavailable"` || string(fields["origin_quic"]) != `"unavailable"` {
				t.Fatalf("setup receipt has fabricated stream or QUIC state:\n%s", output)
			}
		})
	}
}
