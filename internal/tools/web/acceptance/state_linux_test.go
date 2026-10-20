// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build webprivileged && linux

package acceptance_test

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestMitmwebLocalModeUnavailable(t *testing.T) {
	binary := os.Getenv("MITMPROXY_TEST_MITMWEB")
	if !filepath.IsAbs(binary) {
		t.Fatal("MITMPROXY_TEST_MITMWEB must name the unprivileged prebuilt backend; root compilation is forbidden")
	}
	role := os.Getenv("MITMPROXY_TEST_WEB_ROLE")
	if role != "root" && role != "nonroot" {
		t.Fatal("MITMPROXY_TEST_WEB_ROLE must explicitly select root or nonroot")
	}
	uid := os.Geteuid()
	if (uid == 0) != (role == "root") {
		t.Fatalf("effective uid %d does not implement requested role %s", uid, role)
	}
	t.Setenv("HOME", t.TempDir())
	tests := map[string]struct{ want jsontext.Value }{
		"effective uid": {jsontext.Value(`"mitmproxy is not running as root."`)},
	}
	if uid == 0 {
		tests["effective uid"] = struct{ want jsontext.Value }{jsontext.Value(`null`)}
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tuple := newWebInputTuple(t, "")
			args := append(tuple.goArgs(), "--set", "server=false")
			process := startWebProcess(t, binary, args, role)
			client := webClient(t)
			waitWebReady(t, process, client, tuple, func(raw []byte) bool {
				var state map[string]jsontext.Value
				return json.Unmarshal(raw, &state) == nil && state["localModeUnavailable"] != nil
			})
			status, _, raw, err := requestWeb(t.Context(), client, tuple, http.MethodGet, "/state", nil)
			if err != nil || status != http.StatusOK {
				t.Fatalf("state response status=%d err=%v", status, err)
			}
			var state map[string]jsontext.Value
			if err := json.Unmarshal(raw, &state); err != nil {
				t.Fatal(err)
			}
			if got := string(state["localModeUnavailable"]); got != string(tt.want) {
				t.Fatalf("effective uid %d: localModeUnavailable=%s, want %s", uid, got, tt.want)
			}
			t.Logf("role=%s source=os.Geteuid effective_uid=%d localModeUnavailable=%s server=false confdir=%s", role, uid, state["localModeUnavailable"], tuple.confdir)
			process.stop(t)
			verifyWebPortsReleased(t, tuple)
		})
	}
}
