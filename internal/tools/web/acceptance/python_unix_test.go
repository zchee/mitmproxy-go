// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest && unix

package acceptance_test

import (
	"context"
	"encoding/hex"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/internal/testutil"
)

func (tuple webInputTuple) args() []string {
	args := []string{"--mode", "regular@127.0.0.1:18080", "--set", "web_host=127.0.0.1", "--set", "web_port=" + strconv.Itoa(tuple.webPort), "--set", "confdir=" + tuple.confdir, "--set", "web_password=" + webTestPassword, "--set", "web_open_browser=false"}
	if tuple.fixture != "" {
		args = append(args, "-r", tuple.fixture)
	}
	return args
}

func buildWebExecutable(t *testing.T) string {
	t.Helper()
	root := filepath.Dir(testutil.FixturePath(t, "."))
	output := filepath.Join(t.TempDir(), "mitmweb")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", output, "./cmd/mitmweb")
	cmd.Dir = root
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build real mitmweb backend: %v\n%s", err, raw)
	}
	return output
}

func pythonWebCommand(t *testing.T, tuple webInputTuple) (string, []string) {
	t.Helper()
	uv, err := exec.LookPath("uv")
	if err != nil {
		t.Fatalf("live mitmweb requires uv: %v", err)
	}
	args := []string{"run", "--quiet", "--no-project", "--python", difftest.PythonVersion, "--with", difftest.Requirement, "python", "-I", "-c", `import sys
from mitmproxy.tools.main import mitmweb
sys.argv = ["mitmweb", *sys.argv[1:]]
mitmweb()`}
	return uv, append(args, tuple.args()...)
}

func recordPythonWebProvenance(t *testing.T) {
	t.Helper()
	uv, err := exec.LookPath("uv")
	if err != nil {
		t.Fatal(err)
	}
	const script = `import hashlib
import importlib.metadata
import pathlib
import re
import sys
import tornado
import tornado.web
import tornado.websocket
from mitmproxy.tools.web import app
metadata = importlib.metadata.distribution("mitmproxy")
origin = metadata.read_text("direct_url.json")
if origin is None:
    raise RuntimeError("installed mitmproxy has no immutable Git provenance")
match = re.search(r'"commit_id"\s*:\s*"([0-9a-f]{40})"', origin)
if match is None:
    raise RuntimeError("installed mitmproxy has no full Git commit id")
print("mitmproxy_commit\t" + match.group(1))
print("python\t" + sys.version.replace("\n", " "))
print("tornado_version\t" + tornado.version)
for name, module in (("mitmproxy_app", app), ("tornado_web", tornado.web), ("tornado_websocket", tornado.websocket)):
    path = pathlib.Path(module.__file__)
    print(name + "_sha256\t" + hashlib.sha256(path.read_bytes()).hexdigest())
`
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, uv, "run", "--quiet", "--no-project", "--python", difftest.PythonVersion, "--with", difftest.Requirement, "python", "-I", "-c", script)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Python runtime provenance: %v\n%s", err, raw)
	}
	fields := make(map[string]string)
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		name, value, exists := strings.Cut(line, "\t")
		if !exists || fields[name] != "" {
			t.Fatalf("malformed runtime provenance row %q", line)
		}
		fields[name] = value
	}
	if fields["mitmproxy_commit"] != difftest.PinnedCommit || !strings.HasPrefix(fields["python"], difftest.PythonVersion+".") || fields["tornado_version"] == "" {
		t.Fatalf("unexpected live runtime identity: %v", fields)
	}
	for _, name := range []string{"mitmproxy_app_sha256", "tornado_web_sha256", "tornado_websocket_sha256"} {
		digest, err := hex.DecodeString(fields[name])
		if err != nil || len(digest) != 32 {
			t.Fatalf("missing/malformed runtime source hash %s", name)
		}
	}
	t.Logf("resolved live Python provenance:\n%s", raw)
}
