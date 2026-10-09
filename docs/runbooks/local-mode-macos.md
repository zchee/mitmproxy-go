# Native local-mode acceptance on macOS

This is a manual runbook, not a record of a successful native run. Run it
on macOS 12 or newer supported by the selected Go toolchain, from the
repository root. Synthetic IPC tests do not prove extension activation.
Do not run it while another proxy owns the installed redirector.

## Prerequisites and pinned application

Install Go 1.27.2 or newer, `uv`, and the command-line developer tools.
Use a normal user account; approve installation and the network/system
extension yourself. Keep the commands and their output with the results.

The pinned wheel is `mitmproxy_macos-0.12.11-py3-none-any.whl`.
Its SHA-256, from `internal/local/artifacts.go:24-26`, is:

```text
63349d9b46514ca679547651f7c0548f9222892edfbcba087b82b3244fbae859
```

```sh
work="${PWD}/_test/local-macos"
test ! -e "$work" || { printf 'Archive the previous results first.\n' >&2; exit 1; }
umask 077
mkdir -p "$work/extracted" "$work/origin"
wheel="$work/mitmproxy_macos-0.12.11-py3-none-any.whl"
curl --fail --location --output "$wheel" \
  'https://files.pythonhosted.org/packages/fe/7f/7f77310e810ab3ee47357e4ce1bdafc05d429e411bad63c0e546ceef2f2e/mitmproxy_macos-0.12.11-py3-none-any.whl'
printf '%s  %s\n' \
  63349d9b46514ca679547651f7c0548f9222892edfbcba087b82b3244fbae859 \
  "$wheel" | shasum -a 256 -c -
unzip -p "$wheel" 'mitmproxy_macos/Mitmproxy Redirector.app.tar' \
  >| "$work/app.tar"
tar -tf "$work/app.tar"
tar -xf "$work/app.tar" -C "$work/extracted"
test -d "$work/extracted/Mitmproxy Redirector.app"
```

Stop on a digest mismatch, unexpected archive contents, or missing app.
If an app already exists in `/Applications`, preserve it separately before
replacing it; never overwrite an application used by another running proxy.
Install only the verified extracted application:

```sh
sudo ditto "$work/extracted/Mitmproxy Redirector.app" \
  '/Applications/Mitmproxy Redirector.app'
codesign --verify --deep --strict '/Applications/Mitmproxy Redirector.app'
```

Approve Mitmproxy Redirector's network/system extension in System Settings
when prompted. Record the approval and `systemextensionsctl list` output.
The Go frontend launches the installed app; it does not install it or grant
extension approval (`internal/local/macos.go:85-113`). If approval prevents
startup, record that attempt and start again only after approval completes.
Do not report synthetic starter tests as a substitute for this step.

## Real origin and interception

Build the CLI and create a known response body:

```sh
go build -o "$work/mitmdump" ./cmd/mitmdump
printf 'native local origin response\n' >| "$work/origin/native-local.txt"
```

In one terminal at the repository root, start a real HTTP origin:

```sh
uv run --no-project python -m http.server 8765 \
  --bind 127.0.0.1 --directory "$PWD/_test/local-macos/origin"
```

In a second terminal at the repository root, run:

```sh
"$PWD/_test/local-macos/mitmdump" --mode local:curl \
  --set "confdir=$PWD/_test/local-macos/conf" \
  --set "save_stream_file=$PWD/_test/local-macos/flows.mitm"
```

After the local mode reports startup, use a third terminal:

```sh
curl --http1.1 --noproxy '*' --max-time 20 \
  'http://127.0.0.1:8765/native-local.txt'
```

Do not use `--proxy`: that would test explicit proxy mode instead. Require
both the known response body and a captured HTTP flow in mitmdump. A curl
response without a captured flow does not prove interception. Preserve the
proxy/origin output; stop the proxy with Ctrl-C so the saved flow file closes.

## Verify the recorded origin address

The diagnostic uses exported `flowio.NewReader`, `Reader.All`,
`flow.Flow.Common`, and `connection.Server.Address`. It was compiled against
module source `github.com/zchee/mitmproxy-go` at
`83e8a0e8331fdce638a263bb02c0ebe3d0b65977`
(`v0.0.0-20261009232944-83e8a0e8331f`) with Go 1.27.2. The local replacement
below uses the checkout that produced the CLI; record its actual commit in
the results. The version pin identifies the validated API, not an assertion
that a later checkout has already been verified.

Create a temporary module **outside the repository tree**:

```sh
repository="$PWD"
diagnostic="$(mktemp -d "${TMPDIR:-/tmp}/local-flow-diagnostic.XXXXXX")"
go -C "$diagnostic" mod init local-flow-diagnostic
go -C "$diagnostic" mod edit -go=1.27.2 \
  -require=github.com/zchee/mitmproxy-go@v0.0.0-20261009232944-83e8a0e8331f \
  "-replace=github.com/zchee/mitmproxy-go=$repository"
```

Copy this code block into `$diagnostic/flow-addresses.go`, not a new file or
package in the repository. It reads saved flows; it does not alter the proxy
or claim that transport-only process metadata is present on the client flow.

```go
// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
    "fmt"
    "log"
    "os"

    "github.com/zchee/mitmproxy-go/flowio"
)

func main() {
    if len(os.Args) != 2 {
        log.Fatal("usage: flow-addresses <flows.mitm>")
    }
    file, err := os.Open(os.Args[1])
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()
    found := false
    for f, err := range flowio.NewReader(file).All() {
        if err != nil {
            log.Fatal(err)
        }
        server := f.Common().ServerConn
        if server == nil || server.Address == nil {
            continue
        }
        fmt.Printf("server_conn.address=(%q, %d)\n",
            server.Address.Host, server.Address.Port)
        found = true
    }
    if !found {
        log.Fatal("no flow with a recorded server address")
    }
}
```

```sh
go -C "$diagnostic" mod tidy
go -C "$diagnostic" run . "$repository/_test/local-macos/flows.mitm"
```

Require a captured origin address of `("127.0.0.1", 8765)`, not a proxy
listener address. Retain the flow file and diagnostic output. This helper
can be verified on existing flow fixtures; that is not native-run evidence.

## Process attribution: BLOCKED

`pid` and `process_name` are exposed by the native local stream's
`GetExtraInfo`, not by the stock client flow
(`internal/proxy/modeserver/local.go:292,305`). The handler reads
`remote_endpoint` only (`internal/proxy/handler_source.go:27-41`).
There is no approved stock CLI diagnostic for these two values on this head.
Record process-attribution verification as **BLOCKED**. Do not infer it from
`local:curl`, a request header, an Activity Monitor PID, or a synthetic IPC
fixture. A later approved admission diagnostic must observe both values on
the actual accepted native stream before this result can become PASS.

## Teardown and results

After stopping mitmdump, repeat the curl command while the origin still
runs. It must succeed directly without a surviving interception session.
Then stop the origin with Ctrl-C. Preserve the installed app and extension
unless uninstalling them is a separate operator decision. Do not kill another
proxy's redirector. Keep `_test/local-macos` logs and flows until reviewed;
this directory is already ignored by Git.

Collect measured identity information:

```sh
date '+%Y-%m-%d %H:%M:%S %Z'
sw_vers
git rev-parse HEAD
go version
shasum -a 256 _test/local-macos/mitmproxy_macos-0.12.11-py3-none-any.whl
systemextensionsctl list
```

Fill this block from the outputs and commit the completed results with
links to the retained evidence. Until then native macOS evidence is absent.

| Result field | Recorded value |
|---|---|
| Timestamp from `date` | not run |
| OS version and build | not run |
| Repository commit and Go version | not run |
| Wheel SHA-256 and application signature | not run |
| Extension approval / activation | not run |
| Native `local:curl` interception and known origin body | not run |
| Saved `server_conn.address` equals the origin | not run |
| Native stream `pid` and `process_name` | BLOCKED: no approved diagnostic |
| Interception disabled and direct curl after shutdown | not run |
| Evidence paths and failure diagnostics | not run |
