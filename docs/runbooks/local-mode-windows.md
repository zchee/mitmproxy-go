# Native local-mode acceptance on Windows

This is a manual runbook, not evidence that native Windows capture passed.
Use Windows 11 or a `windows-2025` VM, from the repository root. Run the
proxy as a normal, non-elevated user with an administrator available to
approve its redirector. Synthetic named-pipe tests do not prove WinDivert
activation, UAC behaviour, native process attribution, or packet checksums.

## Prerequisites and artifact provenance

Install Go 1.27.2 or newer, `uv`, Git Bash, and Wireshark 4.2 or newer with
Npcap loopback support. Put `tshark.exe` on PATH and establish capture access
before this run; do not launch a second elevation just to perform capture.
Keep UAC enabled. Do not run alongside another local-mode proxy.

The pinned wheel is `mitmproxy_windows-0.12.11-py3-none-any.whl`.
Its SHA-256, from `internal/local/artifacts.go:24,27-28`, is:

```text
59addc8864669a08f8cb48d8b29129efb1ca5f6cba9696e2d91f1f506b21a2d7
```

In PowerShell, establish a fresh evidence directory and verify the wheel:

```powershell
$ErrorActionPreference = 'Stop'
$Work = Join-Path (Get-Location) '_test/local-windows'
if (Test-Path $Work) { throw 'Archive the previous results first.' }
New-Item -ItemType Directory -Path "$Work/origin" -Force | Out-Null
$Wheel = Join-Path $Work 'mitmproxy_windows-0.12.11-py3-none-any.whl'
$Expected = '59addc8864669a08f8cb48d8b29129efb1ca5f6cba9696e2d91f1f506b21a2d7'
curl.exe --fail --location --output $Wheel `
  'https://files.pythonhosted.org/packages/52/c9/969db83d2e72de672e88a4ff556d07763ac2a106ba676f6831ced8c4db4e/mitmproxy_windows-0.12.11-py3-none-any.whl'
if ($LASTEXITCODE -ne 0) { throw 'Wheel download failed.' }
if ((Get-FileHash $Wheel -Algorithm SHA256).Hash.ToLower() -ne $Expected) {
  throw 'Wheel SHA-256 mismatch.'
}
go build -o "$Work/mitmdump.exe" ./cmd/mitmdump
if ($LASTEXITCODE -ne 0) { throw 'CLI build failed.' }
Set-Content -Path "$Work/origin/native-local.txt" `
  -Value 'native local origin response' -Encoding utf8
```

The CLI acquires and verifies its own cached copy before launching the
redirector. The preflight wheel above is a provenance check, not an override
of the native executable. Do not manually substitute an unverified binary.

## Start the real origin and native proxy

In a terminal at the repository root, start an ordinary HTTP origin:

```powershell
uv run --no-project python -m http.server 8765 --bind 127.0.0.1 `
  --directory "$PWD/_test/local-windows/origin"
```

In another non-elevated PowerShell terminal at the repository root:

```powershell
$Work = Join-Path (Get-Location) '_test/local-windows'
& "$Work/mitmdump.exe" --mode local:curl `
  --set "confdir=$Work/conf" --set "save_stream_file=$Work/flows.mitm"
```

Approve **one redirector UAC prompt** and record its count, executable path,
and result. The frontend uses `ShellExecuteExW` with `runas`
(`internal/local/windows_native_windows.go:58-83`). An already elevated
shell or disabled UAC cannot establish the one-prompt criterion.
If elevation is refused or native startup fails, record failure and stop;
a successful synthetic pipe row is not a substitute.

After startup, verify the CLI's cached wheel in a separate PowerShell:

```powershell
$Work = Join-Path (Get-Location) '_test/local-windows'
$Cached = Join-Path $Work `
  'conf/redirector/0.12.11/windows/mitmproxy_windows-0.12.11-py3-none-any.whl'
$Expected = '59addc8864669a08f8cb48d8b29129efb1ca5f6cba9696e2d91f1f506b21a2d7'
if ((Get-FileHash $Cached -Algorithm SHA256).Hash.ToLower() -ne $Expected) {
  throw 'Cached wheel SHA-256 mismatch.'
}
```

## Capture and curl round-trip

List capture interfaces, choose the Npcap loopback interface from the actual
output, and start capture before making the request:

```powershell
tshark.exe -D
$CaptureInterface = Read-Host 'Enter the listed Npcap loopback interface ID'
$Work = Join-Path (Get-Location) '_test/local-windows'
tshark.exe -i $CaptureInterface -f 'tcp port 8765' `
  -w "$Work/native.pcapng"
```

In a separate non-elevated terminal:

```powershell
curl.exe --http1.1 --noproxy '*' --max-time 20 `
  'http://127.0.0.1:8765/native-local.txt'
```

Do not pass `--proxy`: the request must traverse native local mode. Require
the known response body, the origin's successful request, and a captured
HTTP flow in mitmdump. Together these exercise the native packet path,
userspace netstack, and origin round-trip. A body without a recorded proxy
flow does not prove interception. Stop capture with Ctrl-C, then stop the
proxy with Ctrl-C to close the flow file. Retain both terminal outputs.

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

```powershell
$Repository = (Get-Location).Path
$Diagnostic = Join-Path $env:TEMP ([Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $Diagnostic | Out-Null
go -C $Diagnostic mod init local-flow-diagnostic
go -C $Diagnostic mod edit -go=1.27.2 `
  '-require=github.com/zchee/mitmproxy-go@v0.0.0-20261009232944-83e8a0e8331f' `
  "-replace=github.com/zchee/mitmproxy-go=$Repository"
```

Copy this code block into `$Diagnostic/flow-addresses.go`, not a new file or
package in the repository:

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

```powershell
go -C $Diagnostic mod tidy
go -C $Diagnostic run . "$Repository/_test/local-windows/flows.mitm"
```

Require `server_conn.address=("127.0.0.1", 8765)`, not the proxy listener.
The diagnostic reads the public saved-flow API; passing it on an existing
fixture is not a native Windows acceptance run.

## Checksum inspection

Confirm the installed TShark exposes the checksum preferences, then inspect
the recorded TCP/IP headers with validation enabled:

```powershell
tshark.exe -G currentprefs | Select-String 'ip.check_checksum|tcp.check_checksum'
$Work = Join-Path (Get-Location) '_test/local-windows'
tshark.exe -r "$Work/native.pcapng" -Y 'tcp.port == 8765' `
  -o ip.check_checksum:TRUE -o tcp.check_checksum:TRUE -V `
  | Tee-Object -FilePath "$Work/checksum-details.txt"
```

If those preferences are absent, stop and record an unsupported-tool result;
do not invent a successful check. Require complete, validated IPv4/TCP
checksums on captured request and response packets of the native round-trip.
Record the relevant frame numbers and statuses from both the diverted
curl-side conversation and the proxy-origin conversation. An origin-side
kernel TCP exchange alone does not verify netstack reinjection checksums.
If the reinjected frames cannot be identified, record **INCONCLUSIVE**.
No packets, unchecked
checksums, or valid-but-partial offload checksums are **INCONCLUSIVE**, not
PASS. A locally captured bad checksum can also be an offload artefact;
confirm a post-offload/receiver-side capture or an approved offload-disabled
capture before calling it a product failure. Do not silently disable
validation to obtain a green result.

TShark options and offload interpretation are documented by the
[official manual][tshark] and [Wireshark checksum guide][checksums].

## Process attribution: BLOCKED

Native `pid` and `process_name` live on the local stream's `GetExtraInfo`
(`internal/proxy/modeserver/local.go:292,305`). The stock flow handler reads
`remote_endpoint` only (`internal/proxy/handler_source.go:27-41`).
There is no approved CLI export for native process attribution on this head.
Keep this result **BLOCKED**. A Task Manager PID, the selector `local:curl`,
or a synthetic named-pipe payload does not verify the two values attached
to this native accepted flow. No diagnostic production change is authorized
by this runbook.

## Teardown and results

With mitmdump stopped and the origin still running, repeat the curl command.
It must succeed directly, with the interception session gone. Then stop the
origin with Ctrl-C. Record whether the redirector process exited and whether
any capture remains active. Do not kill another proxy's daemon or uninstall
Npcap/WinDivert as an undocumented cleanup action. Preserve the evidence in
`_test/local-windows`, which is already ignored by Git.

Collect measured identity information:

```powershell
bash -lc 'date "+%Y-%m-%d %H:%M:%S %Z"'
Get-CimInstance Win32_OperatingSystem | Select-Object Version, BuildNumber
git rev-parse HEAD
go version
Get-FileHash _test/local-windows/mitmproxy_windows-0.12.11-py3-none-any.whl `
  -Algorithm SHA256
tshark.exe --version
```

Fill and commit this block with evidence locations. Until it is filled,
native Windows evidence remains absent.

| Result field | Recorded value |
|---|---|
| Timestamp from `date` | not run |
| Windows version and build | not run |
| Repository commit and Go version | not run |
| Downloaded and cached wheel SHA-256 | not run |
| Redirector UAC prompt count and approval | not run |
| Native `curl.exe` capture and netstack round-trip | not run |
| Saved `server_conn.address` equals the origin | not run |
| Checksum frame numbers, validation and offload status | not run |
| Native stream `pid` and `process_name` | BLOCKED: no approved diagnostic |
| Redirector exit, interception disabled, direct curl after shutdown | not run |
| Evidence paths and failure diagnostics | not run |

[tshark]: https://www.wireshark.org/docs/man-pages/tshark.html
[checksums]: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html
