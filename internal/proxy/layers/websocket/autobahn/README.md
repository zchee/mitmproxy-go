# WebSocket conformance gate

Run from the module root with Go and Docker available:

```sh
internal/proxy/layers/websocket/autobahn/run.sh /absolute/path/to/new-report-directory
```

The directory must not exist. The runner builds the real `mitmdump` executable,
starts a real compression-capable echo origin, starts the reverse proxy, runs the
pinned Autobahn fuzzing client, validates its report, and stops all owned
processes and the container on success or failure. It requires the executable's
HTTP 101 WebSocket handoff; a standalone gows result is not proxy evidence.

`cases.json` independently freezes the 517 IDs exposed by the pinned image's
`autobahntestsuite.case.Cases` catalogue, before any proxy report is produced.
Expected behavior comes from the case definitions and compression offers:
478 `OK`, 3 `INFORMATIONAL`, and 36 `UNIMPLEMENTED`. The latter require a
server compression window below 15 bits; the stdlib compression backend declines
those offers instead of advertising an unsupported window. Expected `FAILED`
or `UNCLEAN` entries are forbidden. The runner uses every explicit manifest ID,
without exclusions, and requires exactly one agent with exactly those IDs and
matching behavior. Close behavior must also be accepted, never `FAILED` or
`UNCLEAN`. Missing, extra, duplicate, malformed, or oversized evidence fails.

The immutable Docker image digest appears in both the manifest and
`fuzzingclient.json`; mismatched or unpinned images fail before execution. The
runtime config, manifest copy, raw `clients/index.json`, individual HTML/JSON
reports, and origin/proxy/suite logs remain in the report directory. Only after
validation and cleanup does the final action publish `summary.json`:
`image`, `total`, `verified`, `failed`, and `report`. A successful complete run
has `total=517`, `verified=517`, and `failed=0`; these are acceptance criteria,
not a claim that a particular checkout passed. A failure publishes no summary.

Optional environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `WS_ORIGIN_HOST` | `127.0.0.1` | Echo origin bind host |
| `WS_ORIGIN_PORT` | `9002` | Preferred origin port; occupied ports fall back to an ephemeral port |
| `WS_PROXY_HOST` | `127.0.0.1` | Proxy bind host |
| `WS_PROXY_PORT` | `9001` | Preferred proxy port; occupied ports fall back to an ephemeral port |
| `WS_CONTAINER_HOST` | Loopback, or `host.docker.internal` on macOS | Host through which Docker reaches the proxy |
| `WS_GATE_TIMEOUT_SECONDS` | `1800` | Whole-suite hang guard, from 1 to 86400 seconds |

Readiness has a separate generous hang guard with goroutine diagnostics; it is
not a timing assertion. Binding failures after port selection fail the run.
For gate integration, the caller supplies the fresh report directory, invokes
this script, propagates its status, and archives that directory. The caller
owns any machine-wide gate lock; this script does not recursively acquire it.

The owned frame fuzzer is run separately and serially:

```sh
go test ./internal/proxy/layers/websocket -run '^$' -fuzz '^FuzzReadMessages$' -fuzztime=30s -parallel=2
```
