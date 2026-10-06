# WebSocket conformance gate

Run from the module root with Go and Docker available:

```sh
internal/proxy/layers/websocket/autobahn/run.sh /absolute/path/to/new-report-directory
```

The directory must not exist. The runner builds the real `mitmdump` executable,
starts a real compression-capable echo origin, starts the reverse proxy, runs the
pinned Autobahn fuzzing client, validates its reports, and stops all owned
processes and containers on success or failure. It requires the executable's
HTTP 101 WebSocket handoff; a standalone gows result is not proxy evidence.

`cases.json` independently freezes the 517 IDs exposed by the pinned image's
`autobahntestsuite.case.Cases` catalogue, before any proxy report is produced.
Expected behavior comes from the case definitions and compression offers:
468 `OK`, 10 `OK` or `NON-STRICT`, 3 `INFORMATIONAL`, and 36 `UNIMPLEMENTED`.
The latter require a server compression window below 15 bits; the stdlib
compression backend declines those offers instead of advertising an unsupported
window. An `expected` string requires that exact status; an array permits any
listed status. The only class-derived proxy alternatives are 3.2, 3.3, 3.4,
4.1.3, 4.1.4, 4.1.5, 4.2.3, 4.2.4, 4.2.5, and 5.15. Their pinned
`case3_*.py`, `case4_*.py`, and `case5_15.py` scripts send a complete valid data
message before a protocol fault and explicitly define both the echoed `OK`
outcome and the unechoed `NON-STRICT` outcome. The proxy forwards already decoded
valid messages and queued writes, then fails the offending hop immediately, as
upstream mitmproxy does. Whether the origin echo is already queued determines
which accepted outcome occurs; the proxy does not await an echo still in flight.
Each of these ten cases records this reason and `["OK","NON-STRICT"]` in the
manifest. Case 7.1.6 instead sends an ordinary Close and overrides its result to
`INFORMATIONAL`; cases 6.4.1 through 6.4.4 test incomplete UTF-8 fragments and
validation timing, not a preceding complete message. Neither group receives the
proxy alternatives. Expected `FAILED` or `UNCLEAN` entries are forbidden, in both
string and array forms. Fragment history is bounded to 131,072 entries
per message: this admits highly fragmented valid messages while rejecting
unbounded empty-fragment streams with close 1009. The runner uses every explicit manifest ID,
without exclusions, and requires exactly one agent with exactly those IDs and
matching behavior. Close behavior must also be accepted, never `FAILED` or
`UNCLEAN`. Missing, extra, duplicate, malformed, or oversized evidence fails.

The immutable Docker image digest appears in both the manifest and
`fuzzingclient.json`; mismatched or unpinned images fail before execution. The
suite runs serially in 13 fresh containers: cases 1–11 together, then each family
12.1–12.5 and 13.1–13.7 separately. This releases the pinned suite's retained
results and allocator state between compression families. Each container has an
8 GiB memory limit and no additional swap; the proxy and origin stay unchanged
throughout the complete run. The 1800-second aggregate guard includes all
container startup overhead, not 1800 seconds per family.

Each directory under `shards/` retains its explicit runtime configuration, raw
`clients/index.json`, individual HTML/JSON reports, unbuffered suite log, Docker
State, exit status, cgroup high-watermark, duration, and periodic resource samples.
The samples include the current case, container memory, largest host processes,
host memory/swap, and workspace/report disk use. Host kernel and oomd diagnostics
are also archived by the network workflow. The runner captures cgroup counters
inside the container before exit and outside it before removal when accessible.

Verification requires disjoint indices whose union is exactly the unchanged 517
frozen IDs. Each family must report precisely its configured cases, the same
image and agent, no exclusions, a bounded container that exited zero without
OOM, and readable memory/duration evidence. Missing, repeated, or overlapping
families fail. The merged `clients/index.json` records all outcomes; original
wire evidence remains under each family's directory.

Only after full validation and cleanup does the final action publish
`summary.json`: the existing `image`, `total`, `verified`, `failed`, and `report`
fields plus `duration_seconds` and a per-family `shards` table of case counts,
verified counts, peak bytes, durations, memory limits and clean container state.
A successful complete run has `total=517`, `verified=517`, and `failed=0`; these
are acceptance criteria, not a claim that a particular checkout passed. A
failure publishes no summary.

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
