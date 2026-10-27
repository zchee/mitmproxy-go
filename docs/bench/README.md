# Proxy performance measurements

These benchmarks are measurements, not correctness gates. There is no regression
threshold. All origins and clients are owned, in-process loopback endpoints; no
external traffic generator or public origin is used.

## Workloads and units

`BenchmarkProxyThroughput` crosses four protocols (`h1`, `h2`, `h3`, `ws`), three
connection counts (1, 16, 256), and two body sizes (1024, 1048576 bytes). A worker
owns one actual transport connection, not merely an HTTP stream. HTTP transports
are not shared between workers; each HTTP/3 worker owns a separate UDP socket and
QUIC connection. The harness checks accepted proxy and origin connection counts,
HTTP response versions and negotiated TLS application protocols. A second
transport dial is an error rather than a silently reused or reconnected worker.

HTTP/3 uses a **10-second QUIC keepalive period on both owned hops**: the
harness client maintains the client-to-proxy connection, and the owned origin
server maintains the proxy-to-origin connection. This is ordinary long-lived
QUIC client/server behavior, needed while later workers are established and
warmed sequentially. The default negotiated idle timeout is unchanged; it is not
extended to make a stalled exchange pass. Keepalive overhead is included in the
workload and the identical configuration applies to both comparison series and
all HTTP/3 correctness scenarios.

Each timed iteration is a **batch**: a barrier releases one exchange on every
connection, then the caller waits for all exchanges. Setup, one warmup exchange
per connection, and joined teardown are outside `b.Loop`.

- HTTP exchange: a POST with a fixed-length binary body and an equally sized
  binary response. Both are streamed and SHA-256 checked.
- WebSocket exchange: one binary message and its binary echo. The upgrade is
  setup, not a measured HTTP request. Fragmented message readers/writers keep
  application buffers bounded without retaining an entire 1 MiB message.
  **WS rows run with a bounded-history addon mirroring the upstream
  `websocket_message` trimming pattern; without it per-connection history grows
  with the exchange count.** The frozen bound is **one retained message**
  (`retainedWebSocketMessages = 1`). Its normal addon dispatch and trimming cost
  is included in the measured workload, identically in correctness scenarios
  and both comparison series; HTTP rows do not install this addon.
- Useful bytes are **response/echo body bytes only**, excluding request bytes,
  headers, framing, handshakes and encryption overhead. Bidirectional traffic is
  therefore larger than the reported useful-byte rate.

Reported fields are benchstat-readable:

| Field | Denominator |
|---|---|
| `ns/op` | Nanoseconds per batch, **not per request** |
| `B/op`, `allocs/op` | Allocations per batch, including client, proxy and origin work |
| `requests/op` | Completed exchanges in one batch: the connection count |
| `req/s` | `(b.N × connections) / measured seconds` |
| `MiB/s` | `(b.N × connections × body bytes) / (1048576 × measured seconds)` |
| Go's `MB/s` | The same useful bytes per second in decimal megabytes |

Barrier scheduling, client validation and origin generation/checksumming are part
of the measured workload. These are not isolated proxy CPU measurements. Each
connection has bounded streaming buffers. HTTP/3 transport, kernel buffering and
WebSocket proxy flow retention are also real costs, not excluded allocations.
An errored, missing, wrong-protocol or wrong-checksum exchange fails the run.

The parser functions consume a fixed vector set per operation (valid and malformed
HTTP heads, pinned upstream TLS ClientHellos, compressed DNS binary records and a
malformed compression pointer). Their `SetBytes` total includes all vectors in the
operation. `BenchmarkNetstackTCP/bytes=...` transfers and checks echoed useful
bytes through two real in-process IP stacks connected by owned packet queues;
it includes TCP acknowledgements and packet forwarding, not an operating-system
loopback shortcut.

## Correctness before measurement

The default build's `TestProxyBenchSmoke` invokes the same tagged harness in a
bounded race-enabled child process and retains its exact argv, exit and JSON
output. It rejects zero-match runs. The full tagged suite has four ownership,
protocol and cancellation contracts plus all 24 deterministic matrix scenarios.
It uses fixed exchange counts, never a speed threshold.

The race-enabled tagged correctness profile uses eight Go execution threads,
matching the measurement profile. A single execution thread under the race
detector can starve concurrent QUIC connections; this does not remove the race
instrumentation or change any scenario, exchange count or idle timeout. The
default smoke retains its separate bounded, one-connection HTTP/1 child profile.

```sh
go test -race -tags proxybench -count=1 -cpu=8 -timeout=60m -run '^TestProxyBench(Harness|Matrix)$' ./internal/proxy/bench
```

## Reproduce a baseline

Never run benchmark campaigns in parallel, including campaigns on different
hosts. Finish correctness, lint and build work first, then reserve the machine
for the entire campaign; no other builds, tests, fuzzing or benchmarks may
interleave. Use the repository's shared gate when multiple workers are active.
Finish darwin/arm64 before transferring byte-identical source to linux/amd64.

Pin Go 1.27.3, `GOMAXPROCS=8`, `-cpu=8`, `-benchtime=3s` and `-count=5` for both
hosts. Keep the same CGO policy for compared series. On Linux inspect the allowed
CPU affinity set and select eight allowed logical CPUs with `taskset`. On macOS
record **GOMAXPROCS pinned; OS affinity not available**; do not claim physical-core
affinity. Record host, CPU topology, kernel, power/load, source commit and tree
hash, toolchain, module graph, argv, UTC dates and artifact checksums. Remote
Debian runs require `umask 022` before any Go test, a Linux-local gate/lock path,
and disposable toolchain/cache directories under `/tmp`.

Run the microbenchmarks under the same uninterrupted campaign reservation:

```sh
GOMAXPROCS=8 go test -run '^$' -bench '^Benchmark' -benchmem -benchtime=3s -count=5 -cpu=8 -timeout=120m ./addon ./filter ./filter/regex ./flowio ./flowio/tnetstring ./internal/netutil/encoding ./internal/pyrepr ./internal/tools/console/flowview ./omap ./internal/http1 ./tlsparse ./dns ./internal/netstack
```

Run all uninstrumented proxy scenarios without relinquishing that reservation:

```sh
GOMAXPROCS=8 go test -tags proxybench -run '^$' -bench '^BenchmarkProxyThroughput$' -benchmem -benchtime=3s -count=5 -cpu=8 -timeout=120m ./internal/proxy/bench
```

A telemetry-enabled comparison is a separately named workload, not an environment
switch; it does not replace the uninstrumented baseline. That series requires the
owned collector integration and is not supplied by the uninstrumented harness.

Save raw outputs as `<host>-<date>.txt` and provenance/interpretation as the matching
`.md`, with host/toolchain/date/source commit but no operational tracking IDs.
Require five successful samples for every literal scenario; a missing row or host
is an incomplete baseline, not a zero. Keep failures instead of silently omitting
them. Record the installed benchstat version using `go version -m` on its binary.

Parse one baseline:

```sh
benchstat docs/bench/<host>-<date>.txt
```

Compare same-host, same-workload runs (ratios remain diagnostic):

```sh
benchstat docs/bench/<host>-<before>.txt docs/bench/<host>-<after>.txt
```

Cross-host topology differences must be reported, not interpreted as a proxy
regression. Upstream's `test/bench/benchmark.py` uses wrk against devd through a
reverse proxy; the 24-scenario owned Go matrix is an extension, not the same
upstream scenario set.
