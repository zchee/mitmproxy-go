# mitmproxy-go

A Go port of [mitmproxy](https://github.com/mitmproxy/mitmproxy), the interactive TLS-capable intercepting proxy, together
with the packet-level parts of [mitmproxy-rs](https://github.com/mitmproxy/mitmproxy-rs) (WireGuard, local and TUN modes,
content views).

The port aims at full compatibility with upstream: flow files, the `~/.mitmproxy` CA layout, the filter language, option
names and precedence, hook names, proxy mode specs and the mitmweb API, verified against upstream fixtures and against
the pinned Python mitmproxy in differential tests.

## Upstream pins

| Upstream | Commit | Notes |
|---|---|---|
| [mitmproxy](https://github.com/mitmproxy/mitmproxy) (Python) | `v12.3.1` / `51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7` | `12.3.1`, flow format version 21 |
| [mitmproxy-rs](https://github.com/mitmproxy/mitmproxy-rs) (Rust) | `v0.12.15` / `a1ce1d9bfd35d3a593ace483015c9cbcd40ddff8` | workspace `0.12.15`; redirector artifacts: `0.12.15` ([PR #288](https://github.com/zchee/mitmproxy-go/pull/288)) |

These are comparison baselines, not a claim of complete behavioural catch-up. Retained artifact-production revisions
and [deferred differences](docs/compat.md#deferred-differences-against-mitmproxy-1231-and-mitmproxy_rs-01215)
remain documented separately. The Python differential oracle and its active fixture generators use `v12.3.1`.
The option manifest contains 117 projected names: comparisons exclude exactly `emudhra` and `emudhra_old`, whose
features remain unimplemented. Historical fixture-production revisions are retained; the embedded mitmweb frontend
is the `v12.3.1` build.

## Status

`mitmdump`, `mitmproxy` and `mitmweb` are implemented under `cmd/`: a flow-dumping CLI, an interactive terminal UI
and a web UI. The release workflow cross-builds all three commands; cross-built artifacts do not establish native
platform acceptance.

The work plan, with scope, architecture, package choices and acceptance criteria, is
[docs/plans/mitmproxy-go-port.md](docs/plans/mitmproxy-go-port.md). Pinned dependencies and their upgrade paths are
listed in [docs/dependencies.md](docs/dependencies.md). Where the port behaves differently from mitmproxy on purpose,
and why, is listed in [docs/compat.md](docs/compat.md).

## Requirements

Go 1.27.4 or newer. `mitmproxy` requires an interactive terminal.

Native local-mode installation and manual acceptance: [macOS](docs/runbooks/local-mode-macos.md) and
[Windows](docs/runbooks/local-mode-windows.md). Cross-compilation is not evidence of native redirector, driver,
process or terminal behavior. FreeBSD is cross-compiled build-only. Windows has no automatic native acceptance in CI;
a [manual fixture-evidence workflow](.github/workflows/windows-fixture-evidence.yaml) is available.

## Build and run

Run these commands from the repository root. Build the dumping CLI:

```sh
go build -o ./bin/mitmdump ./cmd/mitmdump
```

Start a loopback proxy:

```sh
./bin/mitmdump --set listen_host=127.0.0.1 --set listen_port=8080
```

Build the terminal UI:

```sh
go build -o ./bin/mitmproxy ./cmd/mitmproxy
```

Run it in an interactive terminal:

```sh
./bin/mitmproxy --set listen_host=127.0.0.1 --set listen_port=8080
```

Build the web UI:

```sh
go build -o ./bin/mitmweb ./cmd/mitmweb
```

Start loopback proxy and web listeners:

```sh
./bin/mitmweb --set listen_host=127.0.0.1 --set listen_port=8080 --set web_host=127.0.0.1 --set web_port=8081
```

Run one proxy at a time when reusing port 8080. Each command provides `--help`, `--options` and `--version`.
Ctrl-C stops mitmdump and mitmweb; in mitmproxy it opens a Quit confirmation prompt. SIGTERM requests orderly shutdown.
Restart with changed flags or configuration to change startup settings; configuration files are not watched for edits.

For installed commands, use a verified release archive or an independently pinned, clean source checkout. From
that checkout, with `GOBIN` set to an absolute directory outside the tree, install each command separately:

```sh
/usr/bin/env GOTOOLCHAIN=go1.27.4 GOEXPERIMENT= GOFLAGS= GOENV=off GOWORK=off GOBIN="$GOBIN" go install ./cmd/mitmdump
```

```sh
/usr/bin/env GOTOOLCHAIN=go1.27.4 GOEXPERIMENT= GOFLAGS= GOENV=off GOWORK=off GOBIN="$GOBIN" go install ./cmd/mitmproxy
```

```sh
/usr/bin/env GOTOOLCHAIN=go1.27.4 GOEXPERIMENT= GOFLAGS= GOENV=off GOWORK=off GOBIN="$GOBIN" go install ./cmd/mitmweb
```

These source builds report `0.1.0-dev`; they do not run release linker injection. To reproduce the plain compiler
string, source installs require `GOTOOLCHAIN=go1.27.4` and an empty `GOEXPERIMENT`. Version-suffixed `go install`
is unsupported while the YAML replacement remains in `go.mod`. See the
[source installation checks](docs/runbooks/release-artifact-verification.md#install-from-source).
Homebrew, apt, container images and automatic updates are not promised distribution channels.

## Optional telemetry and diagnostics

All three tools register `otel_exporter_endpoint` and `pprof_addr` as string options, both empty (disabled) by default.
Opt into an owned local OTLP/HTTP collector and a separate loopback diagnostics listener:

```sh
./bin/mitmdump --set listen_host=127.0.0.1 --set otel_exporter_endpoint=http://127.0.0.1:4318 --set pprof_addr=127.0.0.1:6060
```

Alternatively, add these values to `~/.mitmproxy/config.yaml`:

```yaml
otel_exporter_endpoint: http://127.0.0.1:4318
pprof_addr: 127.0.0.1:6060
```

Precedence is **passed dedicated flags > config.yml > config.yaml > --set > defaults**. Unpassed flags do not override
configuration. A config value can therefore override the `--set` examples; a separate `--set confdir=<directory>`
selects an isolated configuration directory.

Telemetry exports bounded scalar metadata, including destination hosts, methods, statuses, known sizes and valid
timings, not bodies, URLs/paths/queries, headers, cookies, credentials or intercepted trace context. Use HTTPS with
normal certificate validation for remote collectors; plaintext HTTP is loopback-only. The exporter appends
`/v1/traces` and `/v1/metrics` beneath the configured base URL, refuses redirects and ignores proxy-environment routing.

Diagnostics serve runtime metrics and service status at `/debug` and standard profiling handlers at `/debug/pprof/`.
These are not routes on the proxy or web listeners. Only loopback addresses are accepted; `localhost` maps directly
to `127.0.0.1` without DNS, and `[::1]:6060` explicitly selects IPv6. Collector `localhost` also maps to `127.0.0.1`.
Loopback is a trusted-local-operator boundary, not authentication: profiling exposes privileged process information.
Do not forward this port to untrusted users. Diagnostics close has a five-second budget, but a loopback client that
stalls after sending headers can keep a handler goroutine alive past it; expiry is not proof that every handler joined.

Use the frontend's existing option controls to change either value, or stop and restart with changed configuration.
An empty value disables the corresponding feature. Diagnostics stop the old listener before rebinding; a bind failure
logs a warning and leaves diagnostics disabled. Telemetry routes a completed flow to the exporter generation current
at its terminal; flows ending while export is disabled are not exported retroactively. Bounded queues can drop export
work when the collector is unavailable rather than block the proxy. See [compatibility details](docs/compat.md#flow-telemetry)
for size-known, privacy and cumulative `http_fidelity` semantics.

## Release artifacts

The first public release is `v0.1.0-rc.1`, a prerelease. Final `v0.1.0` promotion requires a separate explicit decision
and fresh exact-source checks; release-candidate artifacts are never renamed as final artifacts.
[Release notes](docs/releases/v0.1.0.md) are the single source for support boundaries and known limitations.

[The release workflow](.github/workflows/release.yaml) runs on pushed `v*` tags. Public tags must be
`vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-rc.N`, with nonnegative decimal version components, positive `N`,
no leading zeros and no build metadata. Accepted tags are at most 64 ASCII bytes. Valid `v0.0.0-test.*` proof tags
build and verify artifacts but never publish a GitHub Release. Public tags publish only after artifact verification;
release candidates are marked as prereleases.

The matrix produces **18 binaries in six archives**: Linux, macOS and Windows × amd64 and arm64. Each
`mitmproxy-go_<tag>_<goos>_<goarch>.tar.gz` contains one same-named directory with LICENSE and the three commands
(`.exe` on Windows). Its matching `.provenance.json` records tag, commit, source tree, toolchain, build flags, module
versions, binary hashes and build information. `SHA256SUMS` covers exactly the six archives and six provenance files,
not itself.

Every one of these 13 core files, including `SHA256SUMS`, has a keyless Sigstore signature bundle and GitHub
build-provenance attestation under the GPG-signed source tag. Keep the core files and their 13 signature sidecars in
separate directories. [Verify the complete family and expected workflow identity](docs/runbooks/release-artifact-verification.md)
before extracting; checksums alone are not publisher authentication. There is no Apple code signing or notarization,
and consistency verification is not a reproducible-build guarantee.

Release builds inject the actual tag into `--version`; ordinary source builds retain `0.1.0-dev`. Archives do not include
native local-mode redirectors or establish native platform acceptance. Install updates into a newly verified versioned
directory and retain old verified directories for rollback. A withdrawn public version keeps its immutable tag and
assets and is superseded by a fixed patch version; it is not overwritten or silently deleted.

## Fuzzing and benchmarks

[The long fuzz carrier](.github/workflows/fuzz-nightly.yaml) is **manual-dispatch only**; its schedule is commented out,
so it is not an active nightly job. It runs the [57 package-qualified targets](hack/fuzz-targets.txt) for ten minutes each
across eight shards, with at most two shards running concurrently, retaining receipts and selected corpus artifacts.
It downloads the module graph before target discovery, then disables module downloads for the discovery/search loop.
Each target retains before/after socket-table snapshots. DNS-over-TCP framing uses in-memory half-closed connections
with fuzz-controlled read segmentation, rather than opening kernel sockets per execution.
The required CI fuzz-smoke jobs remain separate.

The landed [proxy benchmark harness](docs/bench/README.md) covers HTTP/1, HTTP/2, HTTP/3 and WebSocket scenarios.
The telemetry benchmark comparison is not part of this release, and no telemetry-on/off measurement series exists.
[PR #270](https://github.com/zchee/mitmproxy-go/pull/270) remains an open draft at retained head `883d09b` and has not landed.
The HTTP/1 diagnosis remains **INCONCLUSIVE**; the HTTP/3 high-concurrency limitation remains documented.
No product or harness repair or telemetry-on/off performance comparison is claimed.

## Development

```sh
hack/fmt.sh    # gofmt, gofumpt, modernize, goimports-rereviser
hack/lint.sh   # go vet, golangci-lint
go test -race -count=1 ./...
```

[Timing-sensitive acceptance cases](docs/runbooks/acceptance-flakes.md) records the unrepaired socket/startup
boundaries and the failure-retention policy; a green rerun is not a repair claim.

## Licence

MIT; see [LICENSE](LICENSE). Upstream mitmproxy and mitmproxy-rs are MIT-licensed; fixtures copied from them carry
their notice under `testdata/`.
