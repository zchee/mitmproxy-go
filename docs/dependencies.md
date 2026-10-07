# Dependencies

This file lists every third-party module the port plans to use: the exact version, the licence, why the
module was chosen and pinned, and the known-good way to upgrade it. The facts come from the dependency
manifest and the package decisions in [plans/mitmproxy-go-port.md](plans/mitmproxy-go-port.md). Where the
plan records no upgrade path, the table says so instead of guessing.

## Policy

- **Exact pins.** Each module is pinned to the version below. A requirement enters `go.mod` together with
  the first package that imports it (`go mod tidy`), so `go.mod` never lists a module that no package uses.
- **Adapters.** `internal/netstack`, `internal/h2`, `internal/h3`, `dns` (codec glue) and `options` (YAML
  codec) each wrap their third-party API in one file with its own contract test, so a version bump touches
  one file. Other dependencies are used directly.
- **Updates.** Dependabot opens one grouped pull request for Go modules and one for GitHub Actions every
  week ([.github/dependabot.yaml](../.github/dependabot.yaml)). A failing dependabot PR, a red `gotip` job
  or `//nolint` comments accumulating in an adapter are the early signs that an update breaks the build.
- **Toolchain.** CI blocks on the `stable` Go release and runs the development toolchain (`gotip`) without
  blocking. `oldstable` is not tested: `go 1.27`, `encoding/json/v2` and `codeberg.org/miekg/dns` (which
  declares `go 1.27.0`) all require Go 1.27.
- **Licences.** CI runs `go-licenses` with a denylist (GPL, LGPL, AGPL, MPL), because licence
  contamination is a low-likelihood, high-impact risk. Upstream static assets and fixtures carry their MIT
  notices; the upstream redirector binaries are downloaded, never vendored.

## Go modules

| Module | Version | Licence | Used by | Why this module and pin | Known-good upgrade path |
|---|---|---|---|---|---|
| `golang.org/x/net` (`http2`, `http2/hpack`, `html`, `publicsuffix`) | v0.59.0 | BSD-3 | h2, contentviews, console | Go 1.27 moved HTTP/2 into `net/http/internal/http2`, which cannot be imported; x/net keeps the public `Framer`. The port uses `Framer.ReadFrame`, `WriteRawFrame` and the `hpack` encoder and decoder, never `ReadMetaHeaders`, whose validation rejects uppercase names and late pseudo-headers and so contradicts `validate_inbound_headers=false`. | Behind the `internal/h2` adapter; bump and rerun its contract test. The plan expects x/net's `http2` to keep diverging from std. |
| `golang.org/x/sys` | v0.48.0 | BSD-3 | platform, netstack, local, tun, `internal/vtcodes` | `SO_ORIGINAL_DST` for transparent mode (`IP6T_SO_ORIGINAL_DST` is defined locally). `internal/vtcodes` uses the termios and window-size ioctls (`unix`) and the console-mode calls (`windows`) for the terminal detection behind colour output. | Not recorded in the plan. |
| `github.com/itchyny/timefmt-go` | v0.1.9 | MIT | save | `save_stream_file` requires strftime formatting of the stream path, which Go's reference-time layouts do not support. Pure Go, zero dependencies, with Python's `%f`; unsupported modifiers and locale differences are listed in [compat.md](compat.md#addonssave). | Rerun the save rotation tests; the formatted path decides when a new file is opened, so a directive behaviour change moves rotation boundaries. |
| `golang.org/x/crypto` (`bcrypt`, `argon2`, `cryptobyte`) | v0.57.0 | BSD-3 | proxyauth and `internal/htpasswd`, webaddons, tlsparse | bcrypt and argon2 for the `proxyauth` and mitmweb addons; the htpasswd reader is ported from upstream onto `bcrypt` and `crypto/sha1` and accepts exactly upstream's bcrypt and `{SHA}` entries; `cryptobyte` for `tlsparse`. | Rerun the htpasswd password vectors for `$2a$`, `$2b$`, `$2y$` and the upstream fixture before upgrading bcrypt. |
| `golang.org/x/text` (`encoding`, `encoding/ianaindex`, `encoding/htmlindex`) | v0.42.0 | BSD-3 | httpmsg, proxyauth | The IANA and WHATWG character-set indexes resolve the charset a message names for its text, since Go has no codec registry like Python's; where the labels differ from Python's is listed in [compat.md](compat.md#httpmsg). The UTF-8 decoder reproduces Python's replacement of invalid authentication bytes. | Bump and rerun the `httpmsg` charset tests (`TestLegacyCharsets`, `TestLegacyCharsetErrors`, `TestMessageTextLegacyCharset`) and the proxyauth differential test; an index change alters which labels resolve, so recheck the label list in compat.md. |
| `github.com/quic-go/quic-go` | v0.63.0 | MIT | h3, quic layer | QUIC transport (`quic.Transport`, `quic.Conn`, `quic.Stream`, 0-RTT, datagrams, qlog). `golang.org/x/net/quic` declares itself not production-ready, and `x/net/http3` is a test shim. The port does not use quic-go's `http3.RawServerConn`/`RawClientConn`, which decode into `net/http` types and lose header order and case; the HTTP/3 frame parser is ported from quic-go's `http3/frames.go` (MIT). | Behind the `internal/h3` adapter. The plan names a 0.64 change to `quic.Stream` as a likely break, so a minor bump needs the adapter's contract test. |
| `github.com/quic-go/qpack` | v0.6.0 | MIT | h3 | HTTP/3 header blocks as ordered `[]HeaderField`. | Behind the `internal/h3` adapter. |
| `github.com/zchee/gows` | v0.0.0-20261007022926-36059bec13b6 | Apache-2.0 | `internal/proxy/layers/websocket`; planned mitmweb `/updates` | Zero-dependency library, go 1.26. The reviewed frame API exposes controls and fragment boundaries without automatic replies, validates per-peer compression, decodes bounded plaintext, and supports abrupt cancellation. This revision explicitly accepts offered 15-bit server compression windows in the HTTP upgrade response. The relay pins the main merge commit of the reviewed frame API ([pull request #6](https://github.com/zchee/gows/pull/6), merged 2026-10-07); no replace directive or interim library. | Every upgrade must pass frame/relay conformance and the proxy's complete Autobahn gate against all 517 frozen cases, including exactly the 36 documented unsupported compression-window offers. |
| `codeberg.org/miekg/dns` | v0.6.118 | BSD-3 | dns | Has the `HTTPS`/`SVCB` RR types. The root package builds on go1.27.1 with only `x/crypto`, `x/net` and `x/sys` as indirect dependencies; module graph pruning keeps the dependencies of its `cmd/` packages out. DoQ is not implemented upstream. | Pre-1.0, so breaking changes are expected (the plan names a v0.7 `RR` interface change as a likely break). Behind the `dns` codec adapter; stay on v0.6.118 and add `exclude` directives to `go.mod` for known-bad versions. |
| `golang.zx2c4.com/wireguard` | v0.0.0-20260522 (pseudo-version) | MIT | wireguard, tun | wireguard-go device for WireGuard mode, together with the gVisor netstack. | Not recorded in the plan. |
| `gvisor.dev/gvisor` | v0.0.0-20261004063249-f57b8fc79db4 (from the `go` branch) | Apache-2.0 | netstack | The only pure-Go TCP/IP stack that accepts connections to any destination (`tcp.NewForwarder`, `udp.NewForwarder`); tun2socks and Tailscale are prior art. Adds about 3 MB to the binary. | Take pseudo-versions from the `go` branch only: it builds on go1.27.1 for darwin/arm64 and linux/amd64, while `@latest` (master) does not. Behind the `internal/netstack` adapter. |
| `github.com/Microsoft/go-winio` | v0.6.2 | MIT | local (Windows) | The only maintained Go named-pipe server with message mode, `FirstPipeInstance` and `RejectRemoteClients`. Accepting one client and then closing the listener reproduces upstream's `max_instances(1)`. | Not recorded in the plan. |
| `github.com/pion/dtls/v3` | v3.1.10 | MIT | tls layer (DTLS) | The standard library has no DTLS; pion is the only maintained pure-Go implementation. Declares `go 1.24.0` and builds on go1.27.1. | Not recorded in the plan. |
| `software.sslmate.com/src/go-pkcs12` | v0.7.3 | BSD-3 | certs (`mitmproxy-ca.p12` and `mitmproxy-ca-cert.p12`) | Its `Passwordless` encoder writes both passwordless `.p12` files upstream writes: `Encode` the key-bearing file, `EncodeTrustStoreEntries` the cert-only file with the friendly name `mitmproxy`. The files carry no MAC and the cert-only bag carries a Java trust-store attribute, unlike `cryptography`'s (listed in `docs/compat.md`). | Run `go test -tags difftest ./certs`: Python must recover identical full private numbers and certificate DER from both bundles; the certificate-only file must contain no key. |
| `github.com/andybalholm/brotli` | v1.2.6 | MIT | netutil/encoding | The standard library has no brotli. | Not recorded in the plan. |
| `github.com/klauspost/compress` | v1.20.1 | BSD-3 | netutil/encoding, grpc view | zstd, and gzip/flate/zlib with a drop-in API. The library's own benchmarks measure decoding 2–3× faster than std, and a proxy decodes every body for `~b` filters and content views. | Not recorded in the plan. |
| `google.golang.org/protobuf` (+ `cmd/protoc-gen-go`) | v1.36.12 | BSD-3 | contentviews, local IPC | Schema-less decoding (`encoding/protowire`, `dynamicpb`) for the protobuf and gRPC views; `protoc-gen-go` generates the redirector IPC schema code, which is checked in. | Not recorded in the plan. `protoc-gen-go` is pinned at the same version as the runtime module. |
| `github.com/bufbuild/protocompile` | v0.14.1 | Apache-2.0 | protobuf view | Parses the `.proto` files named by `protobuf_definitions` at run time, as upstream's Rust content view does. | Not recorded in the plan. |
| `github.com/shamaton/msgpack/v3` | v3.2.3 | MIT | msgpack view | `vmihailenco/msgpack/v5` has had no commit since 2023-10. | Not recorded in the plan. |
| `github.com/alecthomas/chroma/v2` | v2.27.0 | MIT | highlight | Pure Go. Chroma token types are mapped onto upstream's seven highlight tags. | Not recorded as such. Highlighting goldens are generated from the pinned Rust highlighter and any difference without a recorded exemption fails CI, which also catches a chroma bump that changes output. |
| `github.com/spf13/cobra`, `github.com/spf13/pflag` | v1.10.2, v1.0.10 | Apache-2.0, BSD-3 | cmd | Chosen by the user. `--set` uses `StringArrayVar`, not `StringToString`, whose map, CSV and quote-stripping semantics differ from upstream. Shell completion generators are built in. | Not recorded in the plan. |
| `go.yaml.in/yaml/v4` | v4.0.0-rc.6 | Apache-2.0 | options, console keymap | Chosen by the user; `gopkg.in/yaml.v3` is archived. v4 has no stable tag yet (rc.6 is dated 2026-06-17). | Still a release candidate; the plan names an rc.7 change to merge-key decoding as a likely break. Behind the `options` YAML adapter, so falling back to v3 is a one-file change. |
| `charm.land/bubbletea/v2`, `charm.land/bubbles/v2`, `charm.land/lipgloss/v2` | v2.0.10, v2.2.1, v2.0.6 | MIT | tools/console | Chosen by the user. The `github.com/charmbracelet/bubbletea/v2` import path fails `go get`; use the `charm.land` paths. `tea.Program.Send` blocks on an unbuffered channel, which shapes how the console receives flow updates. | Not recorded in the plan. |
| `github.com/charmbracelet/x/exp/teatest/v2` | v2.0.0-20261004011457-ad85c59fdf4e | MIT | console tests | Golden-frame tests for the console; this version declares its dependency on `charm.land/bubbletea/v2`. | Not recorded in the plan. |
| `go.starlark.net` | v0.0.0-20260930 (pseudo-version) | BSD-3 | script | Chosen by the user for scripting. The module publishes no semver tags. | Not recorded in the plan. |
| `github.com/dlclark/regexp2` | v1.12.0 | MIT | filter, css and javascript contentviews | Fallback for filter regular expressions that RE2 cannot compile (backreferences, lookaround), with a 100 ms `MatchTimeout` against catastrophic backtracking; the css and javascript contentviews use it for upstream's lookbehind patterns with the same limit. | Not recorded in the plan. |
| `github.com/shirou/gopsutil/v4` | v4.26.9 | BSD-3 | processinfo | Running executables for `processinfo`. | Not recorded in the plan. |
| `github.com/ebitengine/purego` | v0.11.1 | Apache-2.0 | processinfo (darwin icons) | Objective-C calls for macOS application icons. | Not recorded in the plan. |
| `github.com/go-ldap/ldap/v3` | v3.4.14 | MIT | proxyauth | LDAP proxy authentication; each service bind, bounded search and user bind runs outside the addon dispatch lock. | Run `go test -race -tags integration ./addons/proxyauth` against the OpenLDAP CI service (or local Docker) after upgrading; verify correct and incorrect passwords, missing users, escaped filters, cancellation and lazy connection failures. |
| `github.com/go-asn1-ber/asn1-ber` (transitive) | v1.5.8 | MIT | go-ldap | Its recursive BER decoder has no depth limit and a process-global default packet limit of 2 GiB minus one byte. LDAP servers must be trusted configuration. The addon adds a per-connection 1 MiB received-byte limit without mutating library globals; this bounds bytes, not nesting or decoded-object overhead. | Recheck decoder depth and allocation behavior on every go-ldap upgrade; prefer per-connection library limits if they become available. Rerun the byte-limit and cancellation tests. |
| `golang.design/x/clipboard` | v0.11.0 | MIT | export (build tag) | Clipboard export, behind the `clipboard` build tag; cgo-free on desktop and optional. | Not recorded in the plan. |
| `go.opentelemetry.io/otel` (+ `sdk`, `exporters/otlp/otlptrace/otlptracegrpc`, `contrib/instrumentation/net/http/otelhttp`) | v1.47.0 / v0.72.0 | Apache-2.0 | observability | Chosen by the user on top of `log/slog`, `net/http/pprof` and `runtime/metrics`; the exporter is opt-in. | Not recorded in the plan. |
| `github.com/chromedp/chromedp` | v0.19.1 | MIT | mitmweb end-to-end tests (test-only) | Reproducible browser tests on ubuntu-26.04 in CI. | Not recorded in the plan. |
| `github.com/google/go-cmp` | v0.7.0 | BSD-3 | tests | Test assertions; the project does not use testify. | Not recorded in the plan. |
| `go.uber.org/goleak` | v1.3.0 | MIT | tests | Goroutine leak checks. | Not recorded in the plan. |
| `github.com/google/btree` | v1.1.3 | Apache-2.0 | addons/view | Generic ordered tree replaces Python's SortedKeyList; insertion sequence preserves equal-key order. | Rerun the view ordering tests. |

## CI tools

These are installed by CI and are not module dependencies.

| Tool | Version | Licence | Why | Upgrade path |
|---|---|---|---|---|
| `github.com/google/go-licenses/v2` | v2.0.1 | Apache-2.0 | Licence gate with the GPL, LGPL, AGPL and MPL denylist. | Not recorded in the plan. |
| `actions/checkout`, `actions/setup-go` | `@v7` (v7.0.1 and v7.0.0 were the latest releases on 2026-10-05) | MIT | Project rule: pin the latest major version only. | Dependabot's weekly GitHub Actions PR. |

## Explicitly avoided

| Module | Reason |
|---|---|
| `github.com/imgk/divert-go` | GPL-3.0 |
| `github.com/AdguardTeam/gomitmproxy` | GPL-3.0 |
| `github.com/sagernet/sing-tun` | GPL-3.0 |
| `github.com/hashicorp/golang-lru/v2` | MPL-2.0; the certificate cache is a hand-written 100-entry FIFO, as upstream's `CertStore` is. |
| `gopkg.in/yaml.v3` | Archived |
| `github.com/google/martian/v3` | Archived |

## DTLS hook configuration

`addon/hookdata` now imports the pinned `github.com/pion/dtls/v3 v3.1.10`:
TLS hooks retain `*tls.Config` and expose `*dtls.Config` separately, selected
by `IsDTLS`. The mutable pion config is retained for hook overrides despite
its deprecation in favor of immutable options-based constructors. Upgrades
must retain the typed hook override contract or migrate all consumers together.

## internal/local

| Module | Version | Licence | Why and upgrade verification |
|---|---|---|---|
| `google.golang.org/protobuf` | v1.36.12 | BSD-3 | Generates and decodes the vendored native-redirector IPC schema. `protoc-gen-go` is pinned to the same version by `go generate ./internal/local`; regeneration preserves optional presence, oneof variants, field numbers, and the schema's Go-package mapping. Before upgrading, regenerate the bindings and rerun the IPC decode and wire-semantics tests, including the explicitly synthetic vectors and subsequent manual-platform captures. |

## dns

The wire adapter now imports `codeberg.org/miekg/dns v0.6.118` (BSD-3), the
exact pin in the module table. It translates the message header without
changing the flow-format-21 state or interpreting opaque record data.
Upgrades must pass the adapter contract, including every reserved flag bit,
section counts and rejected out-of-range fields, before codec tests run.

## internal/h3

| Module | Version | Licence | Importing adapter | Contract and upgrade check |
|---|---|---|---|---|
| `github.com/quic-go/qpack` | v0.6.0 | MIT | `internal/h3/qpack.go` | Static-table QPACK preserves ordered duplicate fields and opaque name/value bytes. Encoded and decoded field sections are capped at 128 KiB; decoded accounting includes 32 bytes per field. Dynamic references are rejected with advertised table capacity zero. After a bump, rerun `go test ./internal/h3` for static/literal wire vectors, empty sections, malformed prefixes, bounds and header-order preservation. |
