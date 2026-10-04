# mitmproxy-rs inventory for the Go port

Sources: `$RS` is upstream-rust at HEAD 51fe2b7 (2026-10-01). `$PY` is upstream-python at HEAD 3368a0a (2026-10-03). Report generated 2026-10-05 02:21:14 JST (`date`). Nothing was executed; every claim comes from reading source, and paths are relative to the two roots.

**Version skew:** `$RS/Cargo.toml` is `0.13.0-dev`, but `$PY/pyproject.toml:48` pins `mitmproxy_rs>=0.12.6,<0.13`. The latest release in `$RS/CHANGELOG.md` is 0.12.11 (20 July 2026). Python HEAD therefore does not consume Rust HEAD.

## 1. Workspace layout

All crates inherit edition 2024, MSRV 1.95 and version 0.13.0-dev from `[workspace.package]` in `Cargo.toml`. The eBPF crate is the exception: it builds on nightly (`mitmproxy-linux-ebpf/rust-toolchain.toml`) and is a member but not a default-member.

| Crate | Purpose | Kind |
|---|---|---|
| `mitmproxy` (`.`) | userspace TCP/IP, packet sources, IPC, processes, DNS, shutdown | pure library, plus the `src/bin/process-list.rs` dev tool |
| `mitmproxy-rs` | pyo3 bindings, `["lib","cdylib"]`, abi3-py312 | **Python extension** (maturin) |
| `mitmproxy-contentviews` | hex, msgpack, protobuf and gRPC prettifiers | pure library |
| `mitmproxy-highlight` | tree-sitter highlighter | pure library |
| `mitmproxy-linux` | `mitmproxy-linux-redirector` binary; embeds the eBPF object | binary wheel (maturin `bindings="bin"`) |
| `mitmproxy-linux-ebpf` | `#![no_std]` program for `bpfel/bpfeb-unknown-none` | **eBPF program** |
| `mitmproxy-linux-ebpf-common` | shared `Action`/`Pattern` types | `no_std` library |
| `mitmproxy-macos/certificate-truster` | sets Admin trust on the cert labelled "mitmproxy" | macOS Rust helper |
| `mitmproxy-windows/redirector` | `windows-redirector.exe`, WinDivert, LGPL-3.0-or-later | **Windows native component** |
| `wireguard-test-client` | boringtun client for end-to-end tests (uses smoltcp 0.14, core uses 0.13.1) | test helper |

Not Cargo members:
- `mitmproxy-macos/redirector/` is an Xcode project in Swift 5 with two targets: the app and the Network Extension.
- `mitmproxy-macos/` and `mitmproxy-windows/` contain hatchling packaging.

## 2. Python-facing API (`mitmproxy-rs/src/lib.rs`, `mitmproxy_rs/*.pyi`)

The module init does three things:
- It bridges Rust `log` to Python logging (pyo3-log).
- It optionally starts tokio-console (the `tracing` feature).
- It eagerly imports `mitmproxy_{macos,linux,windows}`, so a missing platform wheel fails at import.

`__init__.py` re-registers the submodules in `sys.modules` (pyo3#759 workaround).

Top-level `Stream` is modelled on asyncio StreamReader/Writer:

| Method | Semantics |
|---|---|
| `read(n)` | TCP returns up to n bytes; UDP returns one datagram. Returns `b""` at EOF or shutdown. |
| `write(bytes)` | Synchronous, unbounded buffer. `OSError` if closed. |
| `drain()` | Awaits until the buffer can accept more. |
| `write_eof()` / `close()` | Both end in a FIN after flush. |
| `is_closing()` | True once closed or the server has shut down. |
| `wait_closed()` | No-op. |
| `get_extra_info(name, default)` | See below. |

`get_extra_info` keys:
- Always: `transport_protocol`, `peername`, `sockname`.
- WireGuard only: `original_src`, `original_dst`. These are the WG peer endpoint and the server UDP socket, not the tunnelled flow's endpoints.
- Local redirector only: `pid`, `process_name`, `remote_endpoint`.
- An unknown key with no default raises `KeyError`.

| Submodule | Symbols |
|---|---|
| `wireguard` | `genkey()`, `pubkey(priv)`, `start_wireguard_server(host, port, private_key, peer_public_keys, handle_tcp_stream, handle_udp_stream) -> WireGuardServer{getsockname, close, wait_closed}`. Keys are base64 X25519. |
| `udp` | `start_udp_server(host, port, handle_udp_stream) -> UdpServer`; `open_udp_connection(host, port, *, local_addr=None) -> Stream` (client; interleaves v4/v6 addresses). |
| `tun` | `create_tun_interface(handle_tcp, handle_udp, tun_name=None) -> TunInterface{tun_name, close, wait_closed, unavailable_reason()}`. Linux only. |
| `local` | `start_local_redirector(handle_tcp, handle_udp) -> LocalRedirector{set_intercept(spec), describe_spec(spec) (static, ValueError), close, wait_closed, unavailable_reason()}` |
| `dns` | `DnsResolver(*, name_servers=None, use_hosts_file=True)` with `lookup_ip/ipv4/ipv6` (raises `socket.gaierror` with NONAME, NODATA or AGAIN); `get_system_dns_servers()` |
| `process_info` | `active_executables() -> [Process{executable, display_name, is_visible, is_system}]`; `executable_icon(path) -> PNG bytes` (Windows and macOS only) |
| `certs` | `add_cert(pem)`, `remove_cert()`. macOS only; `NotImplementedError` elsewhere. |
| `contentviews` | `Contentview{name, syntax_highlight, prettify, render_priority}`; `InteractiveContentview` adds `reencode`. Instances: `hex_dump`, `hex_stream`, `msgpack`, `protobuf`, `grpc`, `_test_inspect_metadata`. |
| `syntax_highlight` | `highlight(text, language) -> [(tag, str)]`, `languages()`, `tags()` |

Contentview `metadata` is a duck-typed Python object. The Rust side reads `.content_type`, `.http_message.headers[...]`, `.flow.request.path` and `.protobuf_definitions` (`src/contentviews.rs`).

Handlers are Python coroutines called once per connection. The asyncio loop is captured at server start, and handler tasks are aborted on shutdown (`src/task.rs`).

## 3. Core crate `mitmproxy` (`$RS/src/`)

| Area | Facts |
|---|---|
| `network/` | smoltcp 0.13.1 drives TCP. Interface uses `set_any_ip(true)`, placeholder addresses `0.0.0.1/0` and `::1/0`, default routes, `Medium::Ip`, MTU 1420 (`virtual_device.rs`). |
| TCP (`network/tcp.rs`) | Each SYN on an unseen 4-tuple creates a socket listening on the **destination** address (64 KiB rx/tx buffers, 60 s timeout, 28 s keepalive) and emits `ConnectionEstablished{id, src, dst, tunnel_info}`. A second unbounded send buffer sits on top, so `write()` never blocks. `close_connection` ignores `half_close`; both paths set `write_eof` and send a FIN after the flush, never an RST. |
| UDP (`network/udp.rs`) | Hand-rolled. A 4-tuple LRU with 60 s expiry maps to a ConnectionId. `read` returns one datagram; `drain` returns immediately. IDs are even for TCP and odd for UDP (`messages.rs`). |
| ICMP (`network/icmp.rs`) | Echo requests (v4 and v6) get fake replies so apps believe the network is up. No Python equivalent. |
| Task loop (`network/task.rs`) | One tokio task. Event channel capacity 256; command channel unbounded; backpressure through channel permits. |
| `packet_sources/wireguard.rs` | boringtun `Tunn` per peer, keepalive 25 s. Peer lookup by handshake public key or `receiver_idx>>8`. Outgoing peer is chosen by dst IP learned from decrypted source IPs, falling back to the first peer. Max packet is 65535 minus 80. |
| `packet_sources/udp.rs` | Plain UDP via socket2 (`IPV6_V6ONLY`, non-blocking) feeding `UdpHandler`. Swallows Windows error 10054. No tunnel info. |
| `packet_sources/tun.rs` | Linux only. `tun` 0.8 async device, MTU 65535, address 169.254.0.1. Writes `rp_filter=0`, `route_localnet=1` and `accept_local=1` under `/proc/sys/net/ipv4/conf/<tun>/`. A named persistent TUN is reopened unconfigured on PermissionDenied. |
| `packet_sources/{linux,windows,macos}.rs` | Spawn the redirector, then forward packets (Linux, Windows) or per-flow streams (macOS). See section 4. |
| `certificates/` | macOS only. `add_cert` stores the cert in the keychain with label "mitmproxy" (replacing any existing one), then runs `open <truster.app>`. `remove_cert` deletes it. |
| `dns.rs` | hickory-resolver 0.26.1 `TokioResolver`. System config via `read_system_conf()`. Custom servers get UDP and TCP on port 53. `Ipv4AndIpv6` strategy, results interleaved v4/v6. `lookup_ipv4/6` filter `lookup_ip`, because hickory's own v4/v6 calls skip the hosts file. |
| `shutdown.rs` | `watch<()>` receiver. `shutdown_task` joins a JoinSet, cancels the rest on the first failure, then signals "done". |
| `intercept_conf.rs` | Spec grammar: comma-separated, a bare integer is a PID, anything else is a process-name **substring**, `!` excludes. Evaluated in order. The default is intercept-all if the first action is an exclusion. |
| `processes/` | See below. |

**IPC schema** (`src/ipc/mitmproxy_ipc.proto`, proto3, package `mitmproxy_ipc`):
- Messages: `PacketWithMeta{data, TunnelInfo}`, `TunnelInfo{optional pid, optional process_name}`, `FromProxy{oneof Packet|InterceptConf}`, `Packet{data}`, `InterceptConf{repeated string actions}`, `NewFlow{oneof TcpFlow|UdpFlow}`, `TcpFlow{remote_address, tunnel_info}`, `UdpFlow{optional local_address, tunnel_info=3}`, `UdpPacket{data, remote_address}`, `Address{host, port}`.
- The generated Rust is checked in (`src/ipc/mitmproxy_ipc.rs`, protoc-gen-prost in `.github/workflows/autofix.yml`; not prost-build). The Swift copy is `mitmproxy-macos/redirector/ipc/mitmproxy_ipc.pb.swift`.
- Transports: Linux uses `UnixDatagram`, Windows uses a message-mode named pipe, macOS uses Unix stream sockets (details in section 4).
- IPv6 scope suffixes such as `%awdl0` are stripped (`src/ipc/mod.rs`).

**`processes/`:**
- Linux and macOS (`nix_list.rs`): `sysinfo` 0.39.6, grouped by executable path. `is_system` means a path under `/System/` on macOS and uid<1000 on Linux. Visible windows come from macOS `CGWindowListCopyWindowInfo`; Linux always reports none.
- Windows (`windows_list.rs`): `EnumProcesses`, `QueryFullProcessImageNameW`, `IsProcessCritical`, and the `FileDescription` version resource as display name. Visibility uses `EnumWindows` plus the DWM cloaked check.
- Icons: macOS uses `NSRunningApplication.icon`, TIFF, then the `image` crate to a 32×32 PNG. Windows uses `ExtractAssociatedIconW` and `GetDIBits`. Both are cached by icon hash. Linux has none.

**Binaries:** only `src/bin/process-list.rs`, an HTML dump of the process list for Windows and macOS (a stub on Linux).

## 4. Platform components

**Linux** (`mitmproxy-linux*`)
- **Hook:** the eBPF program is a `cgroup_sock` `sock_create` hook, attached to the root cgroup `/sys/fs/cgroup/` (`mitmproxy-linux/src/main2.rs`).
- **Decision:** for a matching process it sets `sk->bound_dev_if` to the TUN ifindex, so the process's new sockets bind to the TUN (`mitmproxy-linux-ebpf/src/main.rs`).
- **Spec storage:** the intercept spec lives in an `INTERCEPT_CONF` array map of at most 20 `Action`s, terminated by a `None` sentinel.
- **Matching:** `Pid` is compared to tgid. `Process` is compared exactly to the 15-byte-truncated `comm` (`mitmproxy-linux-ebpf-common/src/lib.rs`).
- **IPv6:** the redirector adds `ip -6` policy routing through netlink (rtnetlink 0.23, table 1783940182).
- **Packet path:** TUN read → `PacketWithMeta` → `UnixDatagram` (one message per datagram) → proxy. Reinjection is the reverse.
- **Tunnel info:** the redirector sends `tunnel_info: None`, so on Linux `pid` and `process_name` are never attributed.
- **Launch:** a dummy `sudo echo -n`, then `sudo --non-interactive --preserve-env <exe> <tmpdir>`. The redirector prints its socket path on stdout (5 s timeout) and chmods the sockets 0777.
- **Versions:** aya 0.14.0, aya-ebpf 0.2.1, aya-log 0.3.0, aya-build 0.2.0. Building needs nightly, `build-std=core` and `bpf-linker` (CI pins 0.9.15).

**macOS** (`mitmproxy-macos/redirector/`, Swift 5, deployment target 12.0, SwiftProtobuf 1.22.1)
- **App:** `Mitmproxy Redirector.app` installs the system extension (`OSSystemExtensionRequest`) and configures `NETransparentProxyManager` (`app.swift`).
- **Extension:** `NETransparentProxyProvider` with the `app-proxy-provider-systemextension` entitlement. It includes all outbound traffic and decides per flow in `handleNewFlow`. Process identity comes from the flow's audit token, resolved to a pid and executable path (`ProcessInfoCache.swift`).
- **IPC:** one control connection on the Unix socket `/tmp/mitmproxy-<pid>` (length-delimited `InterceptConf` frames, 5 s accept timeout). Each intercepted flow gets its own connection with a u32-BE-prefixed `NewFlow` handshake. TCP then carries raw bytes. UDP carries length-delimited `UdpPacket` frames. There is no smoltcp on this path.
- **Process name:** `process_name` is the executable path, matched by substring.
- **Signing:** Developer ID with manual signing and two provisioning profiles, then `notarytool` and `stapler` (`.github/scripts/build-macos-redirector.sh`).
- **Install:** at runtime the proxy untars `Mitmproxy Redirector.app.tar` into `/Applications` (mtime-compared; `MITMPROXY_KEEP_REDIRECTOR=1` skips it).
- **Certificate truster:** the `.app` bundle holds only `Info.plist` and the icon in the tree, and `certs.add_cert` expects the binary inside it. See section 9 for the packaging gap.

**Windows** (`mitmproxy-windows/redirector/src/main2.rs`)
- **WinDivert:** v2.2.2 (`WINDIVERT_VERSION`), crate windivert 0.6.0, vendored `WinDivert.dll`, `.lib` and `WinDivert64.sys`.
- **Handles:**
  - A socket-layer sniff handle on `tcp || udp` learns the pid on connect, accept, listen and close.
  - A network-layer handle filters `!loopback && ((ip && remoteAddr < 224.0.0.0) || (ipv6 && remoteAddr < ff00::)) && (tcp || udp)`.
  - A send-only handle reinjects packets.
- **Per-connection state:** an LRU of 10 minutes holds `Known(Intercept(pid, name) | None)` or `Unknown`; packets are buffered until the socket event arrives. `GetExtendedTcpTable/UdpTable` (`src/windows/network.rs`) resolves existing connections.
- **IPC:** pipe `\\.\pipe\mitmproxy-transparent-proxy-<pid>`, message mode, `reject_remote_clients`. `PacketWithMeta` carries pid and path. The proxy fills IP checksums for WinDivert packets.
- **Elevation:** started with `ShellExecuteW "runas"`. The build manifest is `requireAdministrator`.
- **Driver signing:** the `.sys` is a vendored upstream binary. I did not verify its signature from the tree.

## 5. Contentviews and highlight

| View (`instance_name`) | Priority | Output and crates |
|---|---|---|
| `hex_dump` ("Hex Dump") | 0.5 if binary | pretty-hex 16 bytes per line, ASCII column; prettify only |
| `hex_stream` | 0.4 if binary | lowercase hex via data-encoding; reencode accepts permissive hex |
| `msgpack` | 1.0 for `application/(x-)msgpack` | rmp-serde to YAML via serde_yaml; reencode YAML to msgpack (named structs) |
| `protobuf` | 1.0 for `application/x-(protobuf\|protobuffer)` | schema-less decode with field-type guessing; YAML tags `!varint`, `!sint`, `!fixed32`, `!fixed64`, `!binary`; unknown fields are keyed by number; protobuf 3.7.2 plus protobuf-parse 3.7.2 read `.proto` files or folders at runtime; best match by `/pkg.Service/Method`, else first service or message; YAML to proto reencode |
| `grpc` | 1.0 for `application/grpc`, `grpc+proto`, `prpc` | 5-byte frame headers, gzip/deflate/identity from `grpc-encoding` (flate2); frames joined by `\n---\n\n`; reencode writes uncompressed frames |
| `_test_inspect_metadata` | n/a | test-only |

`mitmproxy-highlight`: tree-sitter 0.26.12 with grammars css 0.25.0, javascript 0.25.0, xml 0.7.0, yaml 0.7.2, plus `none` and `error`. Tags: Text (empty string), Name, String, Number, Boolean, Comment, Error. `tags()` returns the six non-empty ones. The CSS grammar's one-"Name" limit is worked around by mapping properties to `Boolean`.

## 6. How Python consumes it

Nothing in `$PY/mitmproxy` imports `mitmproxy_windows`, `mitmproxy_macos` or `mitmproxy_linux`. Only the Rust code imports them, to call `executable_path()` or locate the redirector tar.

| Python module | Rust API |
|---|---|
| `mitmproxy/proxy/mode_servers.py` | `udp.start_udp_server`, `wireguard.{start_wireguard_server,genkey,pubkey}`, `local.start_local_redirector` and `set_intercept` (spec `!<own pid>` is always appended), `tun.create_tun_interface`, `Stream` (`remote_endpoint` extra info) |
| `mitmproxy/proxy/mode_specs.py` | `local.LocalRedirector.describe_spec` (spec validation) |
| `mitmproxy/proxy/server.py` | `udp.open_udp_connection` for every UDP upstream connection; `Stream` as reader/writer |
| `mitmproxy/addons/dns_resolver.py` | `dns.get_system_dns_servers`, `dns.DnsResolver` |
| `mitmproxy/contentviews/__init__.py` | registers every non-underscore instance in `mitmproxy_rs.contentviews.__all__` |
| `mitmproxy/contentviews/_view_http3.py` | `hex_dump.prettify` |
| `mitmproxy/addons/dumper.py`, `tools/console/flowview.py` | `syntax_highlight.highlight` |
| `mitmproxy/tools/web/app.py` | `local.LocalRedirector.unavailable_reason`, `process_info.active_executables`, `executable_icon` |
| `test/mitmproxy/**` | `syntax_highlight.tags()` and `languages()` for palette coverage; `udp`, `dns` and `tun` mocks |
| `mitmproxy_rs.certs` | **no call site** in `mitmproxy`, `test` or `docs` |

## 7. Rust-only vs duplicated

**(a) Rust-only, no Python fallback** (most of the surface):
- `Stream` and the whole handler contract.
- `udp.open_udp_connection` (all UDP upstreams) and `udp.start_udp_server` (UDP listeners).
- WireGuard server plus `genkey` and `pubkey`; `tun`; the local redirector on all three platforms; spec parsing.
- `process_info`.
- The hex_dump, hex_stream, msgpack, protobuf and grpc views.
- All of `syntax_highlight`.
- `certs`, which is also unused by Python.

**(b) Rust-backed with a Python fallback:** only DNS. `dns_resolver.py` falls back to `GetaddrinfoFallbackResolver` when no name servers are known and the hosts file is enabled; a `RuntimeError` from `get_system_dns_servers` becomes an empty list. The web app's icon endpoint also substitutes a transparent PNG on error, but that is error handling, not an alternative implementation.

**(c) Overlapping or duplicated:**
- `mitmproxy/platform/{linux,osx,pf,openbsd,windows}.py` is legacy transparent mode (`SO_ORIGINAL_DST`, pf, and a pydivert/WinDivert proxy in `windows.py`; `pyproject.toml:49` depends on `pydivert`). It has the same goal as the local redirector with a different mechanism, and Windows has two independent WinDivert consumers.
- Python's `_view_css`, `_view_javascript` and `_view_xml_html` are reformatters, while Rust only highlights. The domain overlaps but this is not duplication.
- Intercept-spec matching exists in four places and **diverges**:
  - Rust (`src/intercept_conf.rs`) and Swift (`InterceptConf.swift`) use substring match on the executable path.
  - eBPF uses exact match on `comm`, truncated to 15 bytes.
  - Linux never attributes pid or name back to the proxy; only Windows and macOS do.

**Not in Rust at all:** TLS, X.509 and CA generation, HTTP/1-3, QUIC, DNS wire parsing and serving (`layers.DNSLayer`). The lockfile has no rustls, x509-parser or rcgen.

## 8. Dependencies (locked versions from `Cargo.lock`)

| Crate | Version | Role |
|---|---|---|
| boringtun | 0.7.1 | WireGuard (`Tunn`) |
| smoltcp | 0.13.1 (core), 0.14.0 (test client) | userspace TCP/IP |
| internet-packet | 0.2.4 | packet parsing and checksums |
| hickory-resolver (and `-proto`, `-net`) | 0.26.1 | DNS resolver; hickory-server is dev-only |
| aya, aya-ebpf, aya-log, aya-build | 0.14.0, 0.2.1, 0.3.0, 0.2.0 | eBPF load and build |
| tun | 0.8.14 (manifest 0.8.8) | Linux TUN device |
| rtnetlink, netlink-packet-route | 0.23.0, 0.33.0 | Linux IPv6 policy routing |
| windivert, windivert-sys | 0.6.0, 0.10.0 | Windows capture |
| windows | 0.62.2 | Win32 APIs |
| tree-sitter, `-highlight` | 0.26.12 | highlighting |
| tree-sitter-css, `-javascript`, `-xml`, `-yaml` | 0.25.0, 0.25.0, 0.7.0, 0.7.2 | grammars |
| prost | 0.14.4 | IPC messages |
| tokio, tokio-util | 1.53.1, 0.7.19 | async runtime, `LengthDelimitedCodec` |
| pyo3, pyo3-async-runtimes, pyo3-log | 0.29.2, 0.29.0, 0.13.4 | Python bridge |
| security-framework | 3.7.0 | macOS keychain and trust |
| objc2-app-kit, core-graphics | 0.3.2, 0.25.0 | macOS icons and windows |
| sysinfo | 0.39.6 | process enumeration |
| image | 0.25.10 | TIFF to PNG |
| protobuf, protobuf-parse | 3.7.2 | dynamic protobuf and `.proto` parser |
| serde_yaml, rmp-serde | 0.9.34 (deprecated), 1.3.1 | YAML and msgpack |
| flate2 | 1.1.9 | gRPC decompression |
| lru_time_cache | 0.11.11 | UDP and Windows connection LRU |
| socket2 | 0.6.5 | UDP socket options |

## 9. Build and distribution

- **`mitmproxy_rs` wheel:** `maturin build --release` in `mitmproxy-rs/`. Linux x86_64 and arm64 use manylinux2014 via `--zig`, plus an sdist. macOS is universal2; Windows is x86_64. Python 3.12 or later (abi3).
- **`mitmproxy_linux`:** maturin `bindings="bin"` produces a py3-none wheel. The redirector lands in the scripts directory and `executable_path()` finds it (`mitmproxy-linux/mitmproxy_linux/__init__.py`). The eBPF object is embedded at build time.
- **`mitmproxy_windows`:** `cargo build --release --package windows-redirector`, then a hatchling wheel containing the exe and the WinDivert files. `.cargo/config.toml` sets `WINDIVERT_PATH`.
- **`mitmproxy_macos`:** hatchling wheel containing `Mitmproxy Redirector.app.tar`. Without signing secrets the build writes an **empty tar placeholder**.
- **Version pinning:** on tags, `.github/scripts/pin-versions.py` pins `mitmproxy_{windows,linux,macos}==<version>` in `mitmproxy-rs/pyproject.toml`.
- **Certificate truster gap:** CI builds a `lipo` universal binary into `target/release/`. But the `force-include` line at `mitmproxy-macos/pyproject.toml:23` is commented out, and `mitmproxy-rs/.gitignore` ignores `mitmproxy_rs/*.app`. `src/util.rs:108` looks for the `.app` next to `mitmproxy_rs`. I found no step that places the binary in either wheel, so `certs.add_cert` would fail on macOS, and Python never calls it.
- **Runtime requirements:**
  - Linux local mode needs root through sudo and cgroup v2 at `/sys/fs/cgroup`.
  - Linux TUN needs root, unless `tun_name` names a pre-configured persistent TUN (0.12.4 changelog).
  - macOS needs version 12 or later, write access to `/Applications`, a signed and notarized bundle, and user approval of the system extension.
  - Windows needs a UAC prompt on every redirector start (`mode_servers.py` keeps the daemon alive across stops to avoid repeats).
  - TUN is unavailable off Linux.

## 10. Tests and fixtures

- **`src/network/tests.rs`** (859 lines, a `MockNetwork` harness with raw v4/v6 TCP, UDP and ICMP packet builders) is the best conformance fixture. Tests: `do_nothing`, `ipv4_udp`, `ipv6_udp`, `tcp_ipv4_connection`, `tcp_ipv6_connection`, `receive_icmp4_echo`, `receive_icmp6_echo`.
- **Other in-crate tests:** `intercept_conf.rs` (spec grammar), `ipc/mod.rs` (scope stripping), `dns.rs` (in-process hickory server, interleave), `shutdown.rs`, and the contentview roundtrips (`test_roundtrip!` macro in `view_protobuf.rs`, plus hex and msgpack vectors and `mitmproxy-contentviews/testdata/protobuf/*.proto`). The macOS packet source also has stream tests for pending-read and pending-write behaviour.
- **`mitmproxy-rs/pytests/test_task.rs`:** a Rust integration test of `PyInteropTask` error handling. Despite the name it is not Python; low value for a Go port.
- **`wireguard-test-client`:** fixed-key boringtun client. It sends an IPv4 UDP "hello" (1234 → 31337) and a TCP SYN and then data, expecting the upper-cased echo ("HELLO", "HELLO WORLD!"). `$PY/test/wg-test-client/` ships prebuilt x86_64 and macOS binaries plus `test.conf`, usable end to end against a Go WireGuard server. `$PY/test/mitmproxy/proxy/test_mode_servers.py` drives them.
- **`benches/`:** `process.rs` (criterion; macOS and Windows; uses the `openvpnserv.exe` icon fixture), the contentviews and highlight criterion benches, and Python WG/asyncio echo throughput scripts.
- **Stale API in helper scripts:** `wireguard-test-client/wireguard_echo_test_server.py` and `benches/dns.py` call `mitmproxy_rs.start_wireguard_server` and `mitmproxy_rs.DnsResolver` at top level, which no longer exist. They should be `wireguard.start_wireguard_server` and `dns.DnsResolver`.

## Summary: what a Go port must cover

1. Reimplement the `Stream` contract and the handler/shutdown semantics: unbounded sync `write`, `drain`-only backpressure, FIN-only close, no-op `wait_closed`, the `get_extra_info` keys, and the traps (WG `original_*` are the peer endpoint and server socket).
2. Userspace TCP/IP with any-IP: gVisor netstack is the realistic Go replacement for smoltcp (64 KiB buffers, 60 s timeout, 28 s keepalive, MTU 1420, listen-on-destination). It needs a hand-written UDP 4-tuple LRU (60 s) and fake ICMP echo.
3. WireGuard server: wireguard-go (replaces boringtun); the peer-by-IP routing and first-peer fallback are custom.
4. UDP/TUN servers and `open_udp_connection`: pure Go with `x/sys`. Replicate the Linux `/proc/sys` tweaks and persistent-TUN fallback.
5. DNS resolver with gaierror-style errors, v4/v6 interleave and hosts-file filtering: pure Go (`miekg/dns` or stdlib).
6. Protobuf/gRPC/msgpack/hex views: pure Go (`protocompile` + `dynamicpb`/`protowire`, a msgpack library, a YAML library that preserves `!varint`-style tags). Port the `.proto` fixtures and roundtrip vectors.
7. Syntax highlighting: tree-sitter needs cgo, or accept different tags with a pure-Go lexer. This is a conformance risk because the tag set is part of the Python API.
8. **Not pure Go:** the macOS Network Extension must stay Swift/ObjC, with Apple Developer signing, provisioning profiles, notarization and user approval. Go can only implement the Unix-socket IPC (`NewFlow` handshake, length-delimited frames).
9. **Needs native or build-time artifacts:** the Linux eBPF object must be compiled with clang or Rust nightly plus bpf-linker and embedded; loading and attaching from Go works via cilium/ebpf. WinDivert is a signed kernel driver plus DLL, loadable from Go without cgo but needing a separate elevated exe and attention to LGPL. macOS process icons and window lists need ObjC (purego or cgo).
10. Decide intercept-spec semantics once (substring on path vs exact `comm`, Linux has no attribution). Defer the unused `certs` module and the unpackaged truster.