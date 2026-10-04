# Go MITM port: package survey (facts only)

Data as of 2026-10-05 02:31 JST (`date`). Toolchain: go1.27.1 darwin/arm64 (Go 1.27 release notes: go.dev/doc/go1.27, "August 2026"). "Latest" = Go proxy version and tag-commit date (GitHub release date differs where noted). "HEAD" = default-branch HEAD commit date (GitHub API). "I+PR" = GitHub open issues+PRs. "go" = `go` directive of the latest module. Sources: Go proxy, GitHub API, downloaded module sources, GOROOT sources. "Built" = compiled in a scratch module with go1.27.1, CGO_ENABLED=0, darwin/arm64 and linux/amd64.

## a. HTTP/1.x raw fidelity

**std `net/http` loses (verified in GOROOT src):**
- Read: `textproto.Reader.ReadMIMEHeader` always runs `canonicalMIMEHeaderKey`; non-token header names return `ProtocolError`. No hook. Original key case is lost.
- `http.Header` is `map[string][]string`: cross-key order lost; repeats of one key keep relative order.
- Write: `Header.Write/WriteSubset` sort keys (`sortedKeyValues`); `Trailer` keys are written sorted.
- Kept raw: `Request.RequestURI` (server side), `Method`, `Proto`. `Host` is removed from the map; `Transfer-Encoding`, `Content-Length`, `Connection` are consumed by `readTransfer`/`shouldClose`.
- Server auto-handles `Expect: 100-continue` (`expectContinueReader`); client sees 1xx only via `httptrace.ClientTrace.Got1xxResponse`.
- Bypass: not through `http.ReadRequest`/`Request.Write`/`Transport`. Use `http.Hijacker` or your own `net.Conn`, parse with `bufio`/`textproto.Reader.ReadLine`, write raw bytes. (Design statement; not tested.)

| Module | Latest (date) | License | HEAD | I+PR | go | Fit |
|---|---|---|---|---|---|---|
| github.com/valyala/fasthttp | v1.74.0 (2026-09-07) | MIT | 2026-10-04 | 79 | 1.25.0 | Own parser. `DisableHeaderNamesNormalizing`; `AppendBytes` emits User-Agent/Host/Content-Type/Content-Length first unless `RequestHeader.DisableSpecialHeader`; trailers (`SetTrailer`); `Hijack`; `ContinueHandler`/`ExpectHandler`; no HTTP/2 in core. |

**Existing Go MITM/forward proxies.** None uses fasthttp; all use std `net/http` and `x/net/http2`. No raw-header/order feature found (grep: proxify 0 hits, others incidental). No Go repo exists under github.com/mitmproxy (org lists Python/Rust only).

| Module | Latest (date) | License | HEAD | I+PR | go | HTTP/2, WS, TLS interception |
|---|---|---|---|---|---|---|
| github.com/elazarl/goproxy | v1.9.2 (2026-09-27) | BSD-3 | 2026-09-27 | 81 | 1.24.0 | h2 MITM via `http2.Server.ServeConn`; WS via coder/websocket; CONNECT hijack + generated leaf; `CertStorage` cache optional. |
| github.com/google/martian/v3 | v3.3.3 (2022-08-16; GH release 2024-04-16) | Apache-2.0 | 2022-08-16 | 44 | 1.18 | **GitHub-archived.** Has `h2` package: `http2.Framer` relay. Leaf cache: map+RWMutex (no eviction seen). |
| github.com/lqqyt2423/go-mitmproxy | v1.9.3 (2026-08-31) | MIT | 2026-09-01 | 26 | 1.26 | README: HTTP/2, WebSocket (gorilla); h2 server + h2 transport upstream; mitmproxy-compatible `~/.mitmproxy` CA. |
| github.com/AdguardTeam/gomitmproxy | v0.2.2 (2026-08-18) | GPL-3.0 | 2026-08-18 | 14 | 1.20 | No http2 import; WS passthrough; `CertsStorage` interface (default map). |
| github.com/saucelabs/forwarder | v1.6.3 (2026-09-17) | MPL-2.0 | 2026-09-17 | 53 | 1.23.12 | README: HTTP/HTTPS/HTTP2, WebSockets, PAC; vendors a martian fork incl. `h2/relay.go`. |
| github.com/projectdiscovery/proxify | v0.0.16 (2025-08-29) | MIT | 2025-08-29 | 3 | 1.21 | Uses projectdiscovery/martian fork + goproxy; no http2 import; `-cert-cache-size` default 256. |
| github.com/ouqiang/goproxy | v1.3.2 (2022-04-25) | Apache-2.0 | 2022-04-25 | 14 | 1.13 | std only; ouqiang/websocket; stale. |
| github.com/go-gost/gost | pseudo (2026-10-03) | MIT | 2026-10-03 | 103 | 1.26.3 | Tunnel toolkit (logic in go-gost/x); deps tls-dissector, quic-dissector. MITM depth unverified. |
| github.com/kr/mitm | pseudo (2015-06-06) | MIT | 2015-06-06 | 4 | none | Historical; no go.mod. |
| github.com/bettercap/bettercap | v2.41.7 (GH 2026-05-11) | NOASSERTION | 2026-08-13 | 44 | not read | Not examined. |

Worker note: raw fidelity means your own HTTP/1 parser (or fasthttp with `DisableSpecialHeader` + no-normalizing, no h2); std is fine for decoded semantics.

## b. HTTP/2

**Go 1.27 std (verified):** `h2_bundle.go` is gone. HTTP/2 lives in `net/http/internal/http2` (not importable). `net/http/http2.go`: x/net/http2 "is no longer synchronized with std". `http.Protocols` (`HTTP1`, `HTTP2`, `UnencryptedHTTP2`) on `Server`/`Transport`; `HTTP2Config`; `http.ClientConn` (since 1.26). New in 1.27: `Server.DisableClientPriority` (RFC 9218 priorities on by default), `Server.MaxHeaderValueCount`. GODEBUG: `http2client`, `http2server`, `http2debug`. x/net v0.59.0: `h2c` package Deprecated (use `Server.Protocols`); `http2.ClientConn` Deprecated (use `http.ClientConn`).

| Module | Latest (date) | License | HEAD | I+PR | go | Fit |
|---|---|---|---|---|---|---|
| golang.org/x/net/http2 (+hpack) | v0.59.0 (2026-09-08) | BSD-3 | 2026-09-28 | 73 (mirror) | 1.26.0 | `Framer` (`ReadFrame`, `ReadMetaHeaders`, `WriteRawFrame`, `WriteHeaders`...), `hpack`, `Server.ServeConn`, `Transport`. |
| github.com/dgrr/http2 | v0.4.0 (2026-07-18) | Apache-2.0 | 2026-08-31 | 18 | 1.20 | HTTP/2 for fasthttp only. |

Stream semantics: `Server`/`Transport` re-encode. `Transport` emits pseudo-headers in fixed order `:authority,:method,:path,:scheme(,:protocol)`; regular headers come from `range req.Header` (map order, `internal/httpcommon/request.go:156`). `hpack.Encoder` indexes every non-`Sensitive` field that fits (`shouldIndex`), so original HPACK representation choices cannot be reproduced. Wire-order preservation needs `Framer` + `MetaHeadersFrame.Fields`/`PseudoFields()`; martian and forwarder `h2/relay.go` do frame-level relay on this.

## c. HTTP/3 + QUIC

| Module | Latest (date) | License | HEAD | I+PR | go | Fit |
|---|---|---|---|---|---|---|
| github.com/quic-go/quic-go | v0.63.0 (2026-09-22) | MIT | 2026-10-04 | 217 | 1.26.0 | Built. `Listen/ListenEarly/Dial/DialEarly`, `Allow0RTT`, `EnableDatagrams` (RFC 9221), qlog `Tracer`, `internal/handshake/updatable_aead.go` (key update); has go1.27 shim; README: supports latest two Go releases. `http3`: `Server`, `Transport`, `ClientConn`, `RawClientConn`/`RawServerConn`, frame types, `HTTPStreamer`, capsules. Pre-1.0 versioning. |
| golang.org/x/net/quic | v0.59.0 | BSD-3 | 2026-09-28 | - | 1.26.0 | doc.go: "not ready for production usage", API may change, "0-RTT is not supported". |
| golang.org/x/net/http3 | v0.59.0 | BSD-3 | - | - | - | 61-line test shim (`linkname` to net/http tests); zero exported identifiers. |
| github.com/HyNetworks/quic-go (apernet/quic-go) | v0.63.0 per proxy | MIT | 2025-04-20 | 2 | 1.26.0 | Hysteria fork; version/HEAD mismatch, unverified. |

std `crypto/tls` also has `QUICConn`; Go 1.27 adds `QUICConfig.ClientHelloInfoConn`. No HTTP/3 in std (`Protocols` has no HTTP3).

## d. WebSocket

| Module | Latest (date) | License | HEAD | I+PR | go | Frames / compression |
|---|---|---|---|---|---|---|
| github.com/coder/websocket | v1.8.15 (2026-06-15) | ISC | 2026-06-15 | 72 | 1.23 | Message-level `Reader/Writer`; `OnPingReceived/OnPongReceived`; permessage-deflate with context-takeover modes. No raw frames. |
| github.com/gorilla/websocket | v1.5.3 (2024-06-14) | BSD-2 | 2025-03-19 | 83 | 1.12 | `NextReader/NextWriter/WriteControl/PreparedMessage`; compression "in a limited capacity" (doc.go:204). Not archived. No raw frames. |
| github.com/gobwas/ws | v1.4.0 (2024-05-03) | MIT | 2026-02-12 | 30 | 1.16 | **Frame level**: `ReadFrame/WriteFrame/ReadHeader/WriteHeader`; `wsflate` (permessage-deflate); `wsutil`. |
| github.com/lesismal/nbio | v1.7.0 (2026-09-23) | MIT | 2026-10-03 | 0 | 1.16 | Own connection engine ("1000k+ connections" per repo description); `nbhttp/websocket` `OnDataFrame(conn, type, fin, payload)`; compression supported. |
| golang.org/x/net/websocket | v0.59.0 | BSD-3 | 2026-09-28 | - | 1.26.0 | Doc: "lacks some features found in ... gorilla/websocket, coder/websocket". No formal `Deprecated:` tag found. |

Worker note: relaying fragments, ping/pong and RSV bits without re-encoding needs gobwas (or a hand-written RFC 6455 framer); coder/gorilla reassemble messages.

## e. TLS

**std crypto/tls (go1.27.1, verified):**
- `ClientHelloInfo`: `CipherSuites`, `ServerName`, `SupportedCurves`, `SupportedPoints`, `SignatureSchemes`, `SupportedProtos` (ALPN), `SupportedVersions`, `Extensions []uint16`, `Conn`, `HelloRetryRequest` (1.26). **No raw bytes field.**
- `Config`: `GetCertificate`, `GetConfigForClient`, `VerifyConnection`, `SessionTicketKey`/`SetSessionTicketKeys`/`SessionTicketsDisabled`; doc: keys of a `GetConfigForClient` result are used if set on it, else inherited from the parent.
- `ConnectionState`: `ECHAccepted`, `HelloRetryRequest`, `LocalCertificate` (new in 1.27), `TLSUnique`, `ExportKeyingMaterial`.
- Post-quantum: X25519MLKEM768 default since 1.24; SecP256r1MLKEM768 and SecP384r1MLKEM1024 default since 1.26; `MLKEM1024` opt-in via `CurvePreferences` in 1.27; ML-DSA signature scheme IDs added in 1.27. GODEBUG `tlsmlkem`/`tlssecpmlkem`. Removed in 1.27: `tlsunsafeekm`, `tlsrsakex`, `tls3des`, `tls10server`, `x509keypairleaf`. `Config.Rand` deprecated.
- ECH: client `EncryptedClientHelloConfigList` (+`EncryptedClientHelloRejectionVerify`, `ECHRejectionError`); server `EncryptedClientHelloKeys`/`GetEncryptedClientHelloKeys` (KEMs include ML-KEM variants).
- **ECH ordering (source):** `readClientHello` runs `processECHClientHello` before `GetConfigForClient`. With the origin's ECH key, `ClientHelloInfo.ServerName` is the **inner** SNI. With no keys (`len(echKeys)==0`) it returns the outer hello unchanged, so a proxy without the origin's key sees only the outer `public_name` SNI, and `Extensions` lists every offered extension ID (doc), so an ECH attempt should be detectable (not tested). `GetEncryptedClientHelloKeys` receives the outer `ClientHelloInfo`. Key present but no config match: not read (unverified).
- No-terminate peek: tcpproxy `sni.go` peeks the first TLS record, runs `tls.Server` over a read-only conn, captures `hello.ServerName` in `GetConfigForClient` (std-only; yields full `ClientHelloInfo`).

| Module | Latest (date) | License | HEAD | I+PR | go | Fit |
|---|---|---|---|---|---|---|
| github.com/refraction-networking/utls | v1.8.2 (2026-01-12) | BSD-3 | 2026-09-24 | 59 | 1.24 | Built. Fork of crypto/tls; client ClientHello mimicry (Chrome/Firefox/Safari IDs); `ech.go` present; README says "Minimum Go 1.21" (stale vs go.mod); tracked crypto/tls release unverified. |
| github.com/inetaf/tcpproxy | pseudo (2026-05-15) | Apache-2.0 | 2026-05-15 | 20 | 1.16 | Built. SNI peek above; no tags. |
| github.com/dreadl0ck/tlsx | v1.2.0 (2025-11-30) | BSD-2 | 2025-11-30 | 0 | 1.24.0 | `ClientHello.Unmarshal([]byte)`, JA3; depends on gopacket. GitHub marks it a fork. |
| golang.org/x/crypto/cryptobyte | v0.57.0 (2026-09-08) | BSD-3 | 2026-10-04 | 101 | 1.26.0 | Hand-written ClientHello parser (JA4 etc.). No ready JA4 library checked. |

## f. Certificates / CA

- std `crypto/x509`: `CreateCertificate(rand, template, parent, pub, priv)`; template has `DNSNames`, `IPAddresses`, `URIs`, `EmailAddresses`, `PermittedDNSDomains`, `ExcludedDNSDomains`, `PermittedIPRanges`, `PermittedURIDomains`, `PermittedEmailAddresses`, `IsCA`, `MaxPathLen`, `ExtraExtensions`, `Policies`. `ParsePKCS8PrivateKey`, `MarshalPKCS8PrivateKey`, `ParseECPrivateKey`, `ParsePKCS1PrivateKey`.
- Go 1.27 x509: new `RawSignatureAlgorithm` on Certificate/CSR/CRL; ML-DSA algorithm constants; wider `pkix.Name` value parsing; `SystemCertPool` honors `SSL_CERT_FILE`/`SSL_CERT_DIR` on Windows/Darwin (`x509sslcertoverrideplatform=0` reverts). Earlier settings still present: `x509sha256skid`, `x509usepolicies`, `x509negativeserial`, `x509rsacrt`.
- Leaf caches in surveyed proxies: go-mitmproxy `golang/groupcache/lru` (100) + `singleflight`; martian map+RWMutex; gomitmproxy map; goproxy optional `CertStorage`; proxify size flag (impl. unverified).

| Module | Latest (date) | License | HEAD / push | I+PR | go | Fit |
|---|---|---|---|---|---|---|
| software.sslmate.com/src/go-pkcs12 | v0.7.3 (2026-06-24) | BSD-3 | 2026-06-24 | 17 | 1.19 | `Encode` (with CA chain), `EncodeTrustStore`, `Modern2023`/`Modern2026`/`Legacy*` encoders, `Passwordless`. |
| golang.org/x/crypto/pkcs12 | v0.57.0 | BSD-3 | 2026-10-04 | 101 | 1.26.0 | Package is "frozen" per its doc. |
| github.com/hashicorp/golang-lru/v2 | v2.0.7 (2023-09-21) | MPL-2.0 | 2026-09-03 | 56 | 1.18 | Generic LRU/ARC/2Q; `expirable` subpackage adds TTL. |
| github.com/elastic/go-freelru | v0.16.0 (2024-11-20) | Apache-2.0 | push 2026-09-25 | 29 | 1.18 | LRU cache (no repo description). |
| github.com/jellydator/ttlcache/v3 | v3.4.1 (2026-06-22) | MIT | push 2026-09-14 | 19 | 1.23.0 | In-memory cache with expiration, generics (repo description). |
| github.com/maypok86/otter/v2 | v2.3.0 (2025-12-22) | Apache-2.0 | push 2026-06-19 | 18 | 1.24.0 | "High performance caching library" (repo description). |

## g. DNS

| Module | Latest (date) | License | HEAD | I+PR | go | Fit |
|---|---|---|---|---|---|---|
| github.com/miekg/dns (v1) | v1.1.73 (2026-08-19) | BSD-3 | 2026-09-01 | 3 | 1.25.0 | README: v2 is at codeberg; "this repo will only see specific fixes... At some point this repo will be archived". Client/server; DoT via `Net: "tcp-tls"`; no DoH/DoQ found in client/server code. |
| codeberg.org/miekg/dns (v2) | v0.6.118 (2026-10-04) | BSD-3 | not queried | n/a | 1.27.0 | Pre-1.0 ("2028?"), breaking changes allowed. DoH via `dnshttp`; DoQ "not implemented"; `svcb` pkg. go.mod requires certmagic, sqlx, geoip2, prometheus (README ties them to `cmd/`). |
| github.com/AdguardTeam/dnsproxy | v0.86.0 (2026-10-01) | Apache-2.0 | 2026-10-01 | 180 | 1.26.8 | Upstream + server for DoH/DoT/DoQ/DNSCrypt. |
| golang.org/x/net/dns/dnsmessage | v0.59.0 | BSD-3 | 2026-09-28 | - | 1.26.0 | Wire parser (vendored in std). `TypeHTTPS`/`TypeSVCB` constants only; no typed HTTPS/SVCB body found (falls to `UnknownResource`, unconfirmed). |

std `net.Resolver` exposes only `LookupHost/IP/NetIP/IPAddr/Port/CNAME/SRV/MX/NS/TXT/Addr`: no raw RRs, TTLs, rcodes, HTTPS/SVCB. `Resolver.Dial` can redirect transport. Worker note: miekg v1 is maintenance-only per its README; v2's go.mod requires go 1.27.0 or later; of the listed modules only dnsproxy documents DoQ.

## h. WireGuard + userspace TCP/IP

| Module | Latest (date) | License | HEAD | I+PR | go | Fit |
|---|---|---|---|---|---|---|
| golang.zx2c4.com/wireguard | pseudo (2026-05-22) | MIT | 2026-05-22 | 33 (GitHub mirror) | 1.23.1 | Built. `device.NewDevice(tun.Device, conn.Bind, logger)`; `tun.Device` is a 9-method interface (can be backed by gVisor). Its `tun/netstack` is host-style (`AddProtocolAddress`, gonet Dial/Listen): no promiscuous mode, no forwarders. No semver tags. |
| gvisor.dev/gvisor | pseudo (2026-10-04) | Apache-2.0 | 2026-10-04 | 866 | 1.26.3 | **`@latest` (95ed905fb406) does not build on go1.27.1**: `found packages stack ... and bridge (bridge_test.go)`; `pkg/tcpip/stack/bridge_test.go` declares `package bridge_test`. 20260915211658-a6f909f08a72 (Tailscale main pin) and 20250503011706-39ed1f5ac29c (wireguard-go pin) **built**. Breaking commit not isolated. |
| tailscale.com | v1.104.0 (2026-09-30) | BSD-3 | 2026-10-02 | 4689 | 1.27.1 | `wgengine/netstack`: `SetPromiscuousMode(nic,true)`, `tcp/udp.NewForwarder`, `SetTransportProtocolHandler`. Uses fork github.com/tailscale/wireguard-go (pseudo 2026-09-28, MIT, go 1.26.0). |
| github.com/xjasonlyu/tun2socks/v2 | v2.7.0 (2026-07-02) | MIT | 2026-09-13 | 13 | 1.26.3 | `core` built. `SetPromiscuousMode` + `SetSpoofing` + forwarders; pins gvisor 20260701204157-69c2d17aea96. |
| github.com/sagernet/gvisor | pseudo (2025-09-15) | Apache-2.0 | 2026-08-11 | 2 | 1.24.1 | Fork for sing-box. |
| github.com/sagernet/sing-tun | v0.9.6 (2026-09-24) | GPL-3.0 (text; API NOASSERTION) | 2026-10-02 | 44 | 1.25.0 | gVisor/system/mixed stacks, nftables auto-redirect. |
| github.com/eycorsican/go-tun2socks | v1.16.11 (2020-08-09) | MIT | 2020-11-07 | 13 | 1.13 | GitHub-archived; lwip. |

"Any destination" pattern (verified in tun2socks, Tailscale): promiscuous NIC (+spoofing), default route, TCP/UDP forwarders; original destination = `ForwarderRequest.ID().LocalAddress/LocalPort`.
**Size (measured):** net/http+tls+httputil baseline 6,055,570 B (darwin/arm64) / 6,353,056 (linux/amd64); plus gVisor stack+forwarders+gonet+wireguard device 9,005,426 / 9,408,672; delta about +2.95 / +3.06 MB (`-s -w`, CGO off). Blank-import probes understate size (the linker drops unused code).
mitmproxy-rs uses smoltcp 0.13.1 + boringtun 0.7.1. No pure-Go smoltcp equivalent found beyond gVisor and lwip (CGO).

## i. TUN

| Module | Latest (date) | License | HEAD | I+PR | go | Platforms |
|---|---|---|---|---|---|---|
| golang.zx2c4.com/wireguard/tun | see h | MIT | 2026-05-22 | - | 1.23.1 | darwin (utun), linux, windows (wintun), freebsd, openbsd. |
| github.com/songgao/water | pseudo (2020-03-17) | BSD-3 | 2020-03-17 | 30 | none | Linux; macOS TUN only; Windows "experimental". |
| github.com/net-byte/water | v0.0.9 (2023-03-06) | BSD-3 | 2023-03-06 | 2 | 1.18 | Linux, macOS, Windows (wintun). |

## j. Original destination

| Item | Facts |
|---|---|
| Linux `SO_ORIGINAL_DST` | `unix.SO_ORIGINAL_DST` exists (linux only). `IP6T_SO_ORIGINAL_DST` absent from x/sys (define locally). Generic `unix.GetsockoptIPv6Mreq/IPv6MTUInfo/IPMreq` exist (common trick for reading the sockaddr; not tested). std `syscall` has no constant. |
| Linux TPROXY | `IP_TRANSPARENT`, `IPV6_TRANSPARENT`, `IP_RECVORIGDSTADDR` in x/sys (linux; the last also freebsd). github.com/KatelynHaworth/go-tproxy (LiamHaworth redirects): last module version 2019-07-26, GitHub push 2021-11-24, MIT, 7 I+PR, no go.mod; `ListenTCP/ListenUDP/ReadFromUDP/DialUDP`. |
| macOS/FreeBSD pf | `DIOCNATLOOK` is in x/sys only for openbsd. darwin/freebsd are hand-rolled ioctl on `/dev/pf` (examples: Xray-core MPL-2.0, riobard/go-shadowsocks2 `pfutil` Apache-2.0, v2fly freebsd MIT, clash GPL-3.0). **Two different `pfioc_natlook` layouts exist** in the wild (84-byte `4*16+4*4+4*1` vs a uint32-port "xnu-12377" layout); ioctl numbers differ (0xc0544417 seen). No maintained standalone package found. FreeBSD has `IP_BINDANY`, OpenBSD `SO_BINDANY` in x/sys. |
| Windows | No Go package found that does original-destination lookup without WinDivert/WFP. `tailscale/wf` (BSD-3, HEAD 2024-02-14, go 1.18) controls WFP firewall rules, not redirect. |

## k. Local redirect

| Module | Latest (date) | License | HEAD | I+PR | go | Fit |
|---|---|---|---|---|---|---|
| github.com/cilium/ebpf | v0.22.0 (2026-06-26) | MIT | 2026-09-30 | 32 | 1.25.0 | Built. Pure Go loader; `ebpf.CGroupSock`, `AttachCGroupInetSockCreate`, `link.AttachCgroup`. `cmd/bpf2go` default `-cc clang` (`BPF2GO_CC`). Linux amd64/arm64, kernel >= 4.4 nominal. |
| github.com/imgk/divert-go | v0.1.0 (proxy 2022-02-05; GH release 2025-03-29) | **GPL-3.0** | 2025-04-06 | 1 | 1.18 | WinDivert 2.x; DLL via syscall; tags `divert_cgo`, `divert_embedded`. |
| github.com/williamfhe/godivert | pseudo (2018-12-29) | LGPL-3.0 | 2018-12-29 | 2 | none | GitHub-archived; loads WinDivert.dll. |

mitmproxy-rs (read from repo): Linux = Aya (Rust) `cgroup_sock(sock_create)` sets `sock->bound_dev_if` to a TUN ifindex for sockets whose pid/command match an eBPF-map pattern. Windows = `windivert` crate, prebuilt binary on PyPI. macOS = `Mitmproxy Redirector.app` hosting a Network System Extension (Xcode project), prebuilt; its README: dev builds need signing and notarization with a paid Apple Developer account. Go<->extension IPC protocol: unverified. A Go process can only be the proxy peer of such an extension; the extension itself is Swift/ObjC. WinDivert driver signing and admin requirement: unverified here.

## l. SOCKS5 server

| Module | Latest (date) | License | HEAD | I+PR | go | Fit |
|---|---|---|---|---|---|---|
| github.com/things-go/go-socks5 | v0.1.3 (2026-08-24) | MIT | 2026-09-17 | 13 | 1.18 | CONNECT/BIND/ASSOCIATE with `WithConnectHandle/WithBindHandle/WithAssociateHandle`; hooks `WithDial`, `WithRewriter`, `WithResolver`, `WithRule`, `WithAuthMethods`. |
| github.com/armon/go-socks5 | pseudo (2016-09-02) | MIT | 2016-09-02 | 32 | none | README TODO: BIND and ASSOCIATE unsupported. |
| github.com/txthinking/socks5 | pseudo (2026-06-01) | MIT | 2026-06-01 | 8 | 1.16 | README: TCP/UDP, IPv4/IPv6. |
| github.com/wzshiming/socks5 | v0.8.0 (2026-09-16) | MIT | 2026-09-16 | 1 | 1.19 | README: "Full TCP/Bind/UDP". |
| golang.org/x/net/proxy | v0.59.0 | BSD-3 | 2026-09-28 | - | 1.26.0 | Client only (`socks5`/`socks5h`, `proxy.Auth`); no HTTP CONNECT dialer. |

Hand-rolling: RFC 1928 handshake + RFC 1929 user/pass are small; UDP ASSOCIATE needs a relay socket, per-datagram header (RSV/FRAG/ATYP/DST), and association lifetime tied to the TCP control connection (worker estimate: a few hundred lines).

## m. Upstream proxy client

std `Transport.Proxy` (verified): schemes `http`, `https` (TLS to the proxy), `socks5`, `socks5h` (`socks5` treated as `socks5h`); userinfo becomes `Proxy-Authorization: Basic` (HTTP) or SOCKS user/pass; `ProxyConnectHeader`/`GetProxyConnectHeader`; `OnProxyConnectResponse`; CONNECT is written by the transport (transport.go:1986). No PAC, no NTLM/Kerberos. `golang.org/x/net/http/httpproxy.Config` implements env/NO_PROXY logic. A raw CONNECT tunnel outside `Transport` is hand-written (x/net/proxy has none). forwarder advertises PAC.

## Decision matrix

| Block | Candidates | Key differentiator |
|---|---|---|
| a | std net/http; fasthttp; own parser | std loses key case, header order, unknown names; fasthttp keeps case/order (with flags), no h2 |
| a-prior art | goproxy, go-mitmproxy, forwarder, martian (archived), gomitmproxy (GPL) | all std HTTP layer; only martian/forwarder have frame-level h2 relay |
| b | std (internal h2), x/net/http2 | std not importable; x/net unsynced; Framer/hpack for wire order |
| c | quic-go; x/net/quic | quic-go has 0-RTT, datagrams, raw h3 conns; x/net/quic WIP, no 0-RTT |
| d | gobwas; nbio; coder; gorilla | only gobwas/nbio expose frames |
| e | std; utls; tcpproxy; tlsx; cryptobyte | std ECH inner SNI only with origin key; no raw hello bytes |
| f | x509; go-pkcs12; lru libs | std for x509; go-pkcs12 BSD-3; golang-lru MPL-2.0; cache choice only |
| g | miekg v1; codeberg v2; dnsproxy; dnsmessage | v1 maintenance-only; v2 pre-1.0 needs go 1.27.0; DoQ only via dnsproxy |
| h | wireguard-go; gVisor; tailscale; tun2socks | gVisor HEAD broken on 1.27.1; pin an older pseudo-version; +3 MB |
| i | wireguard/tun; water | wireguard/tun is the maintained one |
| j | x/sys; go-tproxy; pf copies | no pf package; layouts conflict |
| k | cilium/ebpf; divert-go; mitmproxy-rs ref | bpf2go needs clang; divert-go GPL; macOS needs Swift extension |
| l | things-go; wzshiming; armon | armon lacks BIND/UDP |
| m | std Transport; x/net/proxy | std covers http/https/socks5; no PAC/NTLM |

## Could not verify

gost MITM depth; bettercap internals; HyNetworks/apernet tag vs HEAD mismatch; utls base crypto/tls release; whether `dnsmessage` returns `UnknownResource` for HTTPS RRs; Go 1.27 behavior when ECH keys are set but no config matches; macOS extension IPC protocol; WinDivert driver signing/admin needs; exact gVisor commit that broke the `go` branch; correct `pfioc_natlook` layout per macOS version; Windows original-destination options beyond WinDivert/WFP; `IP6T_SO_ORIGINAL_DST` numeric value; proxify's cert cache implementation; Linux cgroup v2 / capability prerequisites for eBPF attach; JA4 libraries.
