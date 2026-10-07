# Synthetic redirector IPC vectors

These files are **encoder-generated synthetic vectors**, not captured traffic and
not evidence that an installed redirector interoperates with this proxy.

The schema comes from `src/ipc/mitmproxy_ipc.proto` in mitmproxy-rs commit
`51fe2b7c5aa8439c162abb665db61c6669d146d6` (MIT; upstream licence in
`../UPSTREAM_LICENSE`). Only a final newline was added to the schema copy.
`protoc` 36.2 encoded the checked-in `.textproto` inputs independently of the Go
bindings. The four `.frame` files have a four-byte big-endian payload length,
matching `src/packet_sources/macos.rs`'s `LengthDelimitedCodec` and NewFlow
handshake. `.pb` files contain only protobuf bytes: Windows pipe messages and
Linux UnixDatagram messages have no additional stream length prefix.

| Input | Protobuf type | Framing |
|---|---|---|
| `intercept` | `mitmproxy_ipc.InterceptConf` | `.frame` for macOS; `.pb` for Linux |
| `new_tcp` | `mitmproxy_ipc.NewFlow` | `.frame` for macOS TCP handshake |
| `new_udp` | `mitmproxy_ipc.NewFlow` | `.frame` for macOS UDP handshake |
| `packet_meta` | `mitmproxy_ipc.PacketWithMeta` | `.pb` for Windows |
| `udp_packet` | `mitmproxy_ipc.UdpPacket` | `.frame` for macOS UDP |
| `linux_packet` | `mitmproxy_ipc.PacketWithMeta` | `.pb`, one Linux datagram, no attribution |
| `from_proxy_intercept` | `mitmproxy_ipc.FromProxy` | `.pb` for Windows |
| `from_proxy_packet` | `mitmproxy_ipc.FromProxy` | `.pb` for Windows |

Regenerate each `.pb` from the repository root with its type from the table:

```sh
protoc --proto_path=internal/local --encode=mitmproxy_ipc.InterceptConf \
  mitmproxy_ipc.proto < testdata/local-ipc/synthetic/intercept.textproto \
  >| testdata/local-ipc/synthetic/intercept.pb
```

For `.frame`, prefix the encoded `.pb` with its byte length as an unsigned
32-bit big-endian integer. Linux vectors are separate datagrams, never
concatenated or length-prefixed. The decode tests verify all fields, optional
presence, oneof selection, and byte-for-byte re-encoding. The payload bytes in
packet vectors are arbitrary test data, not validated IP/checksum evidence.

Real control, handshake, attributed packet, UDP, and Linux datagram captures
remain manual-platform runbook obligations. Replace these compatibility inputs
with actual captures when those runbooks are executed; retain honest provenance
and distinguish platform-run evidence from these synthetic decode tests.
