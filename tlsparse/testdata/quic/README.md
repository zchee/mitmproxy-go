# QUIC Initial fixtures

`client_hello.hex`, `fragmented_client_hello1.hex` and
`fragmented_client_hello2.hex` are copied verbatim from
`test/mitmproxy/proxy/layers/quic/test__stream_layers.py` in Python mitmproxy
commit `3368a0a06ae6195aad817a1ece1aaeb6fe0353a1`.
The single packet's SNI is `example.com`; the fragmented hello's SNI is
`localhost` (the pinned `test_fragmented_client_hello` assertion).
The upstream MIT notice is in the repository's `testdata/UPSTREAM_LICENSE`.

`rfc9001_client_initial.hex` and `rfc9369_client_initial.hex` are the
independent protected Client Initial packets in appendix A.2 of
[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.2) and
[RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html#appendix-A.2).
Both carry SNI `example.com` and ALPN `alpn`.

`quic_go_initial_1.hex` and `quic_go_initial_2.hex` are **real captured
client datagrams**, not encoder-generated parser output. Captured once by
`/private/tmp/claude-501/-Users-zchee-go-src-github-com-zchee-mitmproxy-go/0fc8bd70-7a9e-4dcf-985b-c68d3c4db1af/scratchpad/quicfixture/generate.go`
(build tag `quicfixture`, isolated module `quicfixture`,
`github.com/quic-go/quic-go v0.63.0`, `go version go1.27.1 darwin/arm64`).
Capture time **2026-10-08 04:54:13 JST**, printed by `date` immediately
before the generator command in `tasks/bvghmfij7.output` of that session.
The client sent to a real UDP loopback socket with an initial packet size
of 1200, SNI `two-datagram.example`, ALPN `h3`, and X25519MLKEM768.
The receiver recorded its first two datagrams before cancelling the dial;
it did not accept TLS and did not rewrite the datagrams. Tests require
that either datagram alone is incomplete, both yield the expected SNI,
and reverse arrival order also completes.

A maintained copy of the build-tagged generator is `generate.go` beside
these fixtures. The original capture and its provenance above are unchanged.
To reproduce the capture, use a new empty output directory:

```sh
go run -tags quicfixture ./tlsparse/testdata/quic/generate.go <output-directory>
```

Fixture generation uses exclusive file creation to prevent accidental
replacement of the original capture.
