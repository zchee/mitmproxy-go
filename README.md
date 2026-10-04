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
| [mitmproxy](https://github.com/mitmproxy/mitmproxy) (Python) | `3368a0a` | `13.0.0.dev`, flow format version 21 |
| [mitmproxy-rs](https://github.com/mitmproxy/mitmproxy-rs) (Rust) | `51fe2b7` | workspace `0.13.0-dev`; redirector artifacts come from the 0.12.x wheels |

## Status

Planning is complete. Foundation work (tooling, CI, flow data model, codecs and registries) is in progress; there is no
binary yet. The three binaries `mitmdump`, `mitmproxy` and `mitmweb` will live under `cmd/`.

The work plan, with scope, architecture, package choices and acceptance criteria, is
[docs/plans/mitmproxy-go-port.md](docs/plans/mitmproxy-go-port.md). Pinned dependencies and their upgrade paths are
listed in [docs/dependencies.md](docs/dependencies.md). Where the port behaves differently from mitmproxy on purpose,
and why, is listed in [docs/compat.md](docs/compat.md).

## Requirements

Go 1.27 or newer.

## Development

```sh
hack/fmt.sh    # gofmt, gofumpt, modernize, goimports-rereviser
hack/lint.sh   # go vet, golangci-lint
go test -race -count=1 ./...
```

## Licence

MIT; see [LICENSE](LICENSE). Upstream mitmproxy and mitmproxy-rs are MIT-licensed; fixtures copied from them carry
their notice under `testdata/`.
