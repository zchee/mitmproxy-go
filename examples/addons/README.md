# Starlark addon examples

These are translations of the Python examples at mitmproxy commit
`3368a0a06ae6195aad817a1ece1aaeb6fe0353a1`. The original files are retained
byte-exact under [`testdata/mitmproxy/script/examples/addons/`](../../testdata/mitmproxy/script/examples/addons/).
They are MIT-licensed, Copyright (c) 2013 Aldo Cortesi; the complete upstream
copyright and permission notice is retained in
[`testdata/UPSTREAM_LICENSE`](../../testdata/UPSTREAM_LICENSE).
The translations remain covered by that notice.

## Running an example

```sh
mitmdump -s examples/addons/http-add-header.star
mitmdump -s examples/addons/options-simple.star --set addheader=true
mitmdump -s examples/addons/commands-simple.star
mitmdump --tcp-hosts '.*' -s examples/addons/tcp-simple.star
```

The same `-s` option is available in mitmproxy and mitmweb. The black-box
`script/acceptance` package builds race-enabled mitmdump and exercises all
eighteen ports with real owned HTTP, DNS, TCP and WebSocket peers. Its upstream
HTTP forwarder maps requested destinations to an owned loopback origin without
resolving or dialing the requested hostname. TCP and DNS use reverse mode with
owned loopback targets. Domain conditions in the translated scripts are not
rewritten for tests.

```sh
go test -race ./script/acceptance
go test -race -tags scripttiming -count=5 -cpu=1 -run '^TestScriptTiming$' ./script/acceptance
```

The tagged tests measure real one- and five-second waits, parallel completion,
hot reload and the watcher. They are separate from default deterministic
ownership and state assertions.

Scripts use module-level functions and dictionaries, not Python classes,
imports, decorators or async functions. `on_load(loader)` replaces Python's
`load` hook. The runtime supplies `ctx`, `byteops`, `module`, and HTTP/DNS
constructors; `concurrent` is supplied by the concurrent runtime. Binary content
stays bytes: `byteops.replace` and `byteops.startswith` avoid UTF-8 conversion.

`http-trailers.star` compares `http_version` strings (`"HTTP/1.0"`,
`"HTTP/1.1"`, `"HTTP/2.0"`, `"HTTP/3"`), not Python's boolean `is_http1x`
properties. `dns-simple.star` uses
`dns.ResourceRecord.AAAA("example.com", "::1")`: address input is textual,
class is IN and the default TTL is 60; `dns.ResourceRecord` itself is not a
callable constructor.

`commands-simple.star` registers the real zero-argument `myaddon.inc` command
and additionally invokes it through `ctx.master.commands.call` for each
request, making command registration and execution observable without a
console prompt. The upstream example only registers the command.

`nonblocking.star` translates only the thread-based alternative in the
upstream source, using `request = concurrent(_request)` and `ctx.sleep(5)`.
The active asyncio branch is not supported. Concurrent handlers see a frozen
second module instance and a detached flow; they cannot mutate the ordinary
module's dictionary. `tcp-simple.star` replaces occurrences within observed
chunks only: TCP does not preserve message boundaries.

The redirect and reply examples retain upstream's public-domain conditions.
Tests must map those destinations to owned local origins; running acceptance
must never depend on a public service.

## Translation provenance

Each `.star` file below is a translation of the correspondingly named
`examples/addons/<stem>.py` at the pinned commit. Git blobs identify those
original sources; the complete copied-source size/mode/SHA-256 provenance is
in [`testdata/README.md`](../../testdata/README.md#scripting-references).
Translations are not byte-exact upstream copies and never enter
`testdata/SHA256SUMS`. Translation digests identify source revisions separately
from the copied-byte manifest; they are not generated expected output.

| Translation | Upstream file | Upstream Git blob |
| --- | --- | --- |
| `anatomy.star` | `examples/addons/anatomy.py` | `a03404a91efec0631ff4b2418583dcd29b6c4397` |
| `anatomy2.star` | `examples/addons/anatomy2.py` | `09814c4861058d855135e59f199d3415f4591224` |
| `commands-simple.star` | `examples/addons/commands-simple.py` | `4edef09e6087de84cc2ea18eb692da259ea3d36c` |
| `dns-simple.star` | `examples/addons/dns-simple.py` | `69c742d7cd50c7fc65c17173e6325e30e46eb30e` |
| `http-add-header.star` | `examples/addons/http-add-header.py` | `b4a623fbad19e0a08c7606ecf89c182a6c040b61` |
| `http-modify-form.star` | `examples/addons/http-modify-form.py` | `7586adba7112e3dc8d59275c6b612c07996624ff` |
| `http-modify-query-string.star` | `examples/addons/http-modify-query-string.py` | `6908b72ce1232565d0a665fae17efe122cb5acfc` |
| `http-redirect-requests.star` | `examples/addons/http-redirect-requests.py` | `48390d5ad8fe420d57915c5e24ae3fd31202c80e` |
| `http-reply-from-proxy.star` | `examples/addons/http-reply-from-proxy.py` | `485fb499b818aae94d2c7bb91be5a7a00ea5b1a8` |
| `http-stream-simple.star` | `examples/addons/http-stream-simple.py` | `454f4792e58daf5ac710db62ab6900d12711f93d` |
| `http-trailers.star` | `examples/addons/http-trailers.py` | `5822389a1b1299dc5dce26c1b6aa11b360e44648` |
| `internet-in-mirror.star` | `examples/addons/internet-in-mirror.py` | `e0abf8817740d1a4a4ff21cba5d752cef66987f4` |
| `log-events.star` | `examples/addons/log-events.py` | `08a6225be7a38aba108d8cd87b53bc001638e847` |
| `nonblocking.star` | `examples/addons/nonblocking.py` | `1be8cd7310a395ac4967e51f774e92feebde4cb9` |
| `options-simple.star` | `examples/addons/options-simple.py` | `88ead1ee4e470291ec9f6ba77dfb7e8d360d20f6` |
| `shutdown.star` | `examples/addons/shutdown.py` | `cc8520037c380bfb91ca3767001e799ceac6bec9` |
| `tcp-simple.star` | `examples/addons/tcp-simple.py` | `11a464522d386d853c2af84848ec4ba68aa8d7c9` |
| `websocket-simple.star` | `examples/addons/websocket-simple.py` | `9ec1e6b956c24c5f34f2763ed7fbb16861724164` |

### Translation digests

These SHA-256 values identify the translated `.star` source bytes separately
from the upstream copied-source manifest. They are not generated test
expectations and do not assert byte equality with the Python originals. The
source/blob mapping above and the retained upstream notice apply to every row.

| Translation | SHA-256 |
| --- | --- |
| `anatomy.star` | `9192370aa424f83ec3afa4b0db05b2ae150cdda25704d3a5ed73c04b6ed90555` |
| `anatomy2.star` | `469c9fac211083aa5ee9d99a2065bbaea682d1145748036e0a6080561517e289` |
| `commands-simple.star` | `52d8a5b1675cb416460f0997652a59b1a26d42a91f40dfc2ffa1fc87ed12a5f8` |
| `dns-simple.star` | `42906b95f3086ce6a8b555e027ca5ac289fa91bf0a12bbdf3fc5f833199f2727` |
| `http-add-header.star` | `9156ba748c3d7cb992d9158c85bda26d470f5956cc28dd873e65dcc233cfa6de` |
| `http-modify-form.star` | `cf6722abc89d851d2b9130431b2ad5c1f7c45bf4846a59a64017d605853bfa91` |
| `http-modify-query-string.star` | `92fdf208b22be4c08d73a762f5f3d64eee89d32f5f40e6cf35065f63a823d2ad` |
| `http-redirect-requests.star` | `efc67604e032fa8c483e76ff5fc6b7940f7016efdb42d49cf58062d0dcde9772` |
| `http-reply-from-proxy.star` | `082a27cb50bded30f338a2acc3a155ce5e67df6f391a07360541e9bab13e5c99` |
| `http-stream-simple.star` | `f7dbc26dcade777928c384fdaa61acd17948e0e252b482b4b157e387da49040c` |
| `http-trailers.star` | `aee36fd94034e6b38d5876d50289ecb81b7eccb3e35abc80d51ee0e030fb637c` |
| `internet-in-mirror.star` | `ff7cad529451464b06031f0d53805c12fbba3a682b0c18510d784ea6caf285f1` |
| `log-events.star` | `773de81c5c4edd66f0ef7ac2ffb7bb827ab839c8ae62985c34a7fd7727ee2fe3` |
| `nonblocking.star` | `51a5b90e212a13559eac6c3fe4153d8f44f17a69acfbd8cd448d67de6e6cb137` |
| `options-simple.star` | `33d5f5690b2e6a966d2ab60741e762fc35c02fc14beb108b5dd0c44f096c3135` |
| `shutdown.star` | `6018347680e9122a2fb5f0686132fd73e5ba1633e6633df7db7836e7d9884f5a` |
| `tcp-simple.star` | `60e69b24edecf45c20bd119d3cd9a0a4882082e5dce0a39ee5ac8deb3a9396f0` |
| `websocket-simple.star` | `2d6318e04a33a1dbb90a5a808cb125c6eef7948148d10c2ec05145fc7892e466` |

## Examples not ported

These twelve files complete the disposition of all thirty upstream examples;
no partial substitute is claimed as a full port.

| Upstream example | Unsupported behavior / alternative |
| --- | --- |
| `commands-flows.py` | Arbitrary typed Python-decorated command registration; `loader.add_command` intentionally accepts zero-argument commands only. |
| `commands-paths.py` | Typed command registration plus direct Python file I/O; use existing save commands with explicit paths. |
| `contentview-interactive.py` | Python contentview class/reencode registration; existing Go contentviews are unchanged. |
| `contentview.py` | Python class/contentview plugin registration; body mutation is not an equivalent replacement. |
| `duplicate-modify-replay.py` | `ctx.master.addons` membership introspection; omitting its conditional view behavior would change the example. |
| `filter-flows.py` | Python `flowfilter.parse`/`match` imports; existing proxy filter options and commands remain available. |
| `http-stream-modify.py` | A callable streaming callback has no protected dispatch frame; boolean streaming remains supported. |
| `io-read-saved-flows.py` | Standalone Python argv/open/FlowReader program; use Go flowio or `script.run` over an already loaded dump. |
| `io-write-flow-file.py` | Direct random/environment/file-handle APIs; use existing save commands/options with explicit paths. |
| `options-configure.py` | Raising Python's typed OptionsError; generic Starlark `fail` is not identical exception behavior. |
| `websocket-inject-message.py` | asyncio periodic task creation; command-call injection alone does not reproduce the complete example. |
| `wsgi-flask-app.py` | Python Flask/WSGI process/runtime; a separate Go apphost is a different integration. |
