# Go port of mitmproxy: application-layer package facts

Measured 2026-10-05 02:28 JST (`date`). Toolchain go1.27.1 darwin/arm64.
- **tag (date)**: `go list -m -json <mod>@latest` (module-proxy time). `@latest` skips pre-releases unless none exists.
- **license / last commit / iss/PR**: GitHub GraphQL via `gh api graphql` (default-branch commit date; open issues / open PRs). Used instead of the github MCP to batch ~95 repos. NOASSERTION = GitHub could not classify; I read the LICENSE head and name it.
- **go**: `go` directive in go.mod at that tag. Upstream facts come from the lead's checkouts (mitmproxy HEAD 3368a0a, 2026-10-03; mitmproxy_rs HEAD 51fe2b7, 2026-10-01).

## a. Terminal UI
| module | tag (date) | license | last commit | iss/PR | go | notes |
|---|---|---|---|---|---|---|
| charm.land/bubbletea/v2 | v2.0.10 (2026-09-24) | MIT | 2026-10-02 | 114/126 | 1.26.0 | v2 stable. Declarative View, cell renderer, `MouseMode` + `msg.Mouse()`, grapheme-width negotiation (mode 2027, tea.go). |
| charm.land/bubbles/v2 | v2.2.1 (2026-08-24) | MIT | 2026-10-01 | 135/114 | 1.25.0 | list, table, viewport, textinput, textarea, filepicker, tree. Table renders only rows within ±viewport height of cursor (table.go comment). |
| charm.land/lipgloss/v2 | v2.0.6 (2026-08-11) | MIT | 2026-09-11 | 68/83 | 1.25.0 | Styles/layout. |
| github.com/rivo/tview | v0.42.0 (2025-08-27) | MIT | 2026-08-11 | 46/52 | 1.18 | Retained-mode widgets (Table, TextArea, List, Form, TreeView). `TableContent` interface (GetCell/GetRowCount) allows a virtual table. `Application.EnableMouse`. go.mod (HEAD and tag v0.42.0) pins tcell/v2 v2.8.1, uniseg v0.4.7. |
| github.com/gdamore/tcell/v3 | v3.5.0 (2026-09-11) | Apache-2.0 | 2026-10-04 | 6/5 | 1.25.0 | Pure Go. README: wide chars, grapheme clusters. v2 line: v2.13.10 (2026-05-06), go 1.24.0. |
| github.com/gizak/termui/v3 | v3.1.0 (2019-07-15) | MIT | 2025-07-10 | 79/27 | none | Dashboard widgets on termbox-go; keyboard/mouse/resize events. README: irregular update cadence, seeks maintainers. |
| github.com/jroimartin/gocui | v0.5.0 (2021-08-14) | BSD-3-Clause | 2025-05-01 | 44/17 | 1.16 | Views + keybindings, mouse. |
| github.com/awesome-gocui/gocui | v1.1.0 (2022-01-13) | BSD-3-Clause | 2026-08-25 | 20/8 | 1.13 | gocui fork; README: "better wide character support", mouse. |
| github.com/rivo/uniseg | v0.4.7 (2024-02-08) | MIT | 2024-04-13 | 5/6 | 1.18 | Grapheme-cluster width (tview dep). |
| github.com/mattn/go-runewidth | v0.0.30 (2026-09-10) | MIT | 2026-09-24 | 0/1 | 1.23 | Per-rune width. |

Old paths: `github.com/charmbracelet/bubbletea` stops at v1.3.10 (2025-09-17); bubbles v1.0.0 (2026-02-09); lipgloss v1.1.0 (2025-03-12). v2 modules declare `charm.land/...` in go.mod, including the v2.0.10 `.mod` in the module cache. The proxy also lists `github.com/charmbracelet/bubbletea/v2@v2.0.10`, but `go get` of that path fails (tested): "module declares its path as: charm.land/bubbletea/v2 but was required as: github.com/charmbracelet/bubbletea/v2". Use the charm.land paths only.
Unverified: large-list behaviour of bubbles `list`, termui, gocui; Unicode width in termui.
Worker note: only bubbles v2 and tview have a verified virtualised table; tview is retained-mode, bubbletea is Elm-style.

## b. CLI / flags
| module | tag (date) | license | last commit | iss/PR | go | notes |
|---|---|---|---|---|---|---|
| github.com/spf13/cobra | v1.10.2 (2025-12-03) | Apache-2.0 | 2026-07-11 | 257/205 | 1.15 | `GenBash/Zsh/Fish/PowerShell` completion generators (go doc confirms Zsh, Fish). No config-file merge. |
| github.com/spf13/pflag | v1.0.10 (2025-09-02) | BSD-3-Clause | 2026-09-21 | 57/85 | 1.12 | `StringToString[P]`: repeated `--set k=v` into `map[string]string`. |
| github.com/urfave/cli/v3 | v3.14.0 (2026-10-02) | MIT | 2026-10-02 | 16/17 | 1.22 | `StringMapFlag`; `ValueSource` chain (EnvVar, File, map); built-in completion (`GenerateShellCompletionFlag`). File sourcing helpers in separate `urfave/cli-altsrc` (pushed 2026-01-19, not archived). |
| github.com/alecthomas/kong | v1.16.1 (2026-08-09) | MIT | 2026-08-28 | 32/24 | 1.20 | `kong.Configuration(loader, paths...)` + `Resolver`; JSON loader built in. No completion; third party `jotaen/kong-completion` (pushed 2026-04-30, 41 stars). |
| github.com/alecthomas/kong-yaml | v0.2.0 (2023-03-16) | MIT | 2024-04-09 | 3/3 | 1.18 | YAML loader for kong. |
| github.com/spf13/viper | v1.21.0 (2025-09-08) | MIT | 2025-10-15 | 8/135 | 1.23.0 | Flag/env/file merge. |
| std `flag` | go1.27.1 | BSD-3-Clause | n/a | n/a | n/a | `flag.Func` exists (go doc). No subcommands or completion. |

Unverified: kong repeated-map flag syntax; cobra's default `completion` subcommand wiring (only the Gen* methods were checked).

## c. YAML and JSON
| module | tag (date) | license | last commit | iss/PR | go | notes |
|---|---|---|---|---|---|---|
| github.com/goccy/go-yaml | v1.19.2 (2026-01-08) | MIT | 2026-04-07 | 151/85 | 1.21.0 | Active; large open-issue count. |
| gopkg.in/yaml.v3 | v3.0.1 (2022-05-27) | MIT + Apache (two licenses, per its LICENSE) | 2025-04-01 | 298/124 | none | Repo go-yaml/yaml is **archived** on GitHub; README header "THIS PROJECT IS UNMAINTAINED". |
| go.yaml.in/yaml/v3 | v3.0.5 (2026-07-26) | Apache-2.0 | 2026-09-30 | 74/44 | 1.16 | Repo yaml/go-yaml. README: started as a fork of go-yaml, maintained by the official YAML organization. |
| go.yaml.in/yaml/v4 | v4.0.0-rc.6 (2026-06-17) | Apache-2.0 | 2026-09-30 | 74/44 | 1.18 | RC only; no stable v4 tag. |
| sigs.k8s.io/yaml | v1.6.0 (2025-07-24) | MIT/BSD-3 (NOASSERTION) | 2025-12-14 | 7/1 | 1.22 | YAML→JSON→struct via json tags. |
| github.com/knadh/koanf/v2 | v2.3.7 (2026-09-24) | MIT | 2026-09-24 | 0/6 | 1.23.0 | Layered providers (file, env, flags) with merge. |

**encoding/json/v2 in Go 1.27: generally available.**
- go.dev/doc/go1.27: "New encoding/json/v2 and encoding/json/jsontext packages: Two new packages are now available"; it lists removals made during the GOEXPERIMENT phase (`format` and `unknown` tag options, `DiscardUnknownMembers`, `SkipFunc`; `inline` renamed `embed`). go.dev/doc/go1.26: no mention (fetched, zero matches).
- go1.27.1 `src/internal/buildcfg/exp.go` baseline sets `JSONv2: true`. `api/go1.27.txt` has 45 json/v2 lines; go1.26.txt and go1.25.txt have none.
- A program importing `encoding/json/v2` + `jsontext` builds with no GOEXPERIMENT. With `GOEXPERIMENT=nojsonv2` it fails: "build constraints exclude all Go files in .../encoding/json/v2".
- Source files still carry `//go:build goexperiment.jsonv2`, so the opt-out flag removes the packages. `jsontext.Value.Indent` exists (go doc). Gemini google_search also reports GA with `nojsonv2` as opt-out.

## d. Embedded scripting
| module | tag (date) | license | last commit | iss/PR | go | notes |
|---|---|---|---|---|---|---|
| go.starlark.net | pseudo v0.0.0-20260930… (2026-09-30); **no semver tags** | BSD-3-Clause | 2026-09-30 | 52/30 | 1.25.0 | Python-like dialect. `Thread.SetMaxExecutionSteps` (deterministic cap); threads run in parallel; Go values enter via `starlark.Value`/`Callable`. |
| github.com/yuin/gopher-lua | v1.1.2 (2026-04-01) | MIT | 2026-04-01 | 54/52 | 1.23 | Lua 5.1 (+`goto`). `LState` not goroutine-safe: one per goroutine. Shared bytecode is read-only safe. |
| github.com/dop251/goja | pseudo v0.0.0-20261002… (2026-10-02); **no semver tags** | MIT | 2026-10-02 | 36/11 | 1.25.0 | README: "ECMAScript 5.1(+)", most of ES6 "still work in progress", can run the TypeScript compiler (no native TS). |
| github.com/grafana/sobek | pseudo v0.0.0-20260915… (2026-09-15) | MIT | 2026-09-15 | 29/1 | 1.25.0 | goja fork (k6); same README claims. |
| github.com/tetratelabs/wazero | v1.12.0 (2026-05-28) | Apache-2.0 | 2026-09-28 | 32/13 | 1.25.0 | Zero deps, no CGO. Compiler (default where supported) or Interpreter. WASM sandbox; Go host functions via `HostModuleBuilder`. |
| github.com/extism/go-sdk | v1.7.1 (2025-03-02) | BSD-3-Clause | 2025-05-14 | 3/2 | 1.22.0 | `Manifest` + `HostFunction`. go.mod pins wazero v1.9.0. No commit for ~17 months. |
| github.com/hashicorp/go-plugin | v1.8.0 (2026-04-29) | MPL-2.0 | 2026-09-28 | 53/20 | 1.24 | Subprocess + gRPC; README: cross-language, plugin can call back into host. Isolation = OS process only. |
| std `plugin` | go1.27.1 | BSD-3-Clause | n/a | n/a | n/a | go doc: Linux/FreeBSD/macOS only; cannot be closed; poor race-detector support; deployment constraints. |
| github.com/traefik/yaegi | v0.16.1 (2024-04-03) | Apache-2.0 | 2026-02-09 | 162/25 | 1.21 | README supports Go 1.21 and 1.22; stdlib symbol tables only `go1_21`, `go1_22` (checked in module). `unsafe`/`syscall` not exported by default. |
| github.com/expr-lang/expr | v1.17.8 (2026-02-14) | MIT | 2026-07-07 | 59/37 | 1.18 | Expression language; README: "side-effect-free", "memory-safe", works on Go types. |
| github.com/google/cel-go | v0.32.0 (2026-08-19) | Apache-2.0 | 2026-09-10 | 1/0 | 1.23.0 | README: non-Turing-complete, sandboxed; protobuf/JSON-like types. |

Unverified: relative performance of any engine (no benchmarks run); Starlark's I/O surface; goja's real ES level (README may lag); host-callback ergonomics of goja/Starlark.

## e. Content decoding / views
Upstream scope (python `contentviews`): css, dns, graphql, http3, image, javascript, json, mqtt, multipart, query, raw, socketio, urlencoded, wbxml, xml_html, zip. mitmproxy_rs adds hex_dump, hex_stream, msgpack, protobuf. The image view parses metadata only (png/gif/jpeg/ico via kaitai); JS/CSS beautify are small in-tree tokenizers; socketio 98 lines, wbxml 25 (over vendored `contrib/wbxml`), graphql 72, mqtt 277.

| module | tag (date) | license | last commit | iss/PR | go | notes |
|---|---|---|---|---|---|---|
| github.com/andybalholm/brotli | v1.2.6 (2026-09-30) | MIT | 2026-09-30 | 3/0 | 1.22 | brotli enc/dec. |
| github.com/klauspost/compress | v1.20.1 (2026-09-25) | BSD-3 (head of LICENSE read, remainder not read; NOASSERTION) | 2026-10-04 | 0/5 | 1.25 | zstd, gzip/flate/zlib, s2. std has no `compress/zstd` (go doc). |
| github.com/vmihailenco/msgpack/v5 | v5.4.1 (2023-10-26) | BSD-2-Clause | 2023-10-26 | 40/20 | 1.19 | No commit since the tag; README has no maintenance notice. |
| github.com/shamaton/msgpack/v3 | v3.2.3 (2026-09-13) | MIT | 2026-10-04 | 3/1 | 1.24 | v2 line: v2.4.2 (2026-08-30), go 1.20. |
| google.golang.org/protobuf | v1.36.12 (2026-08-10) | BSD-3-Clause | 2026-09-16 | 0/2 | 1.23 | `encoding/protowire` parses/formats raw wire format, no schema (go doc). |
| github.com/alecthomas/chroma/v2 | v2.27.0 (2026-06-17) | MIT (head of COPYING read; NOASSERTION) | 2026-09-25 | 3/26 | 1.25 | Highlighter. `chroma/v3` only as v3.0.0-alpha.5 (2026-07-08). |
| golang.org/x/net | v0.59.0 (2026-09-08) | BSD-3-Clause | 2026-09-28 | 0/73 | 1.26.0 | `html`, `publicsuffix`, `http2`, `trace`, `websocket`, `nettest`. |
| github.com/beevik/etree | v1.8.1 (2026-09-23) | BSD-2-Clause | 2026-09-23 | 0/1 | 1.23.0 | XML tree/indent. |
| github.com/tdewolff/parse/v2 | v2.8.16 (2026-08-11) | MIT | 2026-10-03 | 2/0 | 1.11 | Lexers (css/js/html/json/xml), not formatters. `tdewolff/minify/v2` v2.24.19 (2026-10-03) minifies. |
| golang.org/x/image | v0.46.0 (2026-09-08) | BSD-3-Clause | 2026-09-08 | 0/12 | 1.26.0 | Dirs: bmp, tiff, webp, vp8, vp8l, ccitt, riff. |
| github.com/gen2brain/avif | v0.6.0 (2026-07-05) | MIT | 2026-08-14 | 1/0 | 1.25.0 | libavif→WASM via wazero; tries shared lib via purego first; tags `nodynamic`, `wasm2go`. |
| github.com/gen2brain/heic | v0.7.2 (2026-09-15) | MIT | 2026-09-15 | 1/2 | 1.25.0 | Decoder, WASM via wazero, CGO-free. |
| github.com/vektah/gqlparser/v2 | v2.5.60 (2026-10-02) | MIT | 2026-10-02 | 31/4 | 1.25 | Parser + `formatter` package. |
| github.com/eclipse/paho.golang | v0.23.0 (2025-09-06) | EPL-2.0 (NOASSERTION) | 2026-09-21 | 22/4 | 1.24.0 | MQTT v5 `packets` package. |
| github.com/eclipse/paho.mqtt.golang | v1.5.1 (2025-09-16) | EPL-2.0 (NOASSERTION) | 2026-09-29 | 23/1 | 1.24.0 | MQTT 3.1.1 `packets` package. |
| github.com/zishang520/socket.io/v3 | v3.0.6 (2026-09-22) | MIT | 2026-09-22 | 0/3 | 1.26.0 | Socket.IO/Engine.IO implementation; parser reuse unverified. `googollee/go-socket.io` is archived (v1.7.0, 2023-02-08). |

multipart and urlencoded: std `mime/multipart` and `net/url.ParseQuery`; no third-party candidate searched. No maintained Go module found for: WBXML (`magicmonty/wbxml-go` last push 2012-11-23, `gleroi/wbxml` 2018-01-30); JS beautifier (`ditashi/jsbeautifier-go` 2019-12-27); HTML pretty-printer (`yosssi/gohtml`, pseudo-version 2020-10-13). gRPC framing: no module checked; it is the 5-byte length-prefix header from the gRPC spec (not tool-verified).

## f. Flow file formats
- `.mitm` = concatenated tnetstrings, each `flow.get_state()` (io.py `FlowWriter`). Upstream `tnetstring.py` types: `, ; # ^ ! ~ ] }`; `;` is mitmproxy's custom unicode string; dict keys decode as surrogate-escaped ASCII. `FlowReader` also imports HAR (JSON starting `{`, BOM skipped; `io/har.py`). HAR export: `addons/savehar.py`.
- Go tnetstring modules: `edsrzf/tnetstring-go` (pushed 2013-10-02, 7 stars), `jessta/tnetstr` (2012-01-02), `ichiban/tnetstrings` (2018-04-22). None maintained. In `ichiban/decode.go` I found `case '^'` but no `;`, so it likely lacks mitmproxy's extension (single-file grep).

| module | tag (date) | license | last commit | iss/PR | go | notes |
|---|---|---|---|---|---|---|
| github.com/chromedp/cdproto | v0.157.6 (2026-10-04) | MIT | 2026-10-04 | 0/0 | 1.27 | `cdproto/har`: HAR, Log, Entry, Request, Response, Cache, Timings, Page, PostData… (go doc). Whole DevTools-protocol module. |
| github.com/mrichman/hargo/v2 | v2.0.1 (2026-09-17) | MIT | 2026-09-17 | 0/0 | 1.27.1 | v1 was v1.0.1 (2021-09-08). Struct set unverified. |
| github.com/google/martian/v3 | v3.3.3 (2022-08-16) | Apache-2.0 | 2022-08-16 | 32/12 | 1.18 | **Archived.** Has a `har` package (not inspected). |

Hand-written alternative: HAR 1.2 is about 15 object types; with `encoding/json/v2` (GA in Go 1.27) it needs no dependency.

## g. Filter parsing
Upstream `flowfilter.py`: pyparsing; 32 `code =` filter classes; `!` unary (right-assoc), `&`, `|`, parentheses; regex args compiled with Python `re` plus `re.IGNORECASE`.

| module | tag (date) | license | last commit | iss/PR | go | notes |
|---|---|---|---|---|---|---|
| github.com/alecthomas/participle/v2 | v2.1.4 (2025-03-24) | MIT | 2026-10-02 | 26/17 | 1.18 | Struct-tag grammars. Commits continue without a tag since 2025-03-24. |
| github.com/antlr4-go/antlr/v4 | v4.13.1 (2024-05-15) | BSD-3-Clause | 2024-05-15 | 0/0 | 1.22 | README: read-only runtime copy. Generation needs the ANTLR Java tool. |
| golang.org/x/tools/cmd/goyacc | x/tools v0.51.0 (2026-10-02) | BSD-3-Clause | 2026-10-02 | 0/117 | 1.26.0 | `go list` resolves the package. |
| github.com/dlclark/regexp2 | v1.12.0 (2026-04-18) | MIT | 2026-10-02 | 3/1 | 1.13 | Backtracking, Perl5/.NET-compatible; README: no constant-time guarantee, `MatchTimeout`, `regexp2cg` codegen 3-10x. Not identical to Python `re`. |

Go `regexp` is RE2: no backreferences or lookaround. User `~u` patterns are arbitrary Python `re` syntax, so some will not compile under RE2 (no corpus measured).

## h. Process info
| module | tag (date) | license | last commit | iss/PR | go | notes |
|---|---|---|---|---|---|---|
| github.com/shirou/gopsutil/v4 | v4.26.9 (2026-09-27) | BSD (NOASSERTION) | 2026-09-27 | 167/45 | 1.26.0 | Connections: Linux via /proc inode map (net_linux.go); macOS/FreeBSD via net_unix.go `ConnectionsPidWithContext`, which execs `lsof` (`CallLsofWithContext`). macOS libproc via purego (common_darwin.go). |
| github.com/prometheus/procfs | v0.22.0 (2026-08-28) | Apache-2.0 | 2026-09-26 | 24/27 | 1.25.0 | Linux only: net_tcp/udp/unix, proc_fdinfo. |
| github.com/cakturk/go-netstat | pseudo (2020-02-20) | MIT | 2020-02-20 | 4/6 | 1.13 | Stale. |
| github.com/elastic/go-sysinfo | v1.15.5 (2026-06-22) | Apache-2.0 | 2026-06-30 | 14/4 | 1.23.0 | Process/host info; socket→PID unverified. |
| github.com/ebitengine/purego | v0.11.1 (2026-09-18) | Apache-2.0 | 2026-10-02 | 20/13 | 1.25.0 | `purego/objc`: pure-Go Objective-C runtime (go doc). |
| github.com/progrium/darwinkit | v0.5.0 (2024-06-21) | MIT | 2024-07-15 | 31/10 | 1.18 | AppKit bindings; cgo status unverified. |
| github.com/jackmordaunt/icns/v4 | v4.2.0 (2026-09-20) | MIT | 2026-09-23 | 0/4 | 1.27.0 | README: image→.icns; decoding unverified. |
| github.com/adrg/xdg | v0.5.3 (2024-10-31) | MIT | 2026-09-15 | 3/4 | 1.19 | **Not a desktop-entry/icon library**: XDG base dirs only. |

Upstream (mitmproxy_rs `src/processes`): listing uses the `sysinfo` crate on Linux/macOS (+macOS visible windows) and EnumWindows/IsWindowVisible/QueryFullProcessImageName on Windows. Icons: macOS `NSRunningApplication.runningApplicationWithProcessIdentifier(pid).icon().TIFFRepresentation()` → PNG 32×32; Windows `ExtractAssociatedIconW` + GetIconInfo/GetDIBits → PNG; **Linux: no icons** (docstring "Windows, macOS"). A GitHub search for Go desktop-entry parsers returned no hits (existence unverified).

## i. Logging / observability
| module | tag (date) | license | last commit | iss/PR | go | notes |
|---|---|---|---|---|---|---|
| `log/slog`, `runtime/metrics`, `net/http/pprof` | go1.27.1 | BSD-3-Clause | n/a | n/a | n/a | std. `runtime/metrics`: "stable interface". |
| go.opentelemetry.io/otel | v1.47.0 (2026-10-02) | Apache-2.0 | 2026-10-03 | 96/67 | 1.26.0 | |
| …/contrib/instrumentation/net/http/otelhttp | v0.72.0 (2026-10-02) | Apache-2.0 | 2026-10-03 | 142/97 | 1.26.0 | Module version still 0.x. |
| github.com/prometheus/client_golang | v1.24.1 (2026-07-24) | Apache-2.0 | 2026-10-03 | 89/56 | 1.25.0 | |
| golang.org/x/net/trace | in x/net v0.59.0 | BSD-3-Clause | 2026-09-28 | n/a | 1.26.0 | Serves /debug/requests, /debug/events. No deprecation notice in go doc. |

## j. Web UI backend
| module | tag (date) | license | last commit | iss/PR | go | notes |
|---|---|---|---|---|---|---|
| std `net/http` ServeMux | go1.27.1 | BSD-3-Clause | n/a | n/a | n/a | Pattern routing (go doc "Patterns"); `embed` + `http.FileServerFS`. |
| github.com/go-chi/chi/v5 | v5.3.2 (2026-08-20) | MIT | 2026-09-29 | 50/66 | 1.23 | |
| github.com/labstack/echo/v5 | v5.4.0 (2026-09-27) | MIT | 2026-10-01 | 9/51 | 1.25.0 | v4 line: v4.16.0 (2026-09-27), go 1.25.0. |
| github.com/coder/websocket | v1.8.15 (2026-06-15) | ISC | 2026-06-15 | 54/18 | 1.23 | `x/net/websocket` godoc recommends it and gorilla. |
| github.com/gorilla/websocket | v1.5.3 (2024-06-14) | BSD-2-Clause | 2025-03-19 | 47/36 | 1.12 | |
| github.com/tmaxmax/go-sse | v0.11.0 (2025-05-13) | MIT | 2025-05-13 | 10/0 | 1.22 | SSE client/server. |

mitmweb API (python `tools/web/app.py`): WebSocket `/updates`; REST `/flows`, `/flows/dump|resume|kill`, `/flows/{id}`, `/flows/{id}/{resume|kill|duplicate|replay|revert}`, `/flows/{id}/{request|response|messages}/content.data` and `/content/{view}`, `/commands`, `/commands/{cmd}`, `/events`, `/options`, `/options/save`, `/state`, `/clear`, `/filter-help`, `/processes`, `/executable-icon`.
Reusable assets: the built bundle is **git-tracked** at `mitmproxy/tools/web/static` (10 files, 2.5 MB: `index-*.js` 174 KB, `vendor-*.js` 899 KB, two CSS, fontawesome woff2/woff/ttf/svg/eot, favicon.ico 365 KB) and ships in PyPI wheel `mitmproxy-12.2.3` (uploaded 2026-05-12, 1.65 MB; same 10 files + `templates/login.html`). Source is `web/` (Vite, React 19, Redux Toolkit); release build: `rm -rf ../mitmproxy/tools/web/static && vite build`. `web/package.json` is `"private": true`: no npm package. License MIT (Aldo Cortesi). File names are content-hashed, so `index.html` must come from the same revision.

## k. Testing
| module | tag (date) | license | last commit | iss/PR | go | notes |
|---|---|---|---|---|---|---|
| github.com/google/go-cmp | v0.7.0 (2025-01-14) | BSD-3-Clause | 2026-06-18 | 45/23 | 1.21 | Required by project rules. |
| golang.org/x/net/nettest | in x/net v0.59.0 | BSD-3-Clause | 2026-09-28 | n/a | 1.26.0 | "Utilities for network testing" (go doc). |
| github.com/stretchr/testify | v1.12.1 (2026-08-17) | MIT | 2026-09-24 | 231/161 | 1.17 | Forbidden by project rules. |
| go.uber.org/goleak | v1.3.0 (2023-10-24) | MIT | 2026-09-15 | 12/13 | 1.20 | Commits continue after last tag. |
| github.com/testcontainers/testcontainers-go | v0.44.0 (2026-08-07) | MIT | 2026-10-01 | 122/77 | 1.25.0 | Container-based e2e. |
| gopkg.in/dnaeon/go-vcr.v4 | v4.0.7 (2026-06-25) | BSD-2-Clause | 2026-09-21 | 5/2 | 1.24 | Record/replay of client-side HTTP. |
| github.com/quic-go/quic-go | v0.63.0 (2026-09-22) | MIT | 2026-10-04 | 165/52 | 1.26.0 | No public test-helper package seen: `internal/mocks` is internal; `integrationtests/tools/proxy` (UDP proxy) is a normal path, stability unverified; `qlog` packages. |
| golang.zx2c4.com/wireguard | pseudo (2026-05-22) | MIT | 2026-05-22 | 0/31 | 1.23.1 | `tun/netstack`: `CreateNetTUN` returns userspace `*Net` (dial/listen/ping); examples `http_client.go`, `http_server.go`, `ping_client.go`. Usable as in-process WireGuard client. mitmproxy_rs has its own `wireguard-test-client` (Rust). |
| gvisor.dev/gvisor | pseudo (2026-10-04) | Apache-2.0 | 2026-10-04 | 481/385 | 1.26.3 | Netstack source (what wireguard's netstack uses); heavy. |

## l. Misc
| module | tag (date) | license | last commit | iss/PR | go | notes |
|---|---|---|---|---|---|---|
| github.com/hashicorp/golang-lru/v2 | v2.0.7 (2023-09-21) | MPL-2.0 | 2026-09-03 | 35/21 | 1.18 | |
| github.com/maypok86/otter/v2 | v2.3.0 (2025-12-22) | Apache-2.0 | 2025-12-23 | 7/11 | 1.24.0 | v1 line: v1.2.4 (2024-11-22). |
| github.com/jellydator/ttlcache/v3 | v3.4.1 (2026-06-22) | MIT | 2026-09-14 | 13/6 | 1.23.0 | TTL cache. |
| golang.org/x/net/publicsuffix | in x/net v0.59.0 | BSD-3-Clause | 2026-09-28 | n/a | 1.26.0 | Snapshot of publicsuffix.org data. |
| std `net/http` cookies | go1.27.1 | BSD-3-Clause | n/a | n/a | n/a | `ParseCookie`, `ParseSetCookie` exist (go doc). Leniency vs mitmproxy unverified. |
| github.com/go-ldap/ldap/v3 | v3.4.14 (2026-07-16) | MIT (NOASSERTION) | 2026-09-28 | 53/7 | 1.25.0 | |
| golang.org/x/crypto | v0.57.0 (2026-09-08) | BSD-3-Clause | 2026-10-04 | 0/101 | 1.26.0 | `bcrypt`. |
| github.com/tg123/go-htpasswd | v1.2.5 (2026-06-03) | MIT | 2026-06-03 | 1/1 | 1.24.0 | README: SSHA, MD5Crypt, APR1Crypt, SHA, Bcrypt (+SHA-256/512 crypt). |
| github.com/GehirnInc/crypt | pseudo (2023-03-20) | BSD-2-Clause | 2023-03-20 | 4/1 | 1.19 | Packages `apr1_crypt`, `md5_crypt`, `sha256_crypt`, `sha512_crypt`. |
| github.com/icholy/digest | v1.2.0 (2026-07-28) | MIT | 2026-07-28 | 0/0 | 1.22 | Digest auth; client/server scope unverified. |
| github.com/abbot/go-http-auth | v0.4.0 (2017-06-29) | Apache-2.0 | 2023-03-10 | 11/6 | none | Stale. |
| golang.design/x/clipboard | v0.11.0 (2026-09-26) | MIT | 2026-09-26 | 0/0 | 1.24 | README: no CGO on desktop; Linux needs Wayland data-control or X server. |
| github.com/atotto/clipboard | v0.1.4 (2021-02-24) | BSD-3-Clause | 2026-10-02 | 21/16 | none | Linux needs `xclip` or `xsel`. |
| github.com/fsnotify/fsnotify | v1.10.1 (2026-05-04) | BSD-3-Clause | 2026-05-11 | 30/21 | 1.23 | |
| github.com/pkg/browser | pseudo (2024-01-02) | BSD-2-Clause | 2024-01-02 | 12/8 | 1.14 | No commits since. |
| koanf/v2, spf13/viper | see c, b | MIT | 2026-09-24, 2025-10-15 | | | koanf active; viper last commit 2025-10-15, 135 open PRs. |
| std `errors.Join` | go1.27.1 | BSD-3-Clause | n/a | n/a | n/a | std. |

## Decision matrix
| block | candidates | key differentiator |
|---|---|---|
| a TUI | bubbletea/bubbles/lipgloss v2; tview+tcell; termui; gocui | v2 stable on `charm.land`, windowed table; tview retained widgets + virtual `TableContent`, pinned to tcell v2; termui/gocui low activity |
| b CLI | cobra+pflag; urfave/cli v3; kong; std flag | completion built into cobra and urfave, kong needs third party; repeated `k=v`: pflag `StringToString`, urfave `StringMapFlag` |
| c YAML/JSON | goccy; go.yaml.in/yaml/v3; yaml.v3; sigs.k8s.io | yaml.v3 archived; go.yaml.in/v3 is the YAML-org continuation; v4 only RC; json/v2 GA in 1.27 |
| d scripting | starlark; gopher-lua; goja/sobek; wazero(+extism); go-plugin; yaegi; expr; cel | in-process language vs WASM sandbox vs subprocess; starlark and goja lack semver tags; yaegi stdlib tables stop at Go 1.22 |
| e content | brotli; klauspost; msgpack; protowire; chroma; etree; x/image; gen2brain; gqlparser; paho | WBXML, JS/CSS beautifiers, Socket.IO parsers: no maintained Go module found; AVIF/HEIC via WASM (CGO-free) |
| f formats | 3 stale tnetstring modules; cdproto/har; hargo/v2; hand-written | no maintained tnetstring; HAR types exist in cdproto (heavy module) |
| g filter | participle; antlr; goyacc; hand-written; regexp2 | participle active; regexp2 backtracks and is .NET-flavoured, not Python `re` |
| h process | gopsutil; procfs; go-netstat; go-sysinfo; purego/objc | gopsutil only cross-OS socket→PID (macOS via `lsof`); upstream has no Linux icons |
| i observability | slog; otel+otelhttp; client_golang; pprof; x/net/trace | otelhttp still v0.x |
| j web | net/http; chi; echo v5; coder/websocket; go-sse | built assets are git-tracked upstream and in the wheel; no npm package |
| k testing | go-cmp; nettest; goleak; testcontainers; go-vcr; wireguard netstack | wireguard `tun/netstack` = in-process WG client; quic-go exposes no test helpers |
| l misc | lru/otter/ttlcache; ldap; bcrypt; go-htpasswd; clipboard; fsnotify; koanf | go-htpasswd covers apr1/bcrypt/sha; golang.design/x/clipboard is CGO-free |

## Could not verify
- Performance of any candidate (no benchmarks run), incl. large-list rendering for bubbles `list`, termui, gocui.
- Whether `go.yaml.in/yaml/v3` is API-identical to yaml.v3 in every corner (README says fork).
- `sigs.k8s.io/yaml` interplay with json/v2 tags.
- tnetstring modules' handling of the `;` type (only `ichiban` partly inspected).
- hargo/v2 and martian `har` struct completeness for HAR 1.2.
- Socket.IO/Engine.IO parser reuse from `zishang520/socket.io`.
- Linux desktop-entry/icon libraries (search returned none); Windows `SHGetFileInfo`/`ExtractAssociatedIcon` access from Go.
- darwinkit cgo status; icns decoding; icholy/digest server side.
- cobra default `completion` subcommand; kong repeated-map flag syntax.
- `net/http` cookie leniency versus mitmproxy's parser.
- Whether real-world `~u` regexes compile under RE2.
