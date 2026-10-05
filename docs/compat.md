# Behavioural differences from mitmproxy

This page lists every place where the Go port behaves differently from upstream mitmproxy (commit `3368a0a`, see the
README) on purpose. It is written for a reader who knows mitmproxy. Each table names the upstream behaviour with the
file it lives in, the Go behaviour, and the reason. Paths without a prefix are relative to the upstream repository root
(`mitmproxy/...`).

The tables cover the code that exists today. The last section lists differences that are already decided for code that
is not written yet. Where a package reproduces an upstream oddity on purpose, it is listed under "Reproduced on purpose"
so that it is not mistaken for a port bug.

Anything not listed here is meant to behave as upstream does; a difference that is not on this page is a bug.

## internal/htpasswd

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| The UTF-8 password file has no size bound (`mitmproxy/utils/htpasswd.py`). | Files larger than 8 MiB are refused. | Bound memory used when loading configuration. |
| A malformed bcrypt hash can raise from `check_password` (`mitmproxy/utils/htpasswd.py:81`); the authentication addon catches it. | `File.Check` returns false for malformed hashes. | The boolean checking API fails closed without requiring its caller to catch a parser error. |

## certs

| Upstream | Go | Reason |
|---|---|---|
| `Cert.cn` and `Cert.organization` return `None` when absent (`mitmproxy/certs.py`). | `CN()` and `Organization()` return an empty string. The certificate's `String()` still distinguishes an absent CN (`None`) from an explicitly empty one (`''`). | The Go accessors return strings. |
| SAN values include cryptography's specialised objects for every GeneralName type (`mitmproxy/certs.py`). | DNS, IP, URI and email names have typed constructors. Other types retain their complete DER as an opaque comparable value and render as hex, rather than Python object text. | Opaque names can be retained without recreating cryptography's object model. |
| Certificate generation starts from naive local `datetime.now()`, which cryptography treats as UTC (`mitmproxy/certs.py`). | Generation uses the current UTC instant, backdated by two days. | Validity must not move with the host's configured time zone. |
| `dummy_cert` accepts `None` separately from empty CN and organization strings (`mitmproxy/certs.py`). | Empty string arguments mean absent CN or organization. | The Go API uses strings rather than optional string pointers. |
| Private-key loading delegates to cryptography/OpenSSL with no input-size or key-derivation work bound (`mitmproxy/certs.py`). | PEM input is capped at 8 MiB. Encrypted PKCS#8 supports PBES2 with PBKDF2-HMAC-SHA1/224/256/384/512 and AES-CBC or triple-DES-CBC, at most 1,000,000 iterations and a 1024-byte salt. Legacy encrypted PEM is also accepted; other encryption schemes are rejected. Unencrypted keys must be accepted by `crypto/x509` and implement `crypto.Signer`. | Bound configuration loading work and use standard-library key parsers and cryptographic primitives. |
| `dummy_crl` adds only a CRL Number extension (`mitmproxy/certs.py`). | The CRL also carries an Authority Key Identifier matching the CA's SKI, or a SHA-1 key identifier when that is absent. | `crypto/x509.CreateRevocationList` requires and emits the identifier. |
| Both passwordless `.p12` files are written by `cryptography`'s `serialize_key_and_certificates(…, NoEncryption())`: an HMAC-SHA-256 MAC keyed from the empty password with 2048 iterations, and `friendlyName` `mitmproxy` on every bag (`mitmproxy/certs.py`). | Both bundles are encoded with go-pkcs12's `Passwordless` encoder: no MAC, the key file's bags carry `localKeyID` but no `friendlyName`, and the cert-only bag carries the Java trust-store attribute `2.16.840.1.113894.746875.1.1`. Python's `pkcs12.load_pkcs12` reads both bundles and recovers the same certificate and complete private key. | go-pkcs12 is the maintained Go encoder, and its `Encoder` fields are unexported, so no configuration reproduces `cryptography`'s exact structure; what matters is that Python reads the bundles. |

## connection

No behavioural differences.

## flow

| Upstream | Go | Reason |
|---|---|---|
| `Flow.kill()` clears `intercepted` but does not set the resume event, so a task in `wait_for_resume()` on a killed intercepted flow stays blocked until its connection is torn down (`mitmproxy/flow.py`). | `Kill` also releases every `WaitForResume` caller. | A blocked goroutine would leak; there is no event loop that tears it down with the connection. |
| `Flow.set_state` stores `backup` as given, whatever its type (`mitmproxy/flow.py`). | `backup` must be a dictionary or null; anything else fails the load. | Flow state is decoded into typed Go fields, and a backup is used as a flow state later. |
| Python's `==` on decoded state treats a bool as an integer: `True == 1` and `False == 0.0` are True. | `state.Equal` compares state values as Python's `==` does, except that a bool equals only a bool: `Equal(true, int64(1))` is false. | A flow file writes a bool (`!`) and an integer (`#`) as different tnetstring types, so two states that differ only there do not write the same file. |
| Message content of TCP, UDP and WebSocket messages is stored as given by `from_state` (`mitmproxy/tcp.py`, `mitmproxy/udp.py`, `mitmproxy/websocket.py`). A WebSocket flow that mitmproxy migrated from a format older than 18 can hold text instead of bytes there, and keeps it when saved again; `~b` then raises `TypeError`. | Content must be bytes; a flow with text content fails to load. | Content is a `[]byte`. Rejecting the flow on load is clearer than failing later inside a filter. |

## httpmsg

| Upstream | Go | Reason |
|---|---|---|
| `validate_headers` checks header names and Content-Length with `re` patterns ending in `$`, which also matches before a final newline, so a name `"Foo\n"` or a value `"42\n"` is accepted (`mitmproxy/net/http/validate.py`). | The patterns are anchored at the absolute end; a trailing newline is rejected. | These checks guard against request smuggling; the stricter reading is the safe one. |
| `Request.constrain_encoding()` joins the kept codings in the iteration order of a Python set, which is not defined (`mitmproxy/http.py`). | The kept codings always appear in the order gzip, identity, deflate, br, zstd. | Deterministic output. |
| Body text is decoded and encoded with Python's codec registry (`mitmproxy/http.py`, `mitmproxy/net/encoding.py`). | Character sets are resolved through the IANA and WHATWG indexes of `golang.org/x/text`, plus Python's own spellings (`cp1252`, `iso8859_7`, `euc_kr`, `cp932`, ...). Most labels resolve to the same encoding, but the two sets differ: `utf-7`, `mac_roman`, `hz`, `johab`, `big5hkscs`, `iso2022_kr` and `cp1006` are not supported, and WHATWG-only labels such as `x-user-defined`, `unicode-1-1-utf-8`, `x-mac-cyrillic` and `x-gbk` are accepted. An unsupported label behaves like an unknown one in upstream: `Text` fails and `SetText` falls back to UTF-8. | Go has no codec registry; `x/text` is the maintained set of encodings. |
| Undecodable body bytes returned by `get_text(strict=False)` are surrogate escapes (U+DC80 to U+DCFF) in a `str` (`mitmproxy/http.py`). | `TextOrRaw` returns those bytes unchanged inside the Go string, which is then not valid UTF-8. `SetText` with such text writes the same bytes upstream's `surrogateescape` fallback writes. | A Go string cannot hold lone surrogates; raw bytes play their role. |
| A non-ASCII host is converted with Python's `idna` codec, which implements IDNA 2003 with nameprep tables fixed at Unicode 3.2 (`mitmproxy/net/http/url.py`). | Conversion uses UTS #46 transitional processing from `golang.org/x/net/idna`, which maps characters as nameprep does (`ß` becomes `ss`) but follows current Unicode tables, so rare characters can map differently. | Go has no IDNA 2003 implementation; UTS #46 transitional processing is the closest one. |

## tcp, udp

| Upstream | Go | Reason |
|---|---|---|
| `TCPMessage` and `UDPMessage` print the content as a Python bytes literal: `-> b'hello\n'` (`mitmproxy/tcp.py`, `mitmproxy/udp.py`). | `String` prints a Go-quoted string: `-> "hello\n"`. | Go syntax in Go output. The flow summaries (`<TCPFlow (3 messages)>`) are unchanged. |

## websocket

No differences beyond the message content rule listed under [flow](#flow).

## dns

No behavioural differences.

## flowio and flowio/tnetstring

| Upstream | Go | Reason |
|---|---|---|
| `FlowReader` migrates every flow format from `(0, 11)` up to the current version 21 (`mitmproxy/io/compat.py`). | Formats 18 to 20 are migrated; older ones are rejected with upstream's message for an unknown version: `mitmproxy-go 0.1.0-dev cannot read files with flow format version 17.` | Scope decision for the port; porting the older migrations is a listed follow-up in the work plan. |
| A file starting with `{` (after an optional UTF-8 byte order mark) is read as HAR (`mitmproxy/io/io.py`). | Such a file returns `ErrHARNotSupportedYet`. The byte order mark is skipped only before `{`, as upstream does. | HAR import is not written yet. |
| Every tnetstring decoding error is reported as `Invalid data format.`; an empty file ends the stream silently (`mitmproxy/io/io.py`). | The codec's own message is returned, for example `not a tnetstring: truncated value`; an empty file ends the stream with `io.EOF`. | A precise message helps locate a corrupt file. |
| Error texts name `mitmproxy <version>` (`mitmproxy/version.py`). | They name `mitmproxy-go <version>` (package `internal/version`). The hint `please update mitmproxy` is kept as upstream writes it. | The reader is a different program. |
| The reader and writer are `FlowReader` and `FlowWriter` (`mitmproxy/io/io.py`). | They are `flowio.Reader` and `flowio.Writer`. | Go naming: the package name already says "flow". |
| `tnetstring.loads` ignores bytes after the first value (`mitmproxy/io/tnetstring.py`). | `Loads` rejects trailing bytes. `Load`, which reads a stream, is unchanged. | A value with trailing data is malformed. |
| Integers, floats and nested length prefixes are parsed with Python's `int()` and `float()`, which accept surrounding whitespace and `_` digit separators; dictionary keys may be any hashable value (`mitmproxy/io/tnetstring.py`). | Whitespace and `_` are rejected; dictionary keys must be text or byte strings. | mitmproxy never writes these forms; rejecting them keeps the parser simple and strict. |
| A dictionary key is a `str` or `bytes` object and is written with the tag of its type, so a dictionary may hold the text key `"k"` and the bytes key `b"k"` side by side (`_rdumpq` in `mitmproxy/io/tnetstring.py`). | Each key keeps the kind it was read or set with and is written with the same tag (`,` or `;`); a byte-string key need not be UTF-8. A dictionary holding both `"k"` and `b"k"` is rejected when read, with `dictionary has both a byte-string and a text key "k"`. In code, `omap.Map.Set` never changes the kind of an existing key and `SetBytesKey` makes it a byte string, so `Set("k", v)` on a map holding `b"k"` replaces the value of `b"k"`, where Python's `d["k"] = v` adds a second, text key. | Go state dictionaries are keyed by the key's bytes, so the two keys would collapse into one and lose a value; rejecting keeps a read and the following write in agreement. mitmproxy never writes such a pair unless an addon stores one. |
| Nesting and integer size are limited only by Python's recursion limit and its 4300-digit `int` conversion limit. | Nesting is limited to 1000 levels and integer literals to 4300 digits, both as explicit errors. | The same limits, made explicit so hostile input cannot exhaust the goroutine stack. |
| A flow's fields hold Python integers of any size, and `set_state` coerces a float field to `int()` (`mitmproxy/flow.py`, `mitmproxy/connection.py`). | An integer beyond the int64 range is kept as a `*big.Int` in free-form state such as `metadata` and written back unchanged. A typed field (a port, a timestamp, a status code, ...) refuses it, and refuses a float whose integer part is beyond that range, with `integer N does not fit in 64 bits`. | The models hold integers as `int64`; no real port, timestamp or size exceeds it. |

## filter and filter/regex

| Upstream | Go | Reason |
|---|---|---|
| An operator that reads the request of an HTTP flow whose request is `None`, such as `~m`, `~d`, `~h` or `~t`, raises `AttributeError` (`mitmproxy/flowfilter.py`). | The operator returns false. | A filter must not crash the caller. Such flows only exist when built by hand; flow files always have a request. |
| A filter object always has a compiled pattern. | A `*filter.Rex` built by hand instead of by `Parse` has no compiled pattern; `Match` returns false for it. | Go allows the zero value of an exported struct; it must not panic. |
| Patterns run on Python's `re`, which has no time limit (`mitmproxy/flowfilter.py`). | Patterns run on Go's `regexp` (RE2) where it can express them, otherwise on `github.com/dlclark/regexp2`. A `regexp2` match that takes longer than 100 ms counts as no match and is logged as a warning. | RE2 cannot backtrack; the time limit bounds the backtracking fallback on hostile input. |
| Byte patterns (`~b`, `~h`, `~m`, ...) see the input as Latin-1 bytes and fold case for ASCII only, and so do the parts of a `str` pattern under `(?a)`: `(?ai)k` does not match the Kelvin sign. | Both Go engines read the input as UTF-8 and fold case for all of Unicode. | Neither Go engine has a Latin-1 byte mode or ASCII-only case folding. |
| In a `bytes` pattern (`~b`, `~h`, `~m`, ...) the inline flag `(?L)` makes `\d`, `\w`, `\s`, `\b` and case folding follow the C library's current locale (Python `re.LOCALE`). | `(?L)` is accepted in a `bytes` pattern and changes nothing: the classes stay ASCII. | Go has no C locale. Under the C and UTF-8 locales Python's classes are ASCII as well; an 8-bit locale such as ISO 8859-1 adds letters from 0x80 up. |
| With a global `(?a)`, `re.search` can miss a match inside a scoped `(?u:...)` group: `(?a)(?u:\d)` does not find U+0663, although `re.match` does. | The scoped `(?u:...)` makes the classes inside it Unicode, as `re.match` has it. | CPython computes where a search can start with the global flags only; reproducing that would mean reproducing its search optimisation. |
| `\d`, `\w` and `\s` in a `str` pattern follow the Unicode database of the Python that runs mitmproxy (15.1 for Python 3.13). | They follow Go's `unicode` package (17.0 for Go 1.27). | Go has no copy of Python's database. The two agree on every code point Unicode 15.1 assigns; only code points assigned later differ. |
| A character class matches each of its members, with or without `re.IGNORECASE`, wherever a match starts (Python `re`). | On `regexp2`, a class range holding an uppercase letter whose lowercase `regexp2`'s case table lacks (several hundred code points, among them the Cherokee, Georgian Mtavruli, Glagolitic and Deseret capitals and the Kelvin, Ohm and Angstrom signs) does not match that letter when the range folds case, and does not let a match start at it when the range is case-sensitive but the pattern can also start with a case-insensitive part: `(?i)(?=)[\u13a0-\u13a1]` does not find U+13A0, and `(?i)x(?=)\|(?-i:[\u212a-\u212b])` does not find the Kelvin sign. Single characters and patterns on RE2 are not affected. | `regexp2` lowercases a range with a case table older than the Unicode version of Go's `unicode` package. The classes the translation writes for `\d`, `\w` and `\s` never fold and avoid the start-character lookup where it would miss; doing the same for every written class would mean rewriting each range for `regexp2`. |
| A `str` pattern may name a character with `\N{...}`, such as `\N{DIGIT ZERO}` (Python `re`). | `\N{...}` is a compile error. | Go's standard library has no table from character names to code points, and Python's lookup also accepts name aliases. |
| Python 3.13 rejects `\z` in a pattern (`bad escape \z`); Python 3.14 reads it as `\Z`, the end of the input. | `\z` is the end of the input. | Upstream runs on Python 3.12 to 3.14; accepting the 3.14 spelling keeps a filter written for it working. |
| `MITMPROXY_CASE_SENSITIVE_FILTERS` is read once, when `flowfilter` is imported (`mitmproxy/flowfilter.py`). | It is read on every `Parse` call. | No import-time state. |
| `parse` raises `ValueError("Empty filter expression")` or `ValueError("Invalid filter expression: '<expr>'")` (`mitmproxy/flowfilter.py`). | `Parse` returns a `*ParseError` reading `empty filter expression` or `invalid filter expression "<expr>": <reason> at offset <n>`. | The error says where parsing failed. |

Reproduced on purpose (compatibility, not differences):

- Python's `$` (end of input or before a final newline) in filter patterns, by rewriting a `$` at the end of a pattern
  for RE2 and sending other patterns to `regexp2`.
- Python's `\d`, `\w`, `\s` and `\b` on either engine: Unicode categories in the `str` patterns of `~u`, `~d`, `~src`,
  `~dst`, `~meta`, `~marker` and `~comment`, ASCII in the `bytes` patterns of the other operators and under `(?a)`,
  never folded for case, and the same inside character classes. The inline flags `a`, `u` and `L` are rejected where
  Python rejects them. `\b` in a `str` pattern and `\B` in any pattern run on `regexp2`, where Python 3.13's `\B`,
  which does not match in an empty input, is reproduced.
- Python's errors for patterns both Go engines would accept: `\p`, `\P` and `\x{...}`, which they read as a property
  class and a code point (`bad escape \p`, `incomplete escape \x`), and a quantifier after a repeat with a comment or
  verbose whitespace between them, as in `a*(?#c)?` or `(?x)a* ?`, which they read as a lazy repeat
  (`multiple repeat`). Likewise `\u` and `\U` in a bytes pattern (`bad escape \u`), a `\u` or `\U` with too few hex
  digits (`incomplete escape \u004`), and a repeat whose minimum exceeds its maximum (`min repeat greater than max
  repeat`).
- Python's repeats without a minimum, `{,n}` and `{,}`, which repeat from 0 where both Go engines read them as text, and
  `\uXXXX` and `\UXXXXXXXX` in `str` patterns, which neither Go engine reads as Python does.
- Python 3.11's possessive repeats (`a*+`, `a++`, `a?+`, `a{m,n}+`), which run on `regexp2` as the atomic groups
  CPython defines them to be (`(?>a*)`), and atomic groups `(?>...)`, which `regexp2` runs as written. A `?` or `+` after
  a lazy or possessive suffix is `multiple repeat`, and a possessive repeat of nothing, of `^` or of `\b` is `nothing to
  repeat`, as in Python.
- Python's named groups, backreferences and conditionals: `(?P<name>...)`, `(?P=name)`, `\N` with one or two digits
  (three octal digits are an octal escape) and `(?(name)yes|no)`, with Python's errors for an unknown, open, missing or
  redefined group and a name that is not an identifier, and `unknown extension` for the group syntax only the Go engines
  know, such as `(?<name>...)` and `(?'name'...)`. A group name is checked with Go's Unicode letter, mark, digit and
  connector categories, where Python uses the XID properties; they differ only on a few characters that NFKC
  normalisation changes.
- Python's `bad escape` for the escapes only a Go engine knows: `\cX`, `\e`, `\G`, `\k<name>` and `\Q`.
- Python's `nothing to repeat` for a quantifier on a position rather than an item, such as `^*`, `a$?`, `\A*` or `\b+`,
  which both Go engines accept.
- pyparsing's grammar as mitmproxy uses it: `a&b` is one bare word, expressions side by side inside parentheses are an
  error, tabs are expanded before parsing, and an operator name must be followed by whitespace, a non-ASCII character
  or the end of the input.
- pyparsing 3.3's `QuotedString` unescaping bug: `\x41` stays the text `x41`, because the numeric-escape regex was
  written in an f-string.
- The 4300-digit limit of Python's `int()` for `~c` arguments.
- `~b`, `~bq` and `~bs` search each WebSocket, TCP and UDP message on its own, as upstream's `FBod` does.

## options

| Upstream | Go | Reason |
|---|---|---|
| `OptManager.update` applies values one by one; a value of the wrong type raises `TypeError` after the values before it were applied (`mitmproxy/optmanager.py`). | Every value is type-checked before any is applied; a type error changes nothing. Unknown names are still reported after the known ones were applied, as upstream does. | An update is all or nothing for type errors. |
| `save` creates a new file with the default mode, normally readable by everyone (`mitmproxy/optmanager.py`). | `Save` creates a new file with mode 0600; an existing file keeps its permissions. | The file can hold `cert_passphrase`. |
| `serialize` adds options that are not yet in the file in the iteration order of a Python set (`opts.keys()`), which is not defined (`mitmproxy/optmanager.py`). | They are added in registration order. Keys already in the file keep their order, as upstream does. | Deterministic output. |
| A type error reads `Expected <class 'bool'> for name, but got <class 'int'>.` (`mitmproxy/utils/typecheck.py`). | It reads `Expected bool for name, but got int.`, with the option type names of `--options` and Go type names. | Python class reprs have no Go counterpart. |
| Integer option strings accept Unicode decimal digits from the running Python's Unicode database (`mitmproxy/optmanager.py`, `_parse_setval`). | They accept decimal digits from Go's `unicode` tables, including digits assigned after the reference Python's Unicode version. | Each runtime supplies its Unicode database; the differential test checks every decimal digit known to the reference Python. |

## command

| Upstream | Go | Reason |
|---|---|---|
| `CommandManager.add` silently replaces a command that is already registered (`mitmproxy/command.py`). | `Register` refuses the name with `ErrDuplicateCommand`. | Two addons claiming one command are reported instead of one shadowing the other. |
| Removing an addon leaves its commands registered (`mitmproxy/addonmanager.py`). | The addon manager unregisters the commands the addon and its sub-addons added through their loaders (`Manager.Unregister`); each addon of a tree has a loader of its own, so removing a sub-addon removes only the commands it added. | Loading the addon again would otherwise be refused as a duplicate, and a removed addon's command would stay callable. |
| A command is any function or method decorated with `@command.command`; it takes no context (`mitmproxy/command.py`). | A command function's first parameter must be a `context.Context`, which is not a command parameter. `Register` and `Loader.AddCommand` refuse any other function with an error wrapping `ErrSignature` that names the command; `Call` passes the caller's context as that first argument. | A command runs under the addon dispatch lock, which Go cannot re-enter. The context carries the dispatch frame through which an option change, another command or a hook fired by the command runs inside the caller's hold of the lock; a command without it would wait forever for the lock its own caller holds. |
| Integer arguments use Python's arbitrary-precision `int`; its validation accepts booleans as integers, and boolean validation accepts numeric zero and one (`mitmproxy/types.py`). | Integer arguments must fit Go's native `int`; an overflow error names the argument. Integer and boolean validation require the corresponding Go type. | Command signatures have statically typed parameters and cannot receive Python's numeric subtyping or arbitrary-precision values. |
| String arguments may decode lone surrogate escapes with `unicode-escape` (`mitmproxy/types.py`). | Surrogate escapes are errors, including a pair of separately escaped surrogates. Other character names and aliases follow the reference Python 3.13 Unicode 15.1 database; Go 1.27 and `x/text` provide Unicode 17.0 tables, restricted to the reference version and supplemented with aliases and algorithmic names. | Surrogates are not Unicode scalar values and have no valid UTF-8 encoding. Substituting a replacement character would lose the supplied value. |
| `parse_partial` caches the last 128 command lines, including validity results from dynamic choice and flow-resolution commands (`mitmproxy/command.py`). | `ParsePartial` checks each call against the current registry and dynamic choices, without a cache. | A repeated line must not retain stale completion validity after options or commands change. |
| Marker completions can return the shared marker list; choice completions and parsed flow lists can share the provider's list (`mitmproxy/types.py`). | Returned completion and parsed-flow slices are caller-owned; resolved flow objects retain their identity. | Mutating a result must not alter future completions or the resolver's stored list. |

Reproduced on purpose: path expansion and completion follow the host's `os.path` conventions, including named users,
leading-dot glob rules, and Python's bracket patterns.

## addon

| Upstream | Go | Reason |
|---|---|---|
| Every hook runs on one asyncio event loop (`mitmproxy/addonmanager.py`). | Hooks run on the caller's goroutine under one dispatch lock. A command or option change made inside a hook re-enters through a dispatch frame carried in the `context.Context`. A frame used after the lock was released makes test binaries panic and returns `ErrStaleFrame` elsewhere. | Go mutexes are not re-entrant, and goroutines have no event loop to confine them. |
| A blocking handler is an `async` function; invoking it from a synchronous context fails with `Async handler ... cannot be called from sync context` before the handler runs (`mitmproxy/addonmanager.py`). | A Go hook calls `addon.Concurrent` to run blocking work with the lock released. Called from a nested dispatch, from `load` or `configure` however they are fired (upstream dispatches both only with `trigger` and `invoke_addon_sync`, never with `trigger_event`), from `done` fired by `Remove` or `Clear`, from any hook fired through `Manager.InvokeSync` (upstream's `invoke_addon_sync`), or from a command, however it is called (`command.Manager.Call`, `Manager.Call` or `Master.Call`; upstream commands are synchronous calls), it returns an error wrapping `ErrSyncContext`; the code of the hook before the call has already run. | Go hooks are plain functions; the release point is explicit. |
| `_iter_hooks` calls every callable attribute named like a hook with the hook's arguments, and refuses only one that is not callable (`mitmproxy/addonmanager.py`). | A method is a handler only when it matches the handler interface. A method with a handler's name whose first parameter is a `context.Context` but whose signature differs is refused at registration; a method with that name and no leading context (the `Done` of an embedded `sync.WaitGroup` or `context.Context`, the `Error` of an addon that implements `error`) is ignored and never called. | Go types gain such methods through embedding and standard interfaces; refusing them would rule out ordinary addons, while a near miss of a handler is still reported. |
| Log records reach `add_log` through `call_soon_threadsafe`, an unbounded queue (`mitmproxy/log.py`). | The queue is bounded (`DefaultLogQueueSize`). When it is full a record is dropped, and one warning entry later says how many were dropped. | Logging never blocks, and an addon that logs from `add_log` cannot grow memory without bound. |

## master

No behavioural differences. `Master.Do` is the Go entry point for goroutines that are not running a hook (frontends,
timers, script reloaders), and `Master.Call` runs a command the same way; upstream reaches the same state by scheduling
work on its event loop.

## internal/human

| Upstream | Go | Reason |
|---|---|---|
| `parse_size` returns a Python integer of any size (`mitmproxy/utils/human.py`). | `ParseSize` returns `ErrSizeRange` for a well-formed size that does not fit in an `int64`. | Sizes are `int64`. |
| Digits and whitespace in `parse_size` follow Python's Unicode 16 tables. | They follow Go's Unicode 17 tables, so digits added in Unicode 17 are accepted. | The tables come with each runtime. |
| `format_timestamp` and `format_timestamp_with_milli` raise for NaN, infinities and timestamps outside the years 1 to 9999. | The caller must pass a finite timestamp in that range; the output for other values is not defined. | Flow timestamps are always finite; no error return for a value that cannot occur. |
| `format_address` falls back to `host:port` for an IPv6 zone containing `%`, because `ipaddress` rejects it. | Same output; Go's `netip` would accept such a zone, so `FormatAddress` checks for it. | Listed only to explain the extra check; the output matches. |

## internal/strutil

| Upstream | Go | Reason |
|---|---|---|
| `bytes_to_escaped_str` post-processes its output with a regex whose repeated group keeps only its last repetition, so two or more backslashes before a quote (or, with `keep_spacing`, before `\n`, `\r` or `\t`) lose all but one escaped pair, and the text no longer decodes to the input (`mitmproxy/utils/strutils.py`). | `BytesToEscapedStr` keeps every backslash; its output always decodes back to the input. | Upstream bug. |
| `always_bytes` and `always_str` convert between `str` and `bytes` (`mitmproxy/utils/strutils.py`). | Not ported: Go uses `[]byte(s)` and `string(b)`, and callers pick a text codec themselves. | Go has no union of text and bytes to normalise. |

## internal/netutil

| Upstream | Go | Reason |
|---|---|---|
| `is_valid_host` matches each label with a `re` pattern ending in `$`, so a host ending in a newline is valid (`mitmproxy/net/check.py`). | `check.IsValidHost` rejects a trailing newline. | A newline is never part of a host name. |
| `is_valid_host` encodes a `str` host with Python's IDNA 2003 codec (`mitmproxy/net/check.py`). | `check.IsValidHost` uses UTS #46 transitional processing, as described under [httpmsg](#httpmsg). | Go has no IDNA 2003 implementation. |
| `encoding.decode` and `encode` fall back to Python's text codecs for names that are not content codings, such as `utf8`, and cache the last result (`mitmproxy/net/encoding.py`). | `encoding.Decode` and `Encode` accept only the content codings (`none`, `identity`, `gzip`, `deflate`, `deflateraw`, `br`, `zstd`); other names are errors. There is no result cache. | A text codec is not a Content-Encoding. |
| A failed `encoding.decode` or `encode` raises `ValueError` with the text `<type> when decoding b'<input>' with '<encoding>': <type>('<message>')`, whose message comes from zlib, brotli or libzstd, for example `error('Error -3 while decompressing data: invalid block type')` (`mitmproxy/net/encoding.py`). | `encoding.Error` has the same text up to the message, with the same type names (`LookupError`, `ValueError` with `Decompression failed: ` for a gzip codec failure, `error`, `ZstdError`) and the same ten-character input repr; the text for an unknown encoding is identical. The message of a codec failure is the Go decoder's, for example `error('flate: corrupt input before offset 1')`. | The messages belong to the C libraries upstream binds; the Go decoders word their failures differently. |

## internal/proxy/modespec

| Upstream | Go | Reason |
|---|---|---|
| Listen-port digits and macOS TUN-name digits follow the running Python's Unicode database (`mitmproxy/proxy/mode_specs.py`). | They follow Go's `unicode` tables, accepting decimal digits added after the reference Python's Unicode version. | Each runtime supplies its Unicode database; the differential test checks every decimal digit known to the reference Python. |
| Parsed modes are frozen dataclass objects, cached by the original specification (`mitmproxy/proxy/mode_specs.py`). | Parsed modes are comparable value structs, returned independently on each call. Callers treat shared values as immutable; changing a copy does not change the original. `String` and `Parse` provide the saved-state round trip. | Value semantics avoid a global cache and shared mutable references. |

Reproduced on purpose: listen hosts keep IPv6 brackets and explicit empty hosts; listen ports accept Python's decimal
integer syntax, including Unicode digits, signs, whitespace and single underscores between digits. The default
4300-digit conversion limit is retained. The macOS TUN-name check accepts one final newline, as Python's `$` does.

## contentviews

| Upstream | Go | Reason |
|---|---|---|
| A failed explicitly selected view displays the Python exception and a trimmed traceback (`mitmproxy/contentviews/__init__.py`). | The display keeps the `Couldn't parse as <view>:` heading and shows the Go error without a Python exception class or traceback. | Go errors have no Python traceback. Automatic selection still falls back to Raw with the same description. |
| `prettify_message` returns the entire rendered text; its callers apply the line cutoff (`mitmproxy/addons/dumper.py`). | `PrettifyMessage` optionally applies the caller's positive line cutoff and reports `Truncated`; a nonpositive cutoff keeps all text. | The shared entry point prevents callers from disagreeing about the cutoff. |
| The JSON view is bounded by Python's recursion limit, which includes the caller's stack (`mitmproxy/contentviews/_view_json.py`). | JSON nesting is limited to 1024 containers. | An explicit limit bounds recursive parsing and formatting independently of the calling goroutine's stack. |
| JSON strings may contain lone UTF-16 surrogates (`mitmproxy/contentviews/_view_json.py`, `json.loads` and `json.dumps(ensure_ascii=False)`). | Such strings retain the surrogate's WTF-8 bytes, including in object keys; ordinary text remains UTF-8. | Go strings store bytes rather than Python code points. This preserves the value without silently substituting U+FFFD. |
| The URL-encoded view's YAML emitter wraps a plain scalar before a word would exceed 80 columns, including a value after a long key (`mitmproxy/contentviews/_utils.py`, ruamel.yaml). | go-yaml may keep that word on the current line and wrap at a later space. Keys, scalar values, repeated-value sequences and their order are unchanged. | Use the maintained YAML emitter rather than duplicate it for cosmetic wrapping; differential tests require identical non-whitespace output and decoded values when wrapping differs. |

## tlsparse

| Upstream | Go | Reason |
|---|---|---|
| `get_client_hello` and `parse_client_hello` reassemble a handshake message of any declared length, up to the 16 MiB a 24-bit length allows (`mitmproxy/proxy/layers/tls.py`). | A handshake message longer than 65,536 bytes, its 4-byte header included, is refused with `ErrTooLarge` as soon as its length is known, before its bytes arrive. | Every re-ask of `next_layer` runs under the global dispatch lock, so ClientHello reassembly must be bounded. |
| `ClientHello.raw_bytes(True)` raises `OverflowError` for a body longer than 65,531 bytes, whose record length does not fit 16 bits (`mitmproxy/tls.py`). | `RawBytes(true)` returns nil for such a body. | Go methods do not raise; the largest accepted handshake body (65,532 bytes) cannot fit in one synthetic record. |

Reproduced on purpose (compatibility, not differences): the handshake message type is not checked; the extensions are
read to the end of the message whatever length their field declares; the server_name and ALPN extensions are read to the
end of their bodies whatever list length they declare, and an empty or truncated one makes the whole ClientHello
invalid; an odd cipher suite length leaves its last byte to be read as the compression methods' length.

## internal/tools/cmdline

| Upstream | Go | Reason |
|---|---|---|
| `--version` prints mitmproxy, Python, OpenSSL and platform information (`mitmproxy/tools/main.py`, `mitmproxy/utils/debug.py`). | Prints `Mitmproxy-go: <version>`, `Go: <runtime.Version()>`, and `Platform: <GOOS/GOARCH>`, on three lines. | Identifies the runtime actually used; the Go proxy does not use OpenSSL. |
| argparse formats help, reports argument errors, and accepts unambiguous long-flag abbreviations. Its `REMAINDER` positional argument keeps a literal `--` in the filter (`mitmproxy/tools/cmdline.py:123-135`, `mitmproxy/tools/main.py:156-164`). | Cobra/pflag supplies command parsing and error text; help preserves option help and metavars but uses a flat flag table. Long flags must be spelled in full. A `--` delimiter before the filter is consumed, not included in the filter text. | The selected Go command-line library uses GNU-style flags. Keeping argparse's literal delimiter would add an unintended filter term; consuming it also lets a filter begin with the reserved word `completion`. |
| A boolean flag accepts no attached value (`mitmproxy/optmanager.py`, `make_parser`). | Generated boolean flags also accept `=true`, meaning that flag was selected; for example, `--no-server=true` disables the server. Other attached values are rejected. | pflag sends the same value to a boolean flag for a bare occurrence and an explicit `=true`. Use the positive or negative flag to select the desired value. |
| There is no `completion` subcommand (`mitmproxy/tools/cmdline.py`). | `completion bash`, `completion zsh`, `completion fish` and `completion powershell` generate scripts backed by Cobra's dynamic `__complete` protocol. The scripts query the running command for every registered flag rather than embedding a static flag table. A filter beginning with the word `completion` must follow `--`. | Shell completion is an explicit addition to the Go CLI. |

## internal/http1

| Upstream | Go | Reason |
|---|---|---|
| The HTTP layer's head receive buffer has no total byte limit (`mitmproxy/proxy/layers/http/_http1.py`). | `MaxHeadBytes` limits each head to 1 MiB, including delimiters and leading empty lines; excess returns `ErrHeadTooLarge`. | Bound memory retained from network input. |
| Head lines have no separate limit (`mitmproxy/net/http/http1/read.py`). | `MaxLineBytes` limits each physical head line to 64 KiB including its newline; excess returns `ErrLineTooLong`. | Bound allocations before a line delimiter arrives. |
| The number of header fields is unlimited (`mitmproxy/net/http/http1/read.py`). | `MaxHeaderFields` permits 10,000 logical fields per head; excess returns `ErrTooManyHeaders`. Continuations count toward byte limits, not as new fields. | Bound per-field metadata. |
| An empty head is ignored until the next receive event (`mitmproxy/proxy/layers/http/_http1.py`, h11's receive buffer). | The blocking request-head reader skips leading empty lines in the same call. They count toward `MaxHeadBytes` and remain in `Raw` and `Consumed`. | A blocking reader has no receive-event boundary; it must continue to the request or EOF. |
| Every assembled head uses canonical spaces and CRLF (`mitmproxy/net/http/http1/assemble.py`). | Passing the original head to assembly preserves unchanged raw start lines and fields. Obs-folded fields use upstream's joined value. No original means canonical assembly. | Preserve byte fidelity where the proxy need not rewrite a field. |
| Status integers use Python's unbounded `int` (`mitmproxy/net/http/http1/read.py`). | Signs and digit separators are accepted, but the value must fit Go's `int` (64 bits on supported targets). | The shared response model stores an `int`. |
| Malformed head input raises `ValueError` with its input repr (`mitmproxy/net/http/http1/read.py`). | The same detail follows an `ErrInvalidHead` prefix; transport truncation is `io.ErrUnexpectedEOF`, and clean EOF is `io.EOF`. | Callers can distinguish syntax, transport, and each resource limit with `errors.Is`. |
| A chunk-size line permits 1–20 hexadecimal digits and unlimited extension bytes (h11 `_abnf.py`, `_readers.py`). | `MaxChunkLineBytes` caps the complete line at 4096 bytes, returning `ErrChunkLineTooLong`; numeric values beyond int64 are rejected. | Bound framing memory without allocating from the declared chunk size. |
| Trailer blocks have no separate byte, line or field limits (h11 `_readers.py`). | Trailers share `MaxHeadBytes`, `MaxLineBytes` and `MaxHeaderFields`, with the same distinct errors. | Trailers are untrusted headers and need the same resource bounds as heads. |
| Incomplete bodies raise an h11 protocol error; malformed footer details depend on the current receive event (h11 `_readers.py`). | Incomplete bodies wrap `io.ErrUnexpectedEOF` after the upstream message. Footer checks collect up to two bytes, so the reported invalid prefix can differ across transport fragmentation. | Blocking `io.Reader` has no receive-event boundary; callers can identify truncation with `errors.Is`. |
| Whole-message assembly requires non-missing `raw_content` (`mitmproxy/net/http/http1/assemble.py`). | Heads and bodies have separate APIs. `BodyWriter` consumes fragments, rejects excess declared-length data and checks completeness on `Close`; it never reads `RawContent`. | Stream without buffering an entire message or confusing absent content with an empty fragment. |

`FidelityCounter` is per proxy and safe for concurrent use. Assembly records an altered start line, each normalized
obs-fold continuation, a changed non-framing header block, and each changed framing-header family (`Content-Length`,
`Transfer-Encoding`) separately. The framing families are excluded from the general header-block count. Unchanged
raw bytes, generated heads without an original, and messages changed by an addon do not increment it; parsing never
increments it.
## internal/proxy

| Upstream | Go | Reason |
|---|---|---|
| The pending events of `NextLayer` and TLS receive buffers have no explicit recording limit (`mitmproxy/proxy/layer.py`, `mitmproxy/proxy/layers/tls.py`). | A recording connection retains at most 128 KiB before handover, and refuses a larger lookahead. After recording stops it replays every retained byte and streams without a body-size bound. | Protocol detection must not retain an unbounded amount of network input; protocol-specific sniff limits may be smaller. |

## internal/proxy

| Upstream | Go | Reason |
|---|---|---|
| The pending events of `NextLayer` and TLS receive buffers have no explicit recording limit (`mitmproxy/proxy/layer.py`, `mitmproxy/proxy/layers/tls.py`). | A recording connection retains at most 128 KiB before handover, and refuses a larger lookahead. After recording stops it replays every retained byte and streams without a body-size bound. | Protocol detection must not retain an unbounded amount of network input; protocol-specific sniff limits may be smaller. |
| `TimeoutWatchdog.watch` checks whether it is armed before sleeping, but does not recheck after the sleep; a previously scheduled timeout can fire during a long hook (`mitmproxy/proxy/server.py`). | Disarming invalidates the pending timer. Expiry checks the disarm counter and timer generation again before cancelling the connection. | Hook execution and intercepted-flow waits must not count as connection idle time. |

## Decided for code that is not written yet

These differences are settled in the work plan ([docs/plans/mitmproxy-go-port.md](plans/mitmproxy-go-port.md): the
sections "Starlark `concurrent` design", "Defaults set by the plan", the ADR and "Open items") and will appear in the
tables above when the code lands.

Scripting (Starlark instead of Python):

| Upstream | Go | Reason |
|---|---|---|
| Addon scripts are Python modules. | Scripts are Starlark modules. The `load` hook is named `on_load`, because `load` is a Starlark keyword; the other 45 hook names are unchanged. | No embedded Python interpreter. |
| `@concurrent` decorates a handler. | Starlark has no decorators: a handler is written `def _request(flow): ...` followed by `request = concurrent(_request)` at the top level, and the hook name comes from that global name. | Starlark syntax. |
| A `@concurrent` handler shares the module's globals and the live flow and connection objects. | Concurrent handlers run from a second, frozen instance of the module, so top-level code runs twice per load, writes to module globals from a handler fail, and the handler works on a copy of the flow that is merged back field by field. `client_conn` and `server_conn` are read-only snapshots. | A Starlark module that several goroutines call at once must be frozen; live connections are owned by their goroutine. |
| `@concurrent` is accepted on any hook except `load` and `configure`. | `concurrent` is accepted only on the 23 hooks that take a single flow; on any other hook the script fails to load with upstream's message `Concurrent decorator not supported for '<name>' method.` | Only a flow can be copied and merged back. |
| Calling a `@concurrent` handler directly returns a coroutine that is never awaited, so the handler does not run. | A direct call fails with `concurrent(<fn>) cannot be called directly; it runs only when invoked as a hook`. | Starlark has no coroutine value to return. |
| `script.run` rejects a concurrent handler with `Async handler <hook> (<module repr>) cannot be called from sync context`. | The message names the script path where upstream prints the module's repr. | A Starlark module has no Python repr. |

Options that only the Go port has (`testdata/options-go-only.txt`; not registered yet):

| Option | Type | Default | Meaning |
|---|---|---|---|
| `content_decode_limit` | str | `256m` | Upper bound on the decoded size of a message body (parsed as a byte size). A body that would decode to more counts as undecodable: `Content` and `Text` fail and `ContentOrRaw`/`TextOrRaw` return the raw bytes. Upstream decodes without a bound. |
| `local_redirector_path` | str | `""` | Path to the local mode redirector; empty means it is downloaded into the configuration directory on first use. |
| `otel_exporter_endpoint` | str | `""` | OTLP endpoint for OpenTelemetry traces and metrics; empty disables the exporter. |
| `pprof_addr` | str | `""` | Loopback address that serves `net/http/pprof`; empty disables it. |
| `script_max_steps` | int | `0` | Maximum Starlark execution steps per script hook call; 0 means no limit. |

HTTP/1 + TLS proxy core:

| Upstream | Go | Reason |
|---|---|---|
| `make_error_response` sends `Server: mitmproxy <version>` (`mitmproxy/proxy/layers/http/_http1.py`). | The error page sends `Server: mitmproxy-go <version>`; status, the other headers and the body are unchanged. | The proxy is a different program, as in the flow-file error texts above. |
| `next_layer` sniffs client data without a size bound (`mitmproxy/addons/next_layer.py`). | Sniffing stops at 64 KiB of client data for the HTTP host search, and at the ClientHello's declared length capped at 64 KiB. Beyond the cap the connection is relayed as raw TCP and the decision is logged. | Every re-ask of `next_layer` runs under the global dispatch lock, so an unbounded sniff buffer re-scanned on each read would stall every hook. |
| Message bodies are decoded without a size bound (`mitmproxy/net/encoding.py`). | Decoding on every `Content`/`Text` path is bounded by `content_decode_limit` (table above). The bound is published process-globally (`httpmsg.SetDecodeLimit`): two Masters in one process share it and the last `configure` wins; the `core` addon's `done` restores the 256 MiB default. | A compression bomb decoded under the dispatch lock would stall every hook; the decode paths are package-level functions, so the bound cannot be per-Master. |

TLS and protocol layers:

| Upstream | Go | Reason |
|---|---|---|
| pyOpenSSL can talk to servers that only offer finite-field DHE, SSLv3, RC4, 3DES or export cipher suites, and honours `@SECLEVEL=0`. | Go's `crypto/tls` supports none of these, so `ssl_insecure` interception of such legacy or IoT servers fails. `mitmproxy-dhparam.pem` is written only to keep the configuration directory layout and is never used. | The port uses the standard TLS stack. An OpenSSL- or utls-backed layer is a possible follow-up. |
| — | Go processes ECH before the proxy sees the ClientHello, so without the origin's ECH key only the outer `public_name` SNI is visible. Clients that attempt ECH fail unless `strip_ech` (default true) removed the `ech` parameter from the HTTPS records they resolved through the proxy. | Behaviour of Go's `crypto/tls`. |
| HTTP/2 windows are 2^31−1 and data is acknowledged at once (`mitmproxy/proxy/layers/http/_http_h2.py`, `_http2.py`). | Bounded windows: 100 concurrent streams, a 1 MiB initial stream window growing to 16 MiB, and a 128 MiB budget for granted windows; a stream's window is returned only when its data has been consumed. | Memory per connection stays bounded under slow readers. |
| TLS connections are half-closed with a bare TCP FIN (`mitmproxy/proxy/layers/tls.py`). | The proxy sends `close_notify`, then FIN. | Go's `tls.Conn.CloseWrite` sends `close_notify`; peers see a clean TLS shutdown. |
| Server connections are reused by address, TLS, `via` and transport protocol (`mitmproxy/proxy/layers/http/__init__.py`). | The SNI is part of the key as well. | A connection opened for one SNI is never reused for another. |
| DTLS follows the `tls_version_*` options. | `pion/dtls` speaks DTLS 1.2 only: a version window that contains `TLS1_2` negotiates DTLS 1.2, any other window fails the DTLS connection. | Limit of the only maintained pure-Go DTLS implementation. |
