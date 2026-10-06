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
| Configured-certificate errors include cryptography's parser text and Python object reprs for mismatched public keys (`mitmproxy/certs.py`, `mitmproxy/addons/tlsconfig.py`). | Missing-file, invalid-format, missing-key and key-mismatch prefixes are preserved; parser details come from Go and mismatches omit Python object reprs. File reads are capped at 8 MiB before parsing. | Python implementation-specific diagnostics have no Go equivalent; bound file loading as well as private-key parsing. |
| `create_store` temporarily tightens the process umask while writing the two key-bearing files (`umask_secret` in `mitmproxy/certs.py`). | The key-bearing files are created with mode 0600 directly; the process umask is never changed. The resulting modes are the same: owner-only for key files, the regular default under the umask for the public files. | Changing the process-global umask would race with every other goroutine creating files. |
| `create_store` overwrites files and accepts configuration directories writable by other users (`mitmproxy/certs.py:563-615`). | New directories use mode 0700; Unix checks the opened directory's ownership and mode, refusing another user's directory or one writable by group or others. CA reads and exclusive file creates use the same pinned `os.Root`, so renaming the configured path cannot redirect a write. Absolute or escaping CA symlinks are refused; relative in-root symlinks remain supported. Existing files are retained; CA key files and DH parameters use mode 0600, including recreated DH parameters. Windows omits the POSIX ownership/mode check because permissions use ACLs. | Do not replace another creator's CA or write a private key into a pre-existing file controlled by another user. |

## addons/upstreamauth

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| Invalid upstream-auth configuration errors include the complete specification (`mitmproxy/addons/upstream_auth.py:15`). | Errors omit the specification. | It can contain a password. |

## addons/proxyauth

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| LDAP connects and service-binds during configuration (`mitmproxy/addons/proxyauth.py`). | Configuration validates syntax only. Each authentication connects, service-binds, searches and user-binds outside the addon dispatch lock. An unreachable directory produces an authentication challenge (407 in proxy modes, 401 in reverse mode) and a warning at authentication time. | Network I/O cannot block configuration or the shared dispatch lock. |
| LDAP operations have no explicit exchange-size or elapsed-time bound, and the search returns all matches before the first is used. | An authentication has a 10-second context deadline; each of its at most two connections receives at most 1 MiB of LDAP data. Search requests one entry without attributes and uses the first returned DN. | Bound resources while retaining the first-match authentication behavior. The configured directory is trusted; the pinned BER library still has no nesting-depth limit. |
| The default `ldap3.Tls()` skips certificate verification. | LDAPS verifies the server certificate and requires TLS 1.2 or newer. Private directory CAs must be installed in the system trust store. | Do not send credentials to an unauthenticated TLS peer; no separate LDAP trust option is provided. |
| Invalid LDAP specifications are included verbatim in configuration errors. | Errors name the invalid field but omit the specification; authentication warnings include the error type, not server-supplied diagnostic text. | Specifications contain the service password, and server diagnostics can disclose credentials or personal data. |
| The LDAP port uses Python `int()` (`mitmproxy/addons/proxyauth.py:252`), including Unicode decimal digits, underscore separators and surrounding whitespace. | Explicit ports must use ASCII decimal syntax (an optional sign is accepted) and fall within 1–65535. | Configuration-only restriction; avoids duplicating the private Python-integer parsers elsewhere in the port. |
| Basic authentication headers have no length limit. | Headers longer than 64 KiB are rejected. | Bound decoding work under the dispatch lock. |

## addons/browser

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| `browser.start` has a Python default argument `browser="chrome"` (`mitmproxy/addons/browser.py:40`). | `Start(ctx, names ...string)` accepts zero or one name, defaults to Chrome, and rejects extra names. Command metadata displays a variadic string argument. | Retain the variadic Go API so callers can omit the browser name as on the CLI. The registry supports defaults through `command.WithDefault`, but this command keeps its existing API and variadic metadata. |
| Flatpak discovery runs `flatpak info` synchronously before the command returns (`mitmproxy/addons/browser.py:19-32`). | Probes run outside dispatch; a launch or unsupported-platform alert can arrive after the command returns. Launch uses the current listen options when discovery completes. `Done` cancels pending probes and prevents their deferred launches. | Waiting for a child process cannot hold the shared addon dispatch lock. Direct filesystem lookup and process start remain synchronous. |
| `done` kills browsers and removes temporary profiles immediately (`mitmproxy/addons/browser.py:227-233`). | `Done` kills without waiting; background reapers wait for each child and then remove its profile. Failed starts remove their unused profiles immediately. Cleanup errors are logged. | Reap children and avoid removing profiles while a terminating browser still uses them, without waiting under dispatch. |
| `done` propagates subprocess termination failures (`mitmproxy/addons/browser.py:227-233`). | On Windows only, an access-denied termination error permits up to one second waiting on the pinned process handle. A signaled exit is treated as already finished; otherwise the error is retained. Other error paths do not wait. | Windows can deny termination while a child is tearing down but before its exit handle is signaled. The bounded exception recognizes that race without suppressing genuine kill failures. |

## addons/dumper

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| DNS answers render through `ResourceRecord.__str__`: A/AAAA addresses, NS/CNAME/PTR domain names, TXT text, HTTPS record JSON, hexadecimal for other types (`mitmproxy/dns.py:74,153-169`). | A, AAAA and TXT render as upstream's do, and unknown types render as hexadecimal; NS, CNAME, PTR and HTTPS records render as their type name instead of their data. | Their data needs the DNS wire codec (compressed domain names, HTTPS record fields), which is ported with the DNS protocol work; the type-name placeholder stands in until that codec lands. |
| Message content chunks are coloured by syntax-highlight tag through `CONTENTVIEW_STYLES` (`mitmproxy/addons/dumper.py:38-45,130-140`). | Message content is printed uncoloured; request, status, header and trailer styles are emitted as upstream's are. | The syntax highlighter behind the tags is ported with the content-view highlighting work; on a pipe, where the differential runs, upstream emits no colour either, so the compared output is identical. |

## addons/savehar

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| HAR objects retain Python dictionary insertion order (`mitmproxy/addons/savehar.py`). | Exported HAR objects sort keys; arrays, duplicate fields and all JSON values retain upstream semantics. | Deterministic standard-library JSON output; HAR consumers do not depend on object key order. Float spelling and ASCII/surrogateescape string spelling follow Python. |
| `.zhar` uses Python's zlib encoder at level 9 (`mitmproxy/addons/savehar.py`). | Uses Go's standard zlib encoder at level 9. The decompressed HAR is equivalent; compressed bytes may differ. | Compression streams depend on the encoder implementation; both encodings are readable by zlib. |
| `save.har` and `hardump` create files with mode 0666 under the process umask (`mitmproxy/addons/savehar.py`). | On Unix, new HAR and compressed HAR files use mode 0600 and existing files are narrowed to 0600; symlinks and foreign-owned targets are refused. See [internal/privfile](#internalprivfile) for the Windows caveat. | Recordings contain bodies, cookies and headers that may contain credentials, matching the port's save, export and cut file policy. |

## addons/save

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| Stream and `save.file` outputs use mode 0666 under the process umask (`mitmproxy/addons/save.py`). | On Unix, new recording files use mode 0600 in both overwrite and append modes and existing files are narrowed to 0600; symlinks and foreign-owned targets are refused. Authentication metadata is preserved as upstream records it. See [internal/privfile](#internalprivfile) for the Windows caveat. | Flow recordings can contain passwords, cookies and bodies; restrict output files to their owner rather than remove compatible metadata. |
| Stream paths use local, naive `datetime.today().strftime`, including the host C library's locale and directive extensions (`mitmproxy/addons/save.py`). | Uses timefmt-go v0.1.9 with local wall-clock fields; bare `%z` and `%Z` render empty and `%%` remains escaped. `E`/`O` modifiers are not interpreted: `%EC`, `%Ey`, `%EY`, `%Od` and `%Om` remain literal. Unsupported directives such as `%q` also remain literal, including `%`; Python's result is platform-dependent. Month/day names and composite formats use timefmt-go's English/C-style output rather than the process locale. Other modifiers and extensions follow timefmt-go. | Use the pure-Go formatter without recreating platform-specific libc strftime. `TestStrftimePath` checks the naive timezone rules, escaped percents and literal unsupported directives. |

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
| Request header validation checks names and framing values but permits bare control bytes in other values (`mitmproxy/net/http/validate.py`). | With `validate_inbound_headers` enabled, request values reject C0 controls other than HTAB and reject DEL; CRLF followed by SP or HTAB remains accepted as obs-fold. With the option disabled, the raw values are forwarded as before. | A bare CR or other control can make a recipient read a different header block; valid folded continuations remain part of the fidelity contract. |

The runtime streaming contract uses two fields rather than Python's bool-or-callable `stream` attribute
(`mitmproxy/http.py:247-259`): `Stream` enables forwarding without buffering, and a non-nil
`StreamFunc func([]byte) [][]byte` enables streaming and transforms chunks. Neither field is saved in flow state.
A transform is called once more with an empty chunk at the end. It runs under the dispatch lock, acquired once per
chunk, to preserve upstream's event-loop serialization. Unlike a hook, it receives no context and must not change
options, call commands or fire hooks, which would wait for its own lock. A slow transform delays all connections'
hooks; streaming with `Stream` alone does not acquire the lock per chunk.

## tcp, udp

| Upstream | Go | Reason |
|---|---|---|
| `TCPMessage` and `UDPMessage` print the content as a Python bytes literal: `-> b'hello\n'` (`mitmproxy/tcp.py`, `mitmproxy/udp.py`). | `String` prints a Go-quoted string: `-> "hello\n"`. | Go syntax in Go output. The flow summaries (`<TCPFlow (3 messages)>`) are unchanged. |

## websocket

No differences beyond the message content rule listed under [flow](#flow).

## dns

No behavioural differences.

## flowio

| Upstream | Go | Reason |
|---|---|---|
| `flow_to_json` includes DNS request and response JSON (`mitmproxy/tools/web/app.py`). | `flowjson.Flow` returns `flowjson: dns flows are not supported yet`. | The DNS JSON view requires the HTTPS-record helpers that arrive with the DNS codec. |
| Tornado's `json_encode` escapes non-ASCII characters in flow JSON, including invalid bytes represented by lone surrogateescape code points (`mitmproxy/tools/web/app.py`, `mitmproxy/http.py`). | Valid non-ASCII text may remain UTF-8; undecodable wire bytes are emitted as the same lone surrogate escapes through a per-string raw JSON encoder. | Escaping style differs, not the JSON string value; binary header values cannot break serialization of the flow list. |
| HAR documents are read in full without a byte-size bound, and JSON nesting is bounded only by Python's recursion limit (`mitmproxy/io/io.py`, `mitmproxy/io/har.py`). | HAR input is capped at 256 MiB and 1000 nested arrays or objects. Streaming token decoding grows memory only with bytes actually read. Invalid documents and entries retain upstream's `Unable to read HAR file. Please provide a valid HAR file` text; the underlying cause is available through `errors.Unwrap`. The byte order mark is skipped only immediately before `{`, as upstream does. | Explicit bounds prevent an untrusted file from exhausting memory or the stack. |
| `startedDateTime` accepts every `datetime.fromisoformat` form (`mitmproxy/io/har.py`). | Accepts RFC 3339 with any fractional-second length, `Z` or numeric offset; naive date-times use local time. A space may replace `T`, and fractions may be omitted. Date-only, ISO-week and compact date-time forms are rejected with the HAR read error. | Limit parsing to forms used by real HAR writers without adding a dependency; microseconds and local-time interpretation match Python. |
| `json.loads` expands every HAR entry before iteration, with no entry-count limit (`mitmproxy/io/io.py`). | The final `log.entries` array is decoded one entry at a time and refused before materializing more than `har.MaxEntries` (100,000) values. Duplicate `log` and `entries` keys keep the last value, as Python does; discarded arrays are byte/depth bounded but do not count against the final entry budget. | Bound per-entry allocation before replay loaders see any flows, while retaining deterministic last-key semantics. |

## flowio and flowio/tnetstring

| Upstream | Go | Reason |
|---|---|---|
| `FlowReader` migrates every flow format from `(0, 11)` up to the current version 21 (`mitmproxy/io/compat.py`). | Formats 18 to 20 are migrated; older ones are rejected with upstream's message for an unknown version: `mitmproxy-go 0.1.0-dev cannot read files with flow format version 17.` | Scope decision for the port; porting the older migrations is a listed follow-up in the work plan. |
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
| Python's capture/substitution expressions have no explicit size bounds (`re`, used by `mitmproxy/addons/modifybody.py`, `mapremote.py` and `maplocal.py`). | `CompilePattern` caps patterns at 1 MiB and subjects, replacement templates and substituted outputs at 256 MiB; an excess returns an error without partial output. | Bound configuration and message transformation memory. Existing filter `Compile` is unchanged. |
| Python substitutes nullable expressions and preserves the non-consuming meaning of `$` (`re.sub`, `mitmproxy/addons/modifybody.py`). | `CompilePattern` sends nullable expressions and non-multiline dollar expressions to the bounded fallback, even when RE2 accepts their syntax. | RE2's iterator does not retry a consuming alternative immediately after an empty match; the boolean filter dollar rewrite can consume a final newline and cannot preserve captures. |
| Python searches and substitutions have no match timeout (`re`). | Capture/substitution searches on the fallback have a 100 ms limit per call. `Search` and `Sub` return a bounded error without logging; their boolean `Matcher` methods log and return false. | Callers must distinguish an abandoned transformation from a successful identity substitution. |
| `re.Match.span` counts Unicode code points for string patterns (`re`, used by `mitmproxy/addons/maplocal.py`). | Capture spans are half-open byte offsets into the original input in both string and bytes modes; unmatched groups use `[-1, -1]`. | Go slices strings by byte offset. Captured text is unchanged. |
| Case-insensitive bytes backreferences fold ASCII only: `re.search(rb'(?i)(.)\1', b'\xc0\xe0')` returns no match (`re`, used by `mitmproxy/addons/modifybody.py`). | `CompilePattern` matches both bytes in this example. Byte literals and classes have ASCII-only folding, but fallback backreferences retain the engine's Unicode folding. | `regexp2` has no ASCII-only case-insensitive backreference mode. Bytes are otherwise interpreted as Latin-1 in the capture/substitution API, unlike the existing filter matcher. |

| Python substitutes without a match-count or capture-table budget (`re.sub`, `mitmproxy/addons/modifybody.py`). | Substitution permits at most 1,048,576 matches on either engine and returns `regex: too many matches` without partial output on overflow. Context-free RE2 expressions retain only the current match; expressions with anchors or boundaries search the whole subject with a 1 MiB estimated index-table budget, including capture-count and growth headroom, and reject excessive tables. | Avoid eager all-match allocation while preserving whole-subject anchors, word boundaries, empty-match retry and count semantics. Fallback timeouts remain per search, not a whole-substitution deadline. |

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

## addons/core

| Upstream | Go | Reason |
|---|---|---|
| Flow editing and encoding commands use `getattr` on request and response objects, including objects on non-HTTP flows (`mitmproxy/addons/core.py`). | `flow.set`, `flow.decode`, `flow.encode` and `flow.encode.toggle` mutate only present HTTP request or response parts. Other flow types and absent parts are skipped; `flow.set` still includes all supplied flows in its update hook. | HTTP fields and body codecs belong to typed HTTP messages, not DNS or transport messages. |
| Assigning `Request.method` preserves the supplied bytes, but reading the property returns their uppercase spelling (`mitmproxy/http.py`). | `flow.set ... method post` leaves `httpmsg.Request.Method` and serialized request state as `post`; callers that need the upstream display value uppercase it themselves. | The exported Go field represents raw wire bytes, without a separate display accessor. |
| There is no `content_decode_limit` option (`mitmproxy/addons/core.py`). | Core registers a string option with default `256m`, validates it with `human.ParseSize`, and rejects negative, malformed and overflowing values with `OptionsError`. An accepted value is published through `httpmsg.SetDecodeLimit`, whose bound is process-global: with several managers in one process the last configure wins, and removing core restores the 256 MiB default for the whole process. Zero bounds every nonempty decoded body, not unlimited decoding. | The Go-only option configures the bounded decoder, whose decode paths are package-level code shared by every manager in the process. |

Reproduced on purpose:

- `flow.set` sends every supplied flow to the update hook, even when the selected field is absent or unchanged;
  upstream writes an instance attribute instead of clearing its local request-update flag.
- `set` creates a separate option assignment for every value. Sequence options accept multiple values; scalar
  options reject them, despite the command's upstream help text saying values are joined with spaces.
- `options.save` preserves an `OptionsError` from malformed existing YAML rather than converting it to a command
  error. Filesystem failures are command errors with the `Could not save options - ` prefix.

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
| `is_valid_host` accepts an IPv6 address whose zone holds any characters except `%` and `/`, through `ipaddress.ip_address` (`mitmproxy/net/check.py`). | `check.IsValidHost` accepts a zone only if it is an RFC 6874 ZoneID: unreserved characters (`A-Z a-z 0-9 - . _ ~`) and `%XX` escapes. A backslash, NUL, space, colon or other byte makes the host invalid, for strings and byte slices alike. | A host taken from a peer, such as a TLS SNI, becomes part of file names (client certificates), where a separator or NUL must never arrive. |
| `is_valid_host` encodes a `str` host with Python's IDNA 2003 codec (`mitmproxy/net/check.py`). | `check.IsValidHost` uses UTS #46 transitional processing, as described under [httpmsg](#httpmsg). | Go has no IDNA 2003 implementation. |
| Byte-slice IPv6 zones can bypass the empty-label and label-length checks applied when a string is IDNA-encoded (`mitmproxy/net/check.py`). | ASCII string and byte-slice hosts obey the same label bounds, including zones: empty interior labels and labels longer than 63 bytes are refused. Non-ASCII byte slices remain invalid. | Validation of the same peer-controlled host must not depend on its representation. |
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
| The URL-encoded, Query and Image views' YAML emitter wraps a plain scalar before a word would exceed 80 columns, including a value after a long key; long double-quoted surrogateescape strings can use escaped line continuations, and wrapping a long double-quoted image-metadata scalar can insert a fold space that upstream's own reload keeps in the value (`mitmproxy/contentviews/_utils.py`, ruamel.yaml). | go-yaml may wrap plain words at a later space. Malformed UTF-8 query scalars retain the same surrogate escapes on one line, and image-metadata scalars stay on one line with their original characters. Keys, scalar values, repeated-value sequences and their order are unchanged. | Use the maintained YAML emitter rather than duplicate it for cosmetic wrapping. Differential tests assert original decoded values, identical non-whitespace output for plain wrapping, and exact escape spelling after removing only escaped line continuations within malformed-UTF-8 double-quoted scalar spans. Output outside those spans is unchanged. The image differential compares the decoded Go output with the metadata the pinned Python view rendered, and the exact text where neither side wraps. |
| Query strings containing non-BMP Unicode are emitted literally by ruamel.yaml (`mitmproxy/contentviews/_view_query.py`, `_utils.py`), for example U+1F642. | go-yaml may double-quote the scalar and emit `\U0001F642` instead. | Cosmetic spelling only: both forms decode to the same original string. Differential tests compare decoded values and the output outside those scalars. |
| A query value `a` + U+0085 (NEL) + `b` is emitted as a single-quoted scalar with a literal NEL and two indentation spaces; upstream's own `yaml_loads` reads it back as `a b` (`mitmproxy/contentviews/_view_query.py`, `_utils.py`, pinned ruamel.yaml probe). An image-metadata value with the character behaves the same way. | Emits the double-quoted scalar `"a\Nb"`, which reads back with the original NEL, in query and image metadata alike. | Deliberate correctness difference: preserve the query's character rather than reproduce ruamel's lossy roundtrip. Differential tests assert equality with the original query strings and output equality outside affected scalars. |
| A zTXt chunk's text is decompressed without a size limit (`mitmproxy/contentviews/_view_image/image_parser.py`, `mitmproxy/contrib/kaitaistruct/png.py`, `zlib.decompress`). | Decompressing beyond 64 MiB fails the image view. | A small chunk must not expand without bound while rendering an untrusted body. |

## tlsparse

| Upstream | Go | Reason |
|---|---|---|
| `get_client_hello` and `parse_client_hello` reassemble a handshake message of any declared length, up to the 16 MiB a 24-bit length allows (`mitmproxy/proxy/layers/tls.py`). | A handshake message longer than 65,536 bytes, its 4-byte header included, is refused with `ErrTooLarge` as soon as its length is known, before its bytes arrive. | Every re-ask of `next_layer` runs under the global dispatch lock, so ClientHello reassembly must be bounded. |
| `ClientHello.raw_bytes(True)` raises `OverflowError` for a body longer than 65,531 bytes, whose record length does not fit 16 bits (`mitmproxy/tls.py`). | `RawBytes(true)` returns nil for such a body. | Go methods do not raise; the largest accepted handshake body (65,532 bytes) cannot fit in one synthetic record. |
| `ClientHello.raw_bytes` raises `NotImplementedError` for a DTLS ClientHello in both wrapping modes (`mitmproxy/tls.py`). | `RawBytes(false)` returns the exact DTLS handshake body; `RawBytes(true)` returns nil. `IsDTLS` lets callers distinguish this case before wrapping. | Expose the received body without fabricating a TLS record that misrepresents DTLS framing. |

Reproduced on purpose (compatibility, not differences): the handshake message type is not checked; the extensions are
read to the end of the message whatever length their field declares; the server_name and ALPN extensions are read to the
end of their bodies whatever list length they declare, and an empty or truncated one makes the whole ClientHello
invalid; an odd cipher suite length leaves its last byte to be read as the compression methods' length.

DTLS sniffing also follows upstream's ordered record concatenation (`mitmproxy/proxy/layers/tls.py:94-160`):
records are read in arrival order and the first handshake header's fragment length is used. The ClientHello sniffer
does not reorder fragments or deduplicate retransmissions; pion handles retransmissions in the subsequent handshake.

## internal/tools/cmdline

| Upstream | Go | Reason |
|---|---|---|
| `--version` prints mitmproxy, Python, OpenSSL and platform information (`mitmproxy/tools/main.py`, `mitmproxy/utils/debug.py`). | Prints `Mitmproxy-go: <version>`, `Go: <runtime.Version()>`, and `Platform: <GOOS/GOARCH>`, on three lines. | Identifies the runtime actually used; the Go proxy does not use OpenSSL. |
| argparse formats help, reports argument errors, and accepts unambiguous long-flag abbreviations. Its `REMAINDER` positional argument keeps a literal `--` in the filter (`mitmproxy/tools/cmdline.py:123-135`, `mitmproxy/tools/main.py:156-164`). | Cobra/pflag supplies command parsing and error text; help preserves option help and metavars but uses a flat flag table. Long flags must be spelled in full. A `--` delimiter before the filter is consumed, not included in the filter text. | The selected Go command-line library uses GNU-style flags. Keeping argparse's literal delimiter would add an unintended filter term; consuming it also lets a filter begin with the reserved word `completion`. |
| A boolean flag accepts no attached value (`mitmproxy/optmanager.py`, `make_parser`). | Generated boolean flags also accept `=true`, meaning that flag was selected; for example, `--no-server=true` disables the server. Other attached values are rejected. | pflag sends the same value to a boolean flag for a bare occurrence and an explicit `=true`. Use the positive or negative flag to select the desired value. |
| There is no `completion` subcommand (`mitmproxy/tools/cmdline.py`). | `completion bash`, `completion zsh`, `completion fish` and `completion powershell` generate scripts backed by Cobra's dynamic `__complete` protocol. The scripts query the running command for every registered flag rather than embedding a static flag table. A filter beginning with the word `completion` must follow `--`. | Shell completion is an explicit addition to the Go CLI. |

## internal/h2

| Upstream | Go | Reason |
|---|---|---|
| HTTP/2 receive windows are 2^31−1, and DATA is acknowledged immediately (`mitmproxy/proxy/layers/http/_http_h2.py:50-67`, `_http2.py:238-240`). | Each receive endpoint independently reserves at most 128 MiB of aggregate stream grants. Initial stream windows are 1 MiB and grow on consumption up to 16 MiB, with at most 100 concurrent streams. Credit is returned only after the original input, including padding, has been consumed; transformed output does not determine the receipt size. | Bound retained input and keep unrelated streams progressing when one stream's reader or transformed output stalls. The two receive directions do not share a budget. |
| HTTP/1 h2c upgrade bodies are admitted under maximal receive windows and immediately acknowledged (`mitmproxy/proxy/layers/http/_http_h2.py`, `_http2.py`). | The endpoint constructor rejects an upgrade body larger than its 1 MiB initial stream window. Accepted bodies are charged to stream 1 and delivered in chunks no larger than `ChunkSize`, with original-byte receipts and the terminal flag only on the final chunk. The default addon set still disables h2c. | Seeding an upgraded stream must obey the same receive-window and ownership bounds as ordinary DATA. |

## internal/http1

| Upstream | Go | Reason |
|---|---|---|
| The HTTP layer's head receive buffer has no total byte limit (`mitmproxy/proxy/layers/http/_http1.py`). | `MaxHeadBytes` limits each head to 1 MiB, including delimiters and leading empty lines; excess returns `ErrHeadTooLarge`. | Bound memory retained from network input. |
| Head lines have no separate limit (`mitmproxy/net/http/http1/read.py`). | `MaxLineBytes` limits each physical head line to 64 KiB including its newline; excess returns `ErrLineTooLong`. | Bound allocations before a line delimiter arrives. |
| The number of header fields is unlimited (`mitmproxy/net/http/http1/read.py`). | `MaxHeaderFields` permits 10,000 logical fields per head; excess returns `ErrTooManyHeaders`. Continuations count toward byte limits, not as new fields. | Bound per-field metadata. |
| An empty head is ignored until the next receive event (`mitmproxy/proxy/layers/http/_http1.py`, h11's receive buffer). | The blocking request-head reader skips leading empty lines in the same call. They count toward `MaxHeadBytes` and remain in `Raw` and `Consumed`. | A blocking reader has no receive-event boundary; it must continue to the request or EOF. |
| Every assembled head uses canonical spaces and CRLF (`mitmproxy/net/http/http1/assemble.py`). | Passing the original head to assembly preserves unchanged raw start lines and fields, including their SP/HTAB spacing and LF-only line endings. Obs-folded fields use upstream's joined value. A start line whose words are separated by other whitespace the parser accepts (VT, FF, bare CR) or whose status code is spelled differently from its integer, and a field whose value carries such whitespace around it, are re-emitted from the parsed values as upstream does. No original means canonical assembly. | Preserve byte fidelity where the proxy need not rewrite a field, but never forward a spelling a stricter parser reads differently from the values the proxy framed the message by. |
| Start lines are always reassembled without leading whitespace (`mitmproxy/net/http/http1/assemble.py`). | Parsed start lines beginning with SP or HTAB are re-emitted canonically and counted once by `FidelityCounter`, unless an addon changed the message. Internal SP/HTAB separators and unchanged headers still retain their wire spelling. | Leading whitespace can be read differently by a stricter HTTP recipient; it is not safe wire fidelity. |
| Status integers use Python's unbounded `int` (`mitmproxy/net/http/http1/read.py`). | Signs and digit separators are accepted, but the value must fit Go's `int` (64 bits on supported targets). | The shared response model stores an `int`. |
| Malformed head input raises `ValueError` with its input repr (`mitmproxy/net/http/http1/read.py`). | The same detail follows an `ErrInvalidHead` prefix; transport truncation is `io.ErrUnexpectedEOF`, and clean EOF is `io.EOF`. | Callers can distinguish syntax, transport, and each resource limit with `errors.Is`. |
| A chunk-size line permits 1–20 hexadecimal digits and unlimited extension bytes (h11 `_abnf.py`, `_readers.py`). | `MaxChunkLineBytes` caps the complete line at 4096 bytes, returning `ErrChunkLineTooLong`; numeric values beyond int64 are rejected. | Bound framing memory without allocating from the declared chunk size. |
| Trailer blocks have no separate byte, line or field limits (h11 `_readers.py`). | Trailers share `MaxHeadBytes`, `MaxLineBytes` and `MaxHeaderFields`, with the same distinct errors. | Trailers are untrusted headers and need the same resource bounds as heads. |
| Incomplete bodies raise an h11 protocol error; malformed footer details depend on the current receive event (h11 `_readers.py`). | Incomplete bodies wrap `io.ErrUnexpectedEOF` after the upstream message. Footer checks collect up to two bytes, so the reported invalid prefix can differ across transport fragmentation. | Blocking `io.Reader` has no receive-event boundary; callers can identify truncation with `errors.Is`. |
| Whole-message assembly requires non-missing `raw_content` (`mitmproxy/net/http/http1/assemble.py`). | Heads and bodies have separate APIs. `BodyWriter` consumes fragments, rejects excess declared-length data and checks completeness on `Close`; it never reads `RawContent`. | Stream without buffering an entire message or confusing absent content with an empty fragment. |

`FidelityCounter` is per proxy and safe for concurrent use. Assembly records an altered start line, each normalized
obs-fold continuation, each field re-emitted because its wire value carried whitespace other than SP and HTAB, a
changed non-framing header block, and each changed framing-header family (`Content-Length`, `Transfer-Encoding`)
separately. The framing families are excluded from the general header-block count. Unchanged raw bytes, generated
heads without an original, and messages changed by an addon do not increment it; parsing never increments it.

## internal/proxy/layers/httplayer

| Upstream | Go | Reason |
|---|---|---|
| `make_error_response` sends `Server: mitmproxy <version>` (`mitmproxy/proxy/layers/http/_http1.py`). | The error page sends `Server: mitmproxy-go <version>`; status, the other headers and the body are unchanged. | The proxy is a different program, as in the flow-file error texts above. |
| Bytes arriving while an HTTP exchange waits for its response, including pipelined requests and early tunnel data, have no explicit buffer limit (`mitmproxy/proxy/layers/http/_http1.py`). | Each endpoint retains at most `layer.MaxRecordBytes` (128 KiB) in this waiting state; excess terminates the exchange with a protocol error. This is separate from body streaming and its configured limits. | Bound memory while the other direction is stalled. |
| Receiving HTTP/1 trailers raises `NotImplementedError`; sending trailer events is not implemented (`mitmproxy/proxy/layers/http/_http1.py`). | Chunked trailers are parsed, exposed to request/response hooks, and emitted after the final transformed body chunk. | The shared message and event contracts represent trailers, so HTTP/1 can preserve them rather than fail. |
| A non-101 informational response is treated as the response for the exchange (`mitmproxy/proxy/layers/http/_http1.py`). | Informational heads are forwarded without completing the exchange; the final response is still awaited. | Informational responses do not replace the final response. Ordinary response hooks run for the final response only. |
| The partial-response-head diagnostic includes a Python repr of buffered bytes (`mitmproxy/proxy/layers/http/_http1.py`). | The error identifies the incomplete response head without that buffered-byte repr. | Blocking readers do not expose the same receive-event buffer; parser errors retain their own details. |
| Server connections are reused by address, TLS, `via` and transport protocol (`mitmproxy/proxy/layers/http/__init__.py`). | The SNI is part of the key as well. | A connection opened for one SNI is never reused for another. |
| CONNECT request and response end-of-message events are suppressed; subsequent events carry tunnel bytes (`mitmproxy/proxy/layers/http/_http1.py`). | Every completed CONNECT HTTP message emits its directional end event, including a refused response. That event does not half-close a successful tunnel. Negotiated tunnel/upgrade transport EOF is `io.EOF`, not another HTTP end event. | Endpoint callers need one uniform HTTP completion contract and must distinguish it from transport closure before handing the connection to a child protocol. |
| The default `disable_h2c` addon strips Upgrade and refuses cleartext prior knowledge; upstream supports HTTP/2 over TLS (`mitmproxy/addons/disable_h2c.py`). | Defaults remain unchanged. An embedder omitting the addon can use cleartext prior knowledge or a validated HTTP2-Settings Upgrade. Request hooks run once before takeover; if their final body exceeds the 1 MiB initial stream window, the request continues as HTTP/1.1 without a 101 response. | RFC 9113 permits ignoring Upgrade. Optional takeover must not seed an unbounded request body or run request hooks twice. |

Validated, enabled WebSocket upgrades select the WebSocket layer, transferring both already-read byte prefixes
and all four extension-header snapshots. Other upgrades and disabled WebSocket handling retain the raw-TCP fallback.

Proxy target, Host and Expect rewrites contribute to the [HTTP/1 fidelity counter](#internalhttp1).
Actual addon head edits are detected at hook boundaries after proxy preparation and exclude that head's emission from
the counter. Editing a body does not by itself exclude its head; editing a head after it was streamed cannot change
an earlier emission's count.

## internal/proxy

| Upstream | Go | Reason |
|---|---|---|
| The pending events of `NextLayer` and TLS receive buffers have no explicit recording limit (`mitmproxy/proxy/layer.py`, `mitmproxy/proxy/layers/tls.py`). | A recording connection retains at most 128 KiB before handover, and refuses a larger lookahead. After recording stops it replays every retained byte and streams without a body-size bound. | Protocol detection must not retain an unbounded amount of network input; protocol-specific sniff limits may be smaller. |
| `TimeoutWatchdog.watch` checks whether it is armed before sleeping, but does not recheck after the sleep; a previously scheduled timeout can fire during a long hook (`mitmproxy/proxy/server.py`). | Disarming invalidates the pending timer. Expiry checks the disarm counter and timer generation again before cancelling the connection. | Hook execution and intercepted-flow waits must not count as connection idle time. |
| Injected messages are queued without a bound and without a size limit (`mitmproxy/proxy/events.py`, `mitmproxy/addons/proxyserver.py`). | A handled connection holds at most 64 undelivered injections, cloned when queued. TCP and WebSocket payloads are limited to 128 KiB; UDP payloads are limited to 65,507 bytes and remain whole datagrams. Message/flow compatibility, explicit identity and direction, and live ownership are validated. Rejections carry an `InjectionError` reason and are returned to the caller. | Injection runs under the dispatch lock, so delivery must never block on a layer or grow a stalled connection's retained queue without bound. Protocol-specific types and limits prevent a queued message from being delivered to the wrong owner. |

Injection rejections are discriminable through `errors.Is` and their typed reason, without parsing diagnostic text.
A closed injection also matches `net.ErrClosed`; `Handler.Inject` adds `ErrFlowNotLive` for ended flows or connections.

## master startup

| Upstream | Go | Reason |
|---|---|---|
| Startup errors raise `SystemExit(1)` (`mitmproxy/addons/errorcheck.py`). | `Master.Run` returns `*master.ExitError`, whose `ExitCode()` is 1, without exiting the process. | Embedders and tests need to observe failure; the executable owns process exit. |
| Shutdown can leave an asyncio server-setup task pending for the event loop to cancel (`mitmproxy/master.py`). | Shutdown cancels and joins the setup goroutine outside dispatch before returning. | Goroutines have no event-loop teardown and must not leak. |
| An event-loop exception handler reports unhandled task errors (`mitmproxy/master.py`). | Addon errors and panics are handled by the addon manager; there is no global goroutine panic handler. | Go has no equivalent of asyncio's task exception callback. |

## internal/proxy/layers/tlslayer

| Upstream | Go | Reason |
|---|---|---|
| TLS ClientHello receive buffers have no explicit byte cap (`mitmproxy/proxy/layers/tls.py`). | ClientHello collection is bounded independently at 128 KiB of wire bytes, including record headers, and 64 KiB of reassembled handshake bytes, including the handshake header. The collector returns a limit error when either bound is exceeded. | Bound retained network input even when a small handshake is fragmented into many records. |
| TLS connections are half-closed with a bare TCP FIN (`mitmproxy/proxy/layers/tls.py`). | The TLS transport sends `close_notify`, then FIN; reads remain available. | Go's `tls.Conn.CloseWrite` sends `close_notify`; peers see a clean TLS shutdown. |
| Handshake failures are explained by matching OpenSSL error identities, falling back to `OpenSSL <repr>` (`mitmproxy/proxy/layers/tls.py`). | The same explanations are produced from the `crypto/tls` error identities: a TLS record header whose first four bytes are ASCII yields `The remote server does not speak TLS.`, a version negotiation failure yields the `tls_version_server_min` guidance, and an unexplained error keeps Go's own error text. | Go's TLS stack reports these conditions through typed errors rather than OpenSSL error tuples. |
| `Certificate verify failed:` is followed by OpenSSL's verify result string (`mitmproxy/proxy/layers/tls.py`). | The prefix is followed by Go's `x509` verification error text, for example `x509: certificate is valid for example.com, not wrong.host`. | The verification detail comes from the verifier in use; the Go text names the same cause. |
| A server may request client authentication after the TLS 1.3 handshake; mitmproxy completes it (`test/mitmproxy/proxy/layers/test_tls.py` `test_post_handshake_authentication`). | Go's `crypto/tls` does not advertise `post_handshake_auth`, so a conforming server never requests it; a request sent anyway is a fatal record error reported as below. | Go's `crypto/tls` accepts only `NewSessionTicket` and `KeyUpdate` after a TLS 1.3 handshake and rejects a post-handshake `CertificateRequest`. |
| A failed post-handshake SSL read logs `TLS Error: ...` without firing another handshake-failed hook (`mitmproxy/proxy/layers/tls.py`). | The same log is emitted before the fatal record error closes that direction of the relay. Once both directions close, TCP emits `tcp_end`, not `tcp_error`; no second TLS failure hook is fired. | Go's `crypto/tls` enters a permanent read-error state after a fatal record error, so continuing to read cannot succeed. The native relay reports that error as a directional close rather than reproducing OpenSSL's BIO event loop. |
| `mitmcert` is set by the tlsconfig addon for every client handshake (`mitmproxy/addons/tlsconfig.py`). | The layer records the presented certificate from the handshake's `LocalCertificate`; a resumed session presents none, so the previous value is kept (nil when there was none). | Go's `crypto/tls` reports the local certificate only for full handshakes; wrapping the user-supplied `GetCertificate` callbacks just to observe the choice would change configuration semantics. |
| A late DTLS alert or application-data datagram readmitted after tuple eviction can open another origin session (`mitmproxy/proxy/layers/tls.py`, `ServerTLSLayer`). | A first datagram with a DTLS alert, change-cipher-spec or application-data version prefix is discarded before opening an origin session. New ClientHello messages and plain UDP to a DTLS origin remain admitted. | A stale post-handshake record cannot start a new session; avoid spurious origin handshakes when an evicted tuple is recreated. |

## internal/proxy/layers/modes

| Upstream | Go | Reason |
|---|---|---|
| Reverse mode accepts `http3`, `quic`, and `dns` targets (`mitmproxy/proxy/layers/modes.py`, `mitmproxy/addons/next_layer.py`). | Building the reverse top layer rejects these schemes with an error naming the scheme and the required QUIC and DNS protocol support. | QUIC, HTTP/3, and DNS protocol layers are not available yet. |

## addons/errorcheck

| Upstream | Go | Reason |
|---|---|---|
| The constructor installs a process-global Python logging handler (`mitmproxy/addons/errorcheck.py`). | The application explicitly composes `LogHandler()` into its logger. Collection is synchronous and mutex-protected, independent of the bounded `add_log` queue. | Embedders own logger configuration, and dropping a startup error could allow an invalid startup to succeed. |
| Repeated errors use Python's log formatter, and terminal summaries may use red ANSI text (`mitmproxy/addons/errorcheck.py`). | Summaries are plain text; repeated messages preserve their text and append any structured slog attributes in text-handler format. | No Python logging formatter or implicit terminal capability detection in the library. |

## addons/readfile

| Upstream | Go | Reason |
|---|---|---|
| `ReadFileStdin` reads `sys.stdin.buffer` and leaves it open; the reading task is abandoned to the event loop on shutdown (`mitmproxy/addons/readfile.py`). | `-` reads the stream configured as `Config.Stdin` (`os.Stdin` by default) and owns it: the done hook closes it to release a blocked read and joins the loading goroutine, and loading closes it when the stream ends. | A goroutine blocked in a read cannot be abandoned like a cancelled asyncio task; it must be unblocked and joined before shutdown completes. |
| `Cannot load flows:` is followed by Python's `OSError` text (`mitmproxy/addons/readfile.py`). | The same prefix is followed by Go's `*os.PathError` text. | The failure detail belongs to each runtime, as with the flow-file error texts under [flowio](#flowio-and-flowiotnetstring). |

## addons/keepserving

| Upstream | Go | Reason |
|---|---|---|
| `keepgoing` calls the replay and connection commands unconditionally, so it needs their addons loaded (`mitmproxy/addons/keepserving.py`). | Unregistered commands and options count as idle and unconfigured; a `keepgoing` command failure also counts as idle. | mitmdump must exit after a file read before the replay addons exist in the port. |
| The watch task is abandoned to the event loop on shutdown (`mitmproxy/addons/keepserving.py`). | The done hook cancels the watcher and joins it outside dispatch. | Goroutines must not leak past shutdown. |

## master flow loading

| Upstream | Go | Reason |
|---|---|---|
| Reverse retargeting of a manually constructed HTTP flow without a request raises `AttributeError` (`mitmproxy/master.py`). | `LoadFlow` returns an error. | Invalid Go values must not panic; flow files contain requests. |

## addons/onboardingapp

| Upstream | Go | Reason |
|---|---|---|
| Certificate and cached Magisk files are read without a size limit (`mitmproxy/addons/onboardingapp/__init__.py`). | Download files larger than 8 MiB return 500. | Bound memory when reading configuration-directory files for an HTTP request. |
| Flask supplies route, missing-file and method-error pages (`mitmproxy/addons/onboardingapp/__init__.py`). | `net/http` supplies routing and plain-text error pages; successful certificate bytes, download filenames and content types are unchanged. | No embedded Flask runtime. |

## addons/apphost

| Upstream | Go | Reason |
|---|---|---|
| Hosts ASGI/WSGI callables with an ASGI scope (`mitmproxy/addons/asgiapp.py`). | Hosts `http.Handler` with a private `http.Request` snapshot, outside the dispatch lock. Paths, queries, headers and compressed response bytes follow `net/http` conventions; request paths that `net/url` rejects produce the app-error response. Headers use Go's canonical names and deterministic alphabetical name order; repeated values retain their order. | The approved Go interface is the standard HTTP handler, not a Python application protocol. |
| Response fields are updated while the async app sends events (`mitmproxy/addons/asgiapp.py`). | The response becomes visible atomically after the handler returns and the dispatch lock is reacquired. | Other goroutines must not see partial response construction or race with the handler. |
| The registration name changes if `host` changes (`mitmproxy/addons/asgiapp.py`). | The registration name remains fixed; `SetHost` changes matching only. | Addon removal must use the name recorded at registration. |

## addons/tlsconfig

| Upstream | Go | Reason |
|---|---|---|
| `ciphers_client` and `ciphers_server` accept the full OpenSSL cipher-string syntax: aliases such as `HIGH`, `!`/`+`/`-` operators, `@STRENGTH` and `@SECLEVEL` (`mitmproxy/addons/tlsconfig.py`). | The options accept only colon-separated exact OpenSSL suite names of suites `crypto/tls` implements, mapped through `internal/tlsnames`; anything else fails configure with an `OptionsError` naming the entry. A connection's `Cipher` and `CipherList` fields still record OpenSSL names, as upstream's do. | `crypto/tls` has no cipher-string engine to hand the expression to, and silently approximating an expression would intercept traffic with an unintended cipher set. |
| Without a ciphers option, connections use upstream's own OpenSSL default cipher list, prefixed with `@SECLEVEL=0` for insecure minimum versions (`mitmproxy/addons/tlsconfig.py:48-75`). | Connections keep the `crypto/tls` default suites. Explicit cipher lists restrict TLS 1.0–1.2 only; TLS 1.3 suite selection remains controlled by Go. There are no `@SECLEVEL` mechanics and no `With tls_version_*_min set to ..., ciphers_* must include "@SECLEVEL=0"` warnings. | Go's `CipherSuites` field does not configure TLS 1.3, and security levels are an OpenSSL concept with no Go counterpart. |
| The `tls_version_*` warnings name the OpenSSL build's supported versions (`mitmproxy/addons/tlsconfig.py:541-558`). | The warnings name `crypto/tls` and its supported versions (`TLS1`, `TLS1_1`, `TLS1_2`, `TLS1_3`). | The version floor comes from the Go TLS stack, not an OpenSSL build. |
| `SSL3` is a selectable bound where the OpenSSL build decides whether it works; `UNBOUNDED` leaves both bounds to OpenSSL (`mitmproxy/net/tls.py`). | `SSL3` clamps to TLS 1.0, the lowest version `crypto/tls` can speak, and logs the unsupported-version warning; `UNBOUNDED` maps to TLS 1.0 as a minimum and TLS 1.3 as a maximum. | Go dropped SSLv3 entirely; the clamp preserves the "as low/high as possible" intent. |
| `tls_ecdh_curve_*` accepts every curve name OpenSSL knows (`mitmproxy/net/tls.py`). | Only `secp256r1`, `secp384r1` and `secp521r1` are accepted; any other name fails configure with an `OptionsError` listing the valid curves. | They are the named curves `crypto/tls` implements. |
| `ssl_verify_upstream_trusted_confdir` is handed to OpenSSL as a hashed certificate directory, loaded lazily per lookup (`mitmproxy/addons/tlsconfig.py`). | Every readable PEM file in the directory is loaded into the verification pool up front; files that hold no certificate are skipped. | Go's verifier takes a pool, not a directory; eager loading keeps the file-system work out of the handshake path. |
| With `client_certs` naming a directory, the file is `os.path.join(dir, server_name + ".pem")` for whatever server name the connection carries (`mitmproxy/addons/tlsconfig.py:319-328`). | Only a file directly inside the directory is used: a server name that would make `<name>.pem` a path with a separator, a `..` element, an absolute path or a NUL is treated as a missing file, so no client certificate is sent. | The server name can come from the client's SNI; it must not select a key pair outside the configured directory. |
| `ssl_insecure` also enables OpenSSL's `legacy_server_connect` (unsafe legacy renegotiation, `mitmproxy/addons/tlsconfig.py:342`). | `ssl_insecure` only disables certificate verification; there is no legacy-renegotiation switch. | `crypto/tls` does not implement insecure legacy renegotiation with servers. |
| DTLS version selection follows the `tls_version_*` bounds through OpenSSL (`mitmproxy/addons/tlsconfig.py`, `mitmproxy/net/tls.py`). | `pion/dtls/v3` negotiates DTLS 1.2 only. Minima `UNBOUNDED`, `SSL3`, `TLS1`, `TLS1_1` and `TLS1_2`, paired with maxima `UNBOUNDED`, `TLS1_2` or `TLS1_3`, are accepted. A `TLS1_3` minimum or an `SSL3`, `TLS1` or `TLS1_1` maximum fails the DTLS connection. Both sides cover all 36 ordered option pairs: 15 accepted and 21 rejected. | The pure-Go DTLS implementation cannot negotiate another version; incompatible bounds fail explicitly rather than silently widening the selected window. |

Automatic ALPN offers and selection honor `http2`. The outer TLS hop of a secure explicit proxy selects HTTP/1
for CONNECT; the tunneled TLS hop may negotiate HTTP/2. Explicit presets and origin negotiation retain upstream
precedence.

The legacy cipher suites and DH parameters that the pyOpenSSL stack supports and `crypto/tls` does not are listed under
["Decided for code that is not written yet"](#decided-for-code-that-is-not-written-yet), because they concern the TLS
layers as much as this addon.

## internal/proxy/layers/websocket

| Upstream | Go | Reason |
|---|---|---|
| Compressed messages retain the plaintext fragment layout emitted by wsproto (`mitmproxy/proxy/layers/websocket.py:167-194`). | Compressed messages are decoded only at FIN and retain one whole-plaintext fragment. Unchanged or same-length edited compressed messages are refragmented from that single fragment, not from their compressed wire layout. | The consumed gows frame API exposes compressed plaintext only when the message is complete; compressed wire lengths cannot stand in for plaintext boundaries. |
| Unknown response extensions are ignored, and permessage-deflate response parameters are finalized without checking the client's original offer (`mitmproxy/proxy/layers/websocket.py:103-121`). | Unknown or unsolicited response extensions are rejected. | RFC 6455 section 9.1 forbids a response extension that the client did not offer. |
| wsproto has no equivalent inbound message-size bound (`mitmproxy/proxy/layers/websocket.py`). | Inbound wire and plaintext messages are each limited to the gows default 32 MiB. | Bound message retention and decompression before addon dispatch. |
| Plaintext fragment history is retained without a separate entry-count limit (`mitmproxy/proxy/layers/websocket.py:167-194`). | At most 131,072 original fragment entries are retained per message; excess sends close 1009 to both peers and records a flow error. | Permit valid 4 MiB messages split into 64-byte fragments, as exercised by Autobahn cases 9.3.1 and 9.4.1, while bounding metadata retained from empty or tiny fragments. |
| Each emitted text fragment is separately decoded with replacement (`mitmproxy/proxy/layers/websocket.py:249-265`), which can corrupt a valid code point split across retained boundaries. | Edited and injected text is validated and sanitized over the complete message before fragmentation. Unchanged valid text preserves its exact bytes and original sizes, including boundaries within a code point. | UTF-8 validity belongs to the complete text message, not each continuation fragment. |
| An empty Close frame is represented by wsproto's reserved 1005 sentinel, and upstream can echo an absent code or 1000 (`mitmproxy/proxy/layers/websocket.py`). | An empty Close payload retains a nil close code in flow metadata and an absent code on the wire. | Do not invent a status code the peer did not send or transmit the reserved 1005 sentinel. |
| wsproto negotiates permessage-deflate offers with a server compression window below 15 bits (`mitmproxy/proxy/layers/websocket.py`, wsproto's `PerMessageDeflate`). | gows declines those offers under RFC 7692 section 7.1.2.1 because Go's `compress/flate` cannot select a smaller compression window. The frozen Autobahn catalogue names exactly 36 such cases as expected `UNIMPLEMENTED`; any other unimplemented case remains a gate failure. | Do not negotiate a compression parameter the implementation cannot honor. The exception is derived from the pinned suite's offers, not observed failures. |

Protocol faults preserve already decoded valid messages and an opposite reader's queued write, then fail immediately
without waiting for an origin echo still in flight. As with upstream mitmproxy's immediate failure, this is not the
behavior of an echo server. The frozen Autobahn expectations therefore accept either `OK` or `NON-STRICT` for cases
3.2, 3.3, 3.4, 4.1.3, 4.1.4, 4.1.5, 4.2.3, 4.2.4, 4.2.5 and 5.15: the preceding valid message's echo may already have
arrived or may still be in flight. All 517 cases still run; no `FAILED` or `UNCLEAN` expectation is permitted.

## internal/proxy/layers/tcplayer

| Upstream | Go | Reason |
|---|---|---|
| Every captured TCP flow receives `tcp_end` or `tcp_error` (`mitmproxy/proxy/layers/tcp.py`). | Every captured flow emits exactly one terminal hook, including on shutdown, idle expiry and cancellation: `tcp_end` for closure or cancellation, `tcp_error` for opening or relay failure. A failed terminal half-close is transport closure; its underlying error remains in the returned error. The hook uses `WithoutCancel`; dispatch then clears `Live`, including on dial failure. An interception retained into or requested during a terminal hook is immediately resumed. | Preserve upstream's terminal-hook lifecycle and release the finished connection. Unlike upstream's suspended hook coroutine, a terminal interception cannot retain a connection owner after its transport has finished. |

## internal/proxy/layers/udplayer

| Upstream | Go | Reason |
|---|---|---|
| Every UDP flow receives `udp_end` or `udp_error`, and a connection-close event emits `udp_end` before clearing `live` (`mitmproxy/proxy/layers/udp.py:44-51,121-126`). | Every captured flow emits exactly one terminal hook, including on shutdown, idle expiry and cancellation: `udp_end` for closure or cancellation, `udp_error` for failure. The hook uses `WithoutCancel`; dispatch then clears `Live`, including on dial failure. An interception retained into or requested during a terminal hook is immediately resumed. | Preserve upstream's terminal-hook lifecycle and release the finished tuple. Unlike upstream's suspended hook coroutine, a terminal interception cannot retain a connection owner after its transport has finished. |

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
| `max_client_connections` | int | `0` | Maximum concurrent accepted clients across all proxy modes; 0 means unlimited. Excess clients are closed before connection hooks and registry entry. |
| `pprof_addr` | str | `""` | Loopback address that serves `net/http/pprof`; empty disables it. |
| `script_max_steps` | int | `0` | Maximum Starlark execution steps per script hook call; 0 means no limit. |

HTTP/1 + TLS proxy core:

| Upstream | Go | Reason |
|---|---|---|
| `next_layer` sniffs client data without a size bound (`mitmproxy/addons/next_layer.py`). | Sniffing stops at 64 KiB of client data for the HTTP host search, and at the ClientHello's declared length capped at 64 KiB. Beyond the cap the connection is relayed as raw TCP and the decision is logged. | Every re-ask of `next_layer` runs under the global dispatch lock, so an unbounded sniff buffer re-scanned on each read would stall every hook. |
| `next_layer` host patterns run on Python's `re`, which has no time limit (`mitmproxy/addons/next_layer.py`). | A host match on the `regexp2` fallback that runs past its 100 ms limit is abandoned and logged once with the option, the pattern and the host. An abandoned `ignore_hosts` match counts as a match (the connection stays ignored), while an abandoned `allow_hosts`, `tcp_hosts` or `udp_hosts` match counts as no match. | The match runs under the global dispatch lock, so backtracking must be bounded; failing towards "ignored" never sends traffic through interception that a slow pattern meant to exclude, and failing towards "no match" keeps allow/tcp/udp lists from widening on a timeout. |
| Message bodies are decoded without a size bound (`mitmproxy/net/encoding.py`). | Decoding on every `Content`/`Text` path is bounded by `content_decode_limit` (table above). The bound is published process-globally (`httpmsg.SetDecodeLimit`): two Masters in one process share it and the last `configure` wins; the `core` addon's `done` restores the 256 MiB default. | A compression bomb decoded under the dispatch lock would stall every hook; the decode paths are package-level functions, so the bound cannot be per-Master. |

TLS and protocol layers:

| Upstream | Go | Reason |
|---|---|---|
| pyOpenSSL can talk to servers that only offer finite-field DHE, SSLv3, RC4, 3DES or export cipher suites, and honours `@SECLEVEL=0`. | Go's `crypto/tls` supports none of these, so `ssl_insecure` interception of such legacy or IoT servers fails. `mitmproxy-dhparam.pem` is written only to keep the configuration directory layout and is never used. | The port uses the standard TLS stack. An OpenSSL- or utls-backed layer is a possible follow-up. |
| — | Go processes ECH before the proxy sees the ClientHello, so without the origin's ECH key only the outer `public_name` SNI is visible. Clients that attempt ECH fail unless `strip_ech` (default true) removed the `ech` parameter from the HTTPS records they resolved through the proxy. | Behaviour of Go's `crypto/tls`. |

## internal/proxy/modeserver

| Upstream | Go | Reason |
|---|---|---|
| Reverse HTTPS opens TCP and UDP listeners (`mitmproxy/proxy/mode_servers.py`, `mitmproxy/proxy/mode_specs.py`). | Reverse HTTPS currently opens TCP listeners only. | The QUIC transport is not implemented yet. |

## addons/proxyserver

| Upstream | Go | Reason |
|---|---|---|
| No global cap on concurrent accepted clients (`mitmproxy/addons/proxyserver.py`, `mitmproxy/proxy/mode_servers.py`). | The Go-only `max_client_connections` integer defaults to 0 (unlimited). A positive cap is shared across all mode listeners; excess clients are closed immediately after accept, warned once, and never registered as active connections. Lowering the cap retains existing clients. | Bound concurrent sockets and handler resources without changing HTTP idle-deadline semantics. |
| `configure` accepts every parseable proxy mode; backends without an implementation fail later, at listen time (`mitmproxy/addons/proxyserver.py`). | `configure` rejects modes whose server backend is not implemented with `Proxy mode <spec> is not supported by mitmproxy-go yet.` | Failing at configure time names the unsupported mode instead of starting a server that cannot serve it. |
| `server_connect` refuses a TCP destination on a listen port only for the four literal host strings `localhost`, `127.0.0.1`, `::1` and the listen host (`mitmproxy/addons/proxyserver.py`). | The TCP dialer's `Control` checks each resolved address actually dialled against the current listeners on the same port: any loopback or unspecified address, the bound address, and, for a wildcard listener, every local interface address. This covers every address spelling, including libc numeric forms, and names that resolve to the proxy, without resolving names twice. The pre-dial host check remains; both checks use upstream's refusal text. Custom dialers must delegate to `ProxyServer.Dialer()` to retain the dial-time guard. | Checking only a host string lets a DNS name or another numeric spelling loop one unauthenticated request into the proxy without end; checking the dialled address also prevents DNS rebinding from bypassing the guard. |
| `inject.tcp`, `inject.websocket` and `inject.udp` only warn when an event cannot be delivered (`mitmproxy/addons/proxyserver.py`). | All three commands are registered. A full injection queue, an oversized message or a wrong message type is returned to the command caller as an error; nonmatching-flow and not-live warnings match upstream. `inject.websocket` defaults its optional `is_text` argument to true. | The bounded injection queue is a deliberate backpressure divergence, and its errors must reach the caller to be actionable. |
| Transparent mode initialises platform redirection at configure time. | Transparent mode is rejected as unsupported. | Original-destination lookup is not implemented yet. |

## addons/export

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| `export.file` creates files with mode 0666 under the process umask (`mitmproxy/addons/export.py:199`). | On Unix, new files use mode 0600 and existing files are narrowed to 0600; symlinks and foreign-owned targets are refused. See [internal/privfile](#internalprivfile) for the Windows caveat. | Exported bodies and headers may contain credentials. |
| `export` returns a Unicode string after surrogateescape encoding and backslashreplace decoding (`mitmproxy/addons/export.py:226-232`). | Returns UTF-8 bytes, replacing each invalid UTF-8 byte with the literal `\xNN`; file exports retain raw bytes. | Go bytes have no surrogate code points; this preserves the upstream display conversion with the command's byte result type. |
| Clipboard support is always imported and runtime failures are logged (`mitmproxy/addons/export.py:207-216`). | `export.clip` is always registered, but without the `clipboard` build tag returns `export.clip: clipboard support is not compiled in (build with -tags clipboard)`. Tagged builds use golang.design/x/clipboard and log runtime errors. | Keep default builds independent of desktop clipboard support. |
| File and clipboard errors contain Python's OS/library diagnostics (`mitmproxy/addons/export.py:205,216`). | Log Go OS/library diagnostics. | Error details come from the runtime and clipboard library in use. |
## addons/modifyheaders

| Upstream | Go | Reason |
|---|---|---|
| `ModifySpec.read_replacement` reads an `@` file without a size limit (`mitmproxy/addons/modifyheaders.py:21-33`). | Replacement files larger than 16 MiB are rejected during configure and on each later read. | Bound memory retained under the addon dispatch lock; file changes still take effect immediately. |
| Invalid file diagnostics include Python's `OSError` details; invalid subject patterns include Python's `re.error` details (`mitmproxy/addons/modifyheaders.py:36-53`). | The `Invalid file path:` and `Invalid regular expression` prefixes are retained; details come from Go's filesystem and the shared Python-syntax regex compiler. | Diagnostics belong to the implementation in use. |
## addons/serverplayback

| Upstream | Go | Reason |
|---|---|---|
| Replay files are read without a combined size or flow-count limit (`mitmproxy/addons/serverplayback.py`, `mitmproxy/io/io.py`). | One file-loading operation accepts at most 512 MiB and 100,000 flows. | Bound memory retained from user-supplied replay files. |
| Matching uses SHA-256 of Python's request-key list repr (`mitmproxy/addons/serverplayback.py`). | Uses the same inputs and Python-compatible list, tuple and byte reprs, including the uppercase method accessor; the key is not persisted. HTTP flows built manually without a request are skipped instead of raising. | Keep the same matching equivalence without a Python runtime; invalid Go values must not panic. |
## addons/view

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| Synchronous Python signals (`mitmproxy/addons/view.py`). | Bounded event channels; overflow closes and removes the subscriber, which must resnapshot. | A slow frontend cannot block the dispatch lock. Channel subscribe/cancel and store access require that lock. |
| `intercept`, `resume` and `kill` are directly dispatched hooks (`mitmproxy/addons/view.py`). | Runtime changes arrive through `update`; direct methods remain available. | The Go core dispatches the shared update hook for lifecycle notifications. |

## addons/eventstore

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| The constructor installs a process-global Python logging handler (`mitmproxy/addons/eventstore.py`). | Entries arrive through the master's existing `add_log` dispatch. | Embedders own logger composition; store mutation remains under the dispatch lock. |
| Synchronous addition and refresh signals (`mitmproxy/addons/eventstore.py`). | Bounded event channels; overflow closes and removes the subscriber, which must resnapshot. Subscribe and cancel require the dispatch lock. | A slow frontend cannot block the dispatcher or retain an unbounded notification queue. |

## addons/cut

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| `cut.save` creates files with mode 0666 under the process umask (`mitmproxy/addons/cut.py:125,136`). | On Unix, new files use mode 0600 and existing files are narrowed to 0600; symlinks and foreign-owned targets are refused. See [internal/privfile](#internalprivfile) for the Windows caveat. | Extracted headers and bodies may contain credentials. |
| `extract` traverses arbitrary Python attributes and formats arbitrary objects with `str` (`mitmproxy/addons/cut.py:48-72`). | Traverses the Go model's exported fields using Python-style names and its explicitly supported computed properties. Unknown attributes return empty text. Nonprimitive model objects use their Go text representation. | Go models do not carry dynamic Python instance attributes or bound Python methods. |
| Clipboard support is always available to import; backend errors use pyperclip text (`mitmproxy/addons/cut.py:150-176`). | `cut.clip` is registered in every build. Without the `clipboard` tag it returns `cut.clip: clipboard support is not compiled in (build with -tags clipboard)`; tagged builds log clipboard-library failures. | Desktop clipboard support remains opt-in. |
| File errors use Python's OS diagnostic text (`mitmproxy/addons/cut.py:147-148`). | Logs Go OS diagnostic text. | The runtime supplies filesystem diagnostics. |
## addons/serversideevents

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| Calling `response` without a response raises `AssertionError` (`mitmproxy/addons/server_side_events.py`). | Returns an error stating that a response is required. | Malformed manually built Go flows should return an error rather than panic. |

## addons/commandhistory

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| History files are read without a size limit (`mitmproxy/addons/command_history.py:38`). | Refuses files larger than 16 MiB before splitting lines; an unsuccessful reload retains current history. | Bound memory used by configuration-file loading under the addon dispatch lock. |
| History text uses Python's default text-file encoding (`mitmproxy/addons/command_history.py:38,46,58`). | Uses strict UTF-8 on every platform. Windows writes retain Python's CRLF newline translation. | A portable, deterministic history-file encoding instead of a process-locale-dependent codec. |
| Append and vacuum create files with mode 0666 under the process umask (`mitmproxy/addons/command_history.py:46,58`). | On Unix, new files use mode 0600 and existing files are narrowed to 0600; symlinks and foreign-owned targets are refused. See [internal/privfile](#internalprivfile) for the Windows caveat. | History can contain sensitive command arguments. |
| Failed writes and deletion log Python exception details (`mitmproxy/addons/command_history.py:48,61,76`). | Preserves `Failed writing to <path>:` and `Failed deleting <path>:` prefixes with Go filesystem details. | Diagnostics belong to the runtime in use. |

## addons/clientplayback

| Upstream | Go | Reason |
|---|---|---|
| The queue and file loads have no combined byte or flow-count bounds (`mitmproxy/addons/clientplayback.py:153,229,285,295`). | At most 100,000 requests are queued; one file-loading operation accepts at most 512 MiB and 100,000 flows. | Bound retained memory from replay commands and user-supplied files. |
| Concurrency `-1` starts an unlimited number of replay tasks (`mitmproxy/addons/clientplayback.py:180-188`). | At most 256 replay requests are active simultaneously. | Bound sockets, goroutines and transport buffers. |
| `replay.client.count` includes the queue and the one scheduler inflight flow, omitting concurrent tasks after launch (`mitmproxy/addons/clientplayback.py:193-194,240-245`). | Counts all queued and active requests until completion. | Keepserving must not shut down while concurrent replays remain active. |
| Only live flows and the scheduler's current inflight flow are refused (`mitmproxy/addons/clientplayback.py:196-198`). | A flow already queued or active is skipped with `Can't replay live flow.` | Avoid simultaneous mutation of the same flow object by separate replay workers. |
| HTTP/2 and HTTP/3 flows pass the replay check (`mitmproxy/addons/clientplayback.py:196-210`). | Saved HTTP/2 requests use the negotiated origin protocol, including conversion to HTTP/1. HTTP/3 remains refused with `Can't replay HTTP/3 flows: HTTP/3 is not supported yet.` | HTTP/2 transport is implemented; HTTP/3 still requires its protocol layer before replay can preserve its semantics. |
| `done` cancels the scheduler only (`mitmproxy/addons/clientplayback.py:166-172`). | Cancels all replay exchanges and joins their workers outside dispatch; synchronous addon removal cancels immediately but cannot join until dispatch is released. | Goroutines and their sockets must not outlive shutdown, and waiting under dispatch would deadlock completion hooks. |

Replay API: `proxy.Replay` takes a `ReplayRunner` supplied as `httplayer.Replay` by the addon, rather than constructing a Python `ReplayHandler` (`mitmproxy/addons/clientplayback.py:85-143`). The explicit runner keeps the proxy package independent of the HTTP layer, whose integration tests import the proxy; hooks and pooled transport behavior are unchanged.
## addons/modifybody

| Upstream | Go | Reason |
|---|---|---|
| `@` replacement files have no size bound (`mitmproxy/addons/modifybody.py`, `modifyheaders.py`). | Uses modifyheaders' 16 MiB replacement-file limit; patterns and transformations use the bounds and engine differences listed under filter/regex. | Bound work under the addon dispatch lock. |
| Replacing a missing streamed body raises `TypeError` (`mitmproxy/addons/modifybody.py:74-85`). | Missing bodies are left untouched. Invalid content encoding returns a hook error without changing the message. | Streamed bodies cannot be modified; preserve their absence. |
| Invalid file and regex errors contain Python exception details (`mitmproxy/addons/modifybody.py:35-39`). | Retains upstream's prefixes, with details from Go's filesystem and shared Python-syntax compiler. | Diagnostics belong to the implementation in use. |

## addons/mapremote

| Upstream | Go | Reason |
|---|---|---|
| URL regex searches and substitutions have no explicit resource limit (`mitmproxy/addons/mapremote.py:64`). | Uses the pattern, subject, template, output and fallback bounds and engine differences listed under filter/regex. Abandoned transformations return a hook error without changing the request. | Bound memory and work under addon dispatch. |
| Invalid regex details come from Python's `re.error` (`mitmproxy/addons/mapremote.py:24`). | Keeps the `Invalid regular expression` prefix and subject repr, with shared compiler details. | The implementation supplies the diagnostic. |

## addons/maplocal

| Upstream | Go | Reason |
|---|---|---|
| Local files are read without a byte bound (`mitmproxy/addons/maplocal.py:139`). | Serves only regular files, capped at 64 MiB; oversized or unreadable files log the upstream warning and continue to later rules. | Bound file reads and avoid ordinary blocking device or FIFO reads under dispatch. |
| Candidate paths are lexically confined, but symlinks may escape the configured directory (`mitmproxy/addons/maplocal.py:41-49,128-139`). | Reads and stats use `os.Root`, refusing symlinks outside the configured directory and absolute symlinks. Relative in-root symlinks are supported. NUL paths are rejected without candidates. Windows reserved device paths are also rejected. | Prevent URL-selected files from escaping the directory, including symlink changes during traversal. |
| Content-Type comes from Python's `mimetypes.guess_type` (`mitmproxy/addons/maplocal.py:134`). | Uses Go's `mime.TypeByExtension`, including the host's MIME database and charset parameters for textual formats. | Use the standard maintained MIME database; host mappings may differ. |
| Synthetic responses identify the server as mitmproxy (`mitmproxy/addons/maplocal.py:133`). | Uses `mitmproxy-go <version>`. | Identify the program serving the local file. |
| Regex and missing-path errors contain Python exception details (`mitmproxy/addons/maplocal.py:31,36`). | Preserves the prefixes and configured subject/path, with Go compiler/filesystem details. Patterns and searched URLs inherit filter/regex's documented bounds and differences. | Resource limits and diagnostics belong to the implementation in use. |

## addons/blocklist

| Upstream | Go | Reason |
|---|---|---|
| Status codes are parsed with Python arbitrary-precision integers (`mitmproxy/addons/blocklist.py:31`). | Preserves Python decimal syntax, but codes must fit Go native int; Unicode digits follow Go tables. | The HTTP response model stores an int; no meaningful HTTP status needs arbitrary precision. |
| Synthetic responses identify the server as mitmproxy (`mitmproxy/addons/blocklist.py:80`). | Uses `mitmproxy-go <version>`. | Identify the program blocking the request. |

## addons/stickycookie

| Upstream | Go | Reason |
|---|---|---|
| Cookie retention is unbounded (`mitmproxy/addons/stickycookie.py:37-39,78`). | The ordered jar holds at most 100,000 cookies and 16 MiB of retained string bytes. At overflow, growing writes are dropped without failing the flow; a warning is emitted once until a deletion or smaller overwrite frees capacity. | Bound traffic-driven state while continuing proxy traffic and allowing cookie deletion. |
| A missing response raises AssertionError, and a bare Domain or Path attribute can cause a later type error (`mitmproxy/addons/stickycookie.py:60-68`). | Missing responses return a hook error. Valueless Domain and Path attributes use the request domain and root path. | Malformed hand-built flows and cookie attributes must not panic. |
| Cookie-domain comparisons use the reference Python Unicode lowercase database (`http.cookiejar`, used by `mitmproxy/addons/stickycookie.py:27-32`). | Uses the pinned x/text lowercase tables, preserving lowercase expansions and contextual mappings. | Unicode assignments can differ between runtime versions. |

## addons/stickyauth

| Upstream | Go | Reason |
|---|---|---|
| Authorization retention by host is unbounded (`mitmproxy/addons/stickyauth.py:35`). | Holds at most 100,000 hosts and 16 MiB of retained string bytes. Overflow drops growing writes without failing the flow and warns once until a smaller overwrite releases bytes. Existing values remain usable; disabling the option retains the jar. | Bound traffic-driven state without turning a retention limit into a flow error. |

## addons/updatealtsvc

| Upstream | Go | Reason |
|---|---|---|
| Alt-Svc substitutions have no explicit size bound and operate on Python header text with surrogate escapes (`mitmproxy/addons/update_alt_svc.py:11-12,33`). | Uses filter/regex's 256 MiB transformation limits and Unicode digit tables. Invalid UTF-8 or an exceeded limit returns a hook error without changing the header. | Bound work under dispatch and retain the shared regex compiler's text contract. |
| A missing response, client connection or listener address raises a Python exception (`mitmproxy/addons/update_alt_svc.py:25,28,31`). | Missing data needed for a rewrite returns a hook error; an invalid stored proxy-mode string is treated as non-reverse. | Malformed hand-built Go flows must not panic; valid flows preserve upstream guards. |

## internal/privfile

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| Recording, export, cut and command-history output opens follow symlinks and preserve existing permissions (`mitmproxy/addons/save.py`, `savehar.py`, `export.py`, `cut.py`, `command_history.py`). | On Unix, `Create` and `Append` refuse final-component symlinks, nonregular files and files not owned by the effective user. The opened descriptor is narrowed to mode 0600 before truncation or the first append write. Overwrite and append content semantics are unchanged. | Output may contain credentials; descriptor checks avoid modifying a substituted symlink target or leaving an existing file readable by other users. Parent directories must be trusted; hard links and already-open descriptors are not revoked. |
| These output paths use ordinary Python file opens on Windows. | Pre-existing symlinks and reparse points are refused with `Lstat` before opening. The check/use window remains, and ACL narrowing is out of scope. Other non-Unix, non-Windows platforms refuse private output as unsupported. | Windows permissions use ACLs rather than Unix modes; the path check is not a race-free descriptor validation. |
