# Behavioural differences from mitmproxy

This page lists every place where the Go port behaves differently from upstream mitmproxy (commit `3368a0a`, see the
README) on purpose. It is written for a reader who knows mitmproxy. Each table names the upstream behaviour with the
file it lives in, the Go behaviour, and the reason. Paths without a prefix are relative to the upstream repository root
(`mitmproxy/...`).

The tables cover the code that exists today and explicitly distinguish reserved options from registered runtime
behaviour. Where a package reproduces an upstream oddity on purpose, it is listed under "Reproduced on purpose"
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
| `done` terminates browsers and removes temporary profiles (`mitmproxy/addons/browser.py:227-233`). | Reapers wait outside dispatch and then remove profiles; asynchronous cleanup-error logging uses a detached five-second dispatch budget. | Cleanup errors must not be lost solely because the caller is cancelled. This does not make process Wait/profile deletion interruptible. |

## addons/dumper

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| DNS answers render through `ResourceRecord.__str__`: A/AAAA addresses, NS/CNAME/PTR domain names, TXT text, HTTPS record JSON, hexadecimal for other types (`mitmproxy/dns.py:74,153-169`). | Decodes all these display types, including the ordered Python dictionary representation of HTTPS parameters and numeric unknown keys. Invalid known data keeps the upstream hexadecimal diagnostic. HTTP/3 and mixed-version exchanges retain version labels and canonical response reason phrases. | Pinned Python measurements and dumper tests verify these outputs; shared string-escaping differences remain documented under internal/strutil. |
| Message content is always coloured by syntax-highlight tag through `CONTENTVIEW_STYLES`, whatever its size (`mitmproxy/addons/dumper.py:38-45,130-140`). | Content is coloured the same way. When the highlighter refuses the input as too large or runs past its deadline (see [contentviews/highlight](#contentviewshighlight)), the whole content is printed without syntax colours: nothing is dropped and no partly coloured prefix is shown. Any other highlighter error still fails the output. | Colouring is optional, but the content must always be shown. |

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

| Upstream | Go | Reason |
|---|---|---|
| DNS wire and expanded record data are parsed through Python helpers (`mitmproxy/dns.py`, `mitmproxy/net/dns/domain_names.py`). | Wire messages are capped at 65,535 bytes; decoded names and RDATA share a 1 MiB expansion budget. Compression pointers are iterative, backward-only and work-bounded. | Bound untrusted decoding. Codec round-trip, malformed-pointer, expansion and fuzz tests verify these limits. |
| Domain names use Python's IDNA 2003 codec and Unicode 3.2 nameprep tables (`mitmproxy/net/dns/domain_names.py`). | Uses x/net/idna UTS #46 transitional processing. Later assignments can differ: U+1E9E maps to `ss` rather than `xn--kkg`. | Use the maintained Go IDNA implementation; `TestIDNAMappings` records the difference. |

Test fixtures for socket-backed DNS resolver origins, mode-server DNS listeners
and origins, DNS-layer UDP sessions, and packet-factory shared-port rows acquire
live TCP/UDP pairs through `freeport.ListenPair`
(`internal/netutil/freeport/pair.go`). This test-side acquisition returns
caller-owned sockets on the same host and port; production listeners do not use
the helper. DNS mode fixtures transfer sockets through the existing private listen
seams; single-protocol fixtures close the unused mate. Packet-factory binding rows
release the UDP mate before exercising the existing binder against the retained
TCP port.

On Windows IPv4, the helper's port-zero selection avoids the union of the TCP and
UDP excluded port ranges within their dynamic-range intersection. Range discovery
is cached once per process. Exclusion discovery is all-or-fallback: if either
protocol's command or parsing fails, both exclusion tables are discarded. The
helper then tries at most 64 distinct randomized candidates with real bind checks;
unavailable dynamic bounds use the IANA range 49152–65535, retaining exclusions
only when both exclusion tables were successfully discovered. Partial pairs close
before retry, and only a requested port zero permits reselection. Windows
`ListenPair` tcp6 acquisition also uses distinct randomized IANA-range candidates,
without querying or applying IPv4 exclusion tables. Non-Windows acquisition stays
native. Windows product IPv6 selection remains native, not randomized.

Production standalone DNS, reverse DNS and reverse HTTPS use the Both binder,
which now consumes freeport's candidate-selection policy, not `ListenPair`'s
paired-socket acquisition. On Windows, requested port zero selects shared IPv4
candidates only for an explicit IPv4 literal or empty-host wildcard, without an
added DNS lookup. The same dynamic-range intersection, exclusion union and
all-or-fallback discovery boundary described above apply. Selection is bounded
by 64 distinct candidates and may exhaust; a selected number is not reserved and
real binds may still fail. Modeserver owns the complete socket set, binds TCP
first, closes partial sets before reselection, and activates factories only after
acquisition succeeds.

On the Windows candidate-selected path only, Both retries TCP bind failures
matching native WSAEADDRINUSE/10048 or WSAEACCES/10013 through `errors.Is`,
closing the partial socket set before selecting the next candidate within the
same shared 64-attempt budget. All other TCP errors fail immediately with their
original cause; fixed ports, non-Windows, non-literal hostnames, explicit IPv6
literals and UDP-only modes retain a single TCP attempt where applicable. The
Windows port-zero UDP retry predicate is unchanged: it accepts only those two
native Winsock causes, not Go's Windows `syscall.EADDRINUSE` or
`ERROR_ACCESS_DENIED`. Fixed ports and non-Windows selection remain unchanged.
For empty-host wildcard
binding, tcp4 selects the number and tcp6 follows it under the existing fallback
rules; the full TCP set must share a number before UDP acquisition. This does not
apply IPv4 exclusion tables to IPv6. Every non-literal hostname, including one
with only IPv4 DNS answers, and explicit IPv6 literals, including zone-bearing
addresses, retain native port-zero selection. UDP-only modes also retain their
native path without a TCP mate. These paths remain susceptible to native
selection failures. Requested-port diagnostics still report zero rather than the
candidate. None of this guarantees product bind success or establishes native
local-mode acceptance.

The native Windows evidence manifest preserves every existing row, including
all DNS resolver tests, and appends one freeport candidate-contract row and one
Both/Packet regression row, each at count 20. The unchanged producer collects
all rows in one dispatch with `-cpu=1,2,8`, expecting 60 executions per selected
top-level identity in each added row and checking full freeport inventory
coverage. The rows specify collection, not completed native evidence or measured
timing: the final native producer and Linux campaign have not run yet.

## flowio

| Upstream | Go | Reason |
|---|---|---|
| `flow_to_json` includes DNS request and response JSON (`mitmproxy/tools/web/app.py`). | `flowjson.Flow` includes the DNS view, including ordered HTTPS parameters. Unknown service-parameter keys use decimal string keys in JSON. | JSON object keys are strings; DNS view/flowjson fixture tests cover the representation. |
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
| Hooks are serialized by the asyncio event loop (`mitmproxy/addonmanager.py`). | Cancellation refuses new dispatch admission and cancelled reacquisition after `Concurrent`. A lost frame skips later handlers, updates and finish callbacks without releasing another hold. | Preserve single-owner addon state without publishing cancelled work. Callback, child-process, filesystem and kernel-I/O interruption is not guaranteed. |

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
| The MsgPack view cannot decode bin8, bin16 or bin32 values, and reads a `!!binary` scalar in edited YAML as a string (`mitmproxy-rs/mitmproxy-contentviews/src/msgpack.rs:17-38`). | Binary values render as `!!binary <base64>` and re-encode to bin; invalid base64 is an `Invalid YAML` error. Whitespace inside the value is removed only in literal and folded block scalars. A quoted or plain value keeps its bytes, and a line break in it is an error. | Binary data must survive a view-and-edit round trip as binary, and `!!binary` is the standard YAML tag for it. Go's base64 decoder skips line breaks silently, so they are refused where they cannot be block formatting. |
| MsgPack decoding stops after the first value and ignores any bytes after it (`mitmproxy-rs/mitmproxy-contentviews/src/msgpack.rs:17-23`). | Bytes after the first value are refused with `MsgPack decoding: trailing bytes`. | The view must not hide part of the body. |
| MsgPack YAML is written by serde_yaml (`mitmproxy-rs/mitmproxy-contentviews/src/msgpack.rs:23`). | A string that is a lone newline, contains U+2028 or starts with a byte-order mark is spelled differently, for example `\|+` instead of `\|2+`. | Cosmetic spellings of the shared bounded YAML emitter; both read back as the same value. |
| The Protobuf view adds numeric comments such as `!varint` by a regular-expression rewrite of the rendered text, which can also rewrite a string value that looks like one (`mitmproxy-rs/mitmproxy-contentviews/src/protobuf/view_protobuf.rs:22-23`, `yaml_to_pretty.rs`). | The comments are derived from the YAML nodes, so string values are never rewritten. | A string field must display as its own bytes. |
| Protobuf map entries render in an unspecified order (`mitmproxy-rs/mitmproxy-contentviews/src/protobuf/proto_to_yaml.rs`). | Map entries render in ascending key order, and re-encoding writes fields in the order they appear in the YAML. | Deterministic output; an edit is written as the user sees it. |
| Protobuf re-encoding panics on odd-length `!binary` hex and casts field numbers outside 1..2^29-1 to 32 bits (`mitmproxy-rs/mitmproxy-contentviews/src/protobuf/reencode.rs:43-48,76`). | Both are errors. Field numbers inside 1..2^29-1, including the reserved 19000..19999 range, are accepted as the Rust view accepts them. | A malformed edit must fail rather than crash or write a different field number. |
| Editing a Protobuf map field fails with an unknown-key error (`mitmproxy-rs/mitmproxy-contentviews/src/protobuf/reencode.rs`). | The edit is refused with `protobuf map fields cannot be edited`. | The error names the actual limitation. |
| Protobuf errors use the Rust library messages (`mitmproxy-rs/mitmproxy-contentviews/src/protobuf/`). | Error wording differs and never quotes message bytes. A schema parse error can quote an out-of-range numeric literal from the operator's own `.proto` file. | Message bodies can be sensitive; the schema is configured by the operator. |
| Without a schema, proto2 groups are discarded (`mitmproxy-rs/mitmproxy-contentviews/src/protobuf/raw_to_proto.rs`). | The same without a schema. A proto2 group declared in a configured schema renders and re-encodes with its definition, within the same depth and node budget as a nested message. | Show the fields the operator's definition declares. |
| gRPC gzip and DEFLATE messages are decompressed without a size bound (`mitmproxy-rs/mitmproxy-contentviews/src/protobuf/view_grpc.rs:70-84`). | Every decompressed byte of every message in the body is charged to the 64 MiB per-call decompression budget before it is buffered. | A small body must not expand without bound while rendering. |
| A gRPC decompression failure reports the decoder's read error (`mitmproxy-rs/mitmproxy-contentviews/src/protobuf/view_grpc.rs:73-81`). | When the reader and its `Close` return the same error it is reported once; a different `Close` error, such as a gzip checksum failure, is reported beside it. | Report every distinct cause without repeating one. |
| An MQTT remaining length is decoded without comparing it to the bytes present, so `c0 05 01 02` renders as `[PINGREQ]`; a short header, field or length raises `IndexError` or `AssertionError` (`mitmproxy/contentviews/_view_mqtt.py`). | A remaining length that does not match the bytes present is refused, and short headers, fields and lengths are errors. | Fail closed on a malformed packet rather than render it as a valid one. |
| A non-string GraphQL `query` is interpolated into the output or raises `TypeError`, and a non-object batch element raises (`mitmproxy/contentviews/_view_graphql.py:8-15`). | Both are refused with `not a GraphQL message` or `invalid GraphQL operation`. Automatic selection still passes over the view, as upstream does after logging the `TypeError`. | Never render an unescaped non-string value as query text. |
| WBXML renders an unknown tag as `UNKNOWN_TAG_XX` (`mitmproxy/contrib/wbxml/ASWBXML.py:891-892`). | Unknown tags, attributes, global tokens and invalid code pages are refused. | Unsupported forms fail instead of rendering a guessed document. |
| A WBXML multi-byte integer or inline string that runs past the input can block forever on the decoder's queue (`mitmproxy/contrib/wbxml/ASWBXMLByteQueue.py:53,65-77,96`). | Every such read is bounded and returns an error; multi-byte integers are limited to 32 bits. | A malformed body must produce a finite error. |
| `zipfile` lists an archive whose disk number is not zero (`mitmproxy/contentviews/_view_zip.py`). | Any nonzero disk number is refused with `multidisk ZIP is not supported`. Error text for other refused archives also differs from Python's. | Multi-disk archives are not supported. Refusing loses only the listing of a malformed archive and reads nothing more. |
| The HTTP/3 view keeps per-flow connection state in a dictionary that holds each flow for the life of the view (`mitmproxy/contentviews/_view_http3.py:72-95`). | Each render replays the flow from its first message up to the selected one, bounded at 64 MiB of replayed bytes and 1,000,000 nodes. No flow is retained between renders. | No unbounded cache of flow pointers; the cost per render is linear in the flow. |
| HTTP/3 HEADERS are decoded by pylsqpack, and a failure is shown as `HEADERS Frame (error: …)` (`mitmproxy/contentviews/_view_http3.py:31-37`). | The existing QPACK codec decodes static and literal fields. A block that references the dynamic table, or fails to decode, is shown as the error line and hex; the error detail differs from pylsqpack's. | Reuse the port's QPACK codec for static and literal fields; dynamic-table state is not reconstructed. |

Reproduced on purpose (compatibility, not differences):

- MsgPack: a plain leading-zero decimal such as `010` re-encodes as the string `"010"`, as the Rust view does over serde_yaml.
- Protobuf: elements of a repeated group or repeated message re-encode without the definition, so field names inside them do not resolve (`unknown protobuf field key`); a group closes at its first end tag whatever its field number, as in the rust-protobuf runtime.
- gRPC: `grpc-encoding` is matched exactly against `identity`, `gzip` and `deflate` (`mitmproxy-rs/mitmproxy-contentviews/src/protobuf/view_grpc.rs:24,71-84`). Any other value, including a different case, an empty or missing header and two headers joined as `gzip, identity`, refuses a compressed message with no output; the error reads `unsupported gRPC compression` without the value. An uncompressed message ignores the header. gzip reads one member and ignores trailing bytes, raw DEFLATE accepts trailing data, re-encoding writes every message uncompressed, and an empty or comment-only YAML stream is `YAML is not a mapping`.
- Socket.IO: the view follows the pinned parser, not the full Socket.IO grammar (`mitmproxy/contentviews/_view_socketio.py:56-67`). The namespace, attachment count and ack id after the packet-type digits are shown as payload, so `42/admin,1[…]` renders as `SocketIO.EVENT /admin,1[…]`. Payload bytes are escaped as the Python views display bytes.
- MQTT: CONNECT shows the user name and password; a client id whose bytes are the text `None` looks the same as an absent one; the protocol name and level are not validated; a PUBLISH with QoS 3 shows its packet identifier as payload (`mitmproxy/contentviews/_view_mqtt.py`).
- WBXML: elements left open at the end of input are closed; a non-empty string table is refused; CDATA containing `]]>` is refused, as Python's `xml.dom.minidom` refuses to write it; other bytes inside CDATA, including control bytes, pass through as the pinned view writes them (`mitmproxy/contrib/wbxml/ASWBXML.py`).
- ZIP: only file names are listed and no entry is opened. An archive with an inconsistent end record or central directory, an extra field shorter than its header, a signature record that overruns the directory, or an invalid UTF-8 name is refused, as `zipfile` refuses it, even where Go's `archive/zip` would accept it.
- HTTP/3: unknown and grease frame types are listed with a hex payload; a frame longer than the bytes available is omitted; a truncated variable-length integer renders `Read out of bounds` (`mitmproxy/contentviews/_view_http3.py:25-52,121-122`).

The shared adapters for new binary/YAML contentviews use per-call budgets:
64 MiB encoded input, output and retained materialization; 1,000,000 logical
nodes or effective alias work; and nesting depth 64. The decompression budget
is also 64 MiB per call; multi-frame and fallback consumers must keep the same
budget. These limits are independent of the existing process-wide
`content_decode_limit` option; they do not change that option or the existing
views' behavior. The adapters alone do not register new views.

YAML is scanned by the same native parser before a loader is constructed.
Mapping keys and values, document/container/scalar nodes and alias expansion
work count against the shared budget. Anchor metadata is limited to 65,536
distinct entries per document in addition to its byte budget. Over-budget
input returns a typed `LimitError`, and failed attempts do not restore spent
work. Output goes through a bounded writer; partial output is discarded.

The local protobuf schema adapter accepts only explicitly configured source
roots and built-in standard descriptors. It allows at most 1,024 source files,
16 MiB per source file, 64 MiB total source bytes, and directory/import depth
64. Imports cannot escape the configured roots; no network resolver or protoc
process is used. Subsequent calls reload changed sources rather than using a
permanent global schema cache.

## contentviews/highlight

| Upstream | Go | Reason |
|---|---|---|
| The CSS, JavaScript, XML and YAML highlighters lex any input to completion, with no size or time bound (`mitmproxy-rs/mitmproxy-highlight/src/lib.rs:22-37`). | Input above 256 KiB returns `ErrInputTooLarge` before lexing. Lexing that has not finished after 250 ms returns `ErrTimeout`, and the lexer stops at the next token. Callers match both errors with `errors.Is` and should show the whole text without syntax styling. Under the race detector only, the deadline is ten times longer (2.5 s). The `none` and `error` languages are unaffected. | The Go highlighter uses Chroma's regular-expression lexers, which take quadratic time on some inputs (measured: 0.18 s, 0.71 s and 2.8 s for 1,000, 2,000 and 4,000 repeated pairs), unlike the upstream Rust lexers. A body from the network must not stall rendering. Race-instrumented test builds lex ordinary inputs about thirty times slower, so only they get the longer deadline. |
| The highlighters have no panic handling of their own (`mitmproxy-rs/mitmproxy-highlight/src/lib.rs`). | A panic inside a Chroma lexer is logged with the language and the panic value's type, without the input text, and then re-raised. | Lexer bugs can be diagnosed without copying a possibly sensitive body into the log; the panic is not swallowed. |

## tlsparse

| Upstream | Go | Reason |
|---|---|---|
| `get_client_hello` and `parse_client_hello` reassemble a handshake message of any declared length, up to the 16 MiB a 24-bit length allows (`mitmproxy/proxy/layers/tls.py`). | A handshake message longer than 65,536 bytes, its 4-byte header included, is refused with `ErrTooLarge` as soon as its length is known, before its bytes arrive. | Every re-ask of `next_layer` runs under the global dispatch lock, so ClientHello reassembly must be bounded. |
| `ClientHello.raw_bytes(True)` raises `OverflowError` for a body longer than 65,531 bytes, whose record length does not fit 16 bits (`mitmproxy/tls.py`). | `RawBytes(true)` returns nil for such a body. | Go methods do not raise; the largest accepted handshake body (65,532 bytes) cannot fit in one synthetic record. |
| `ClientHello.raw_bytes` raises `NotImplementedError` for a DTLS ClientHello in both wrapping modes (`mitmproxy/tls.py`). | `RawBytes(false)` returns the exact DTLS handshake body; `RawBytes(true)` returns nil. `IsDTLS` lets callers distinguish this case before wrapping. | Expose the received body without fabricating a TLS record that misrepresents DTLS framing. |
| QUIC ClientHello sniffing delegates Initial decryption/reassembly to aioquic (`mitmproxy/proxy/layers/quic/_client_hello_parser.py`). | QUIC v1/v2 sniffing uses Go packet protection and sparse CRYPTO reassembly. Datagrams are capped at 65,535 bytes, input datagrams and disjoint fragments at 256 each, and complete handshake/offsets at `MaxClientHelloSize`. Conflicting overlaps fail; missing sparse bytes are never allocated. | Bound work and retained bytes during protocol selection under dispatch; this is a sniffer, not a transport endpoint. |

Reproduced on purpose (compatibility, not differences): the handshake message type is not checked; the extensions are
read to the end of the message whatever length their field declares; the server_name and ALPN extensions are read to the
end of their bodies whatever list length they declare, and an empty or truncated one makes the whole ClientHello
invalid; an odd cipher suite length leaves its last byte to be read as the compression methods' length.

DTLS sniffing also follows upstream's ordered record concatenation (`mitmproxy/proxy/layers/tls.py:94-160`):
records are read in arrival order and the first handshake header's fragment length is used. The ClientHello sniffer
does not reorder fragments or deduplicate retransmissions; pion handles retransmissions in the subsequent handshake.

## internal/tools/console

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| urwid widgets run on the Python event loop (`mitmproxy/tools/console/master.py`, `window.py`). | One Bubble Tea program renders owned snapshots. Live flow/option access and mutations run through the master dispatcher; widgets do not retain borrowed flow pointers outside dispatch. | Keep proxy hooks independent of terminal redraws and avoid data races. |
| Console commands update event-loop state synchronously (`consoleaddons.py`). | Command-visible pane, tab, option and binding state changes synchronously under dispatch; immutable, sequence-numbered effects install later in the UI. A shared 256-credit pool bounds pending effects and returns a busy error when admission is unavailable. | Preserve same-dispatch read-after-write behaviour without waiting on terminal input or rendering under the dispatch lock. |
| Display options are consumed by widgets on the event loop (`consoleaddons.py`, `window.py`). | The options store owns layout/header/mouse values; a queued display effect rebuilds panes and updates derived control mirrors. An option update can commit before presentation capacity is available: the latest pending display request is retained until credit release or the next successful command admission. An ordinary busy error does not roll back committed option values. | Do not lose a configured display change or make the UI a second option owner. |
| Redraw signals refresh the event-loop widgets (`signals.py`). | One background snapshot is in flight, with retained dirty generations. Background traversals start at least 16 ms apart; viewport requests share the admission credit. The ordered view traversal is O(n); row rendering and hit-testing are bounded by the viewport. | Coalesce notifications without losing updates or starting a traversal/goroutine for every flow. |
| `keys.yaml` is loaded through the Python keymap loader (`keymap.py`). | The whole file is validated before bindings are replaced atomically. Limits are 1 MiB input, depth 32, 65,536 expanded logical nodes including aliases and 4,096 bindings. Cycles, invalid contexts/UTF-8 and accounting overflow fail before installation. Missing/nonregular paths remain no-ops. | Bound configuration work before YAML composition and prevent partially applied keymaps. |
| External editor/viewer and grid work is invoked through the console (`master.py`, `grideditor/`). | File and child-process work runs outside dispatch. A fresh dispatch checks the captured stable flow ID, message part and field fingerprint before committing; a changed/removed target reports a conflict rather than overwriting newer data. | Do not hold proxy dispatch during operator input or overwrite concurrent hook changes. |
| Editor/viewer commands come from the environment (`master.py`). | Configured argv is parsed and launched directly, without implicit shell expansion. Private temporary files and owned child processes are cleaned up; viewer results do not commit edits. Edited final components must be regular, nonsymlink files; explicit grid outputs use the existing owner-only private-file policy. | Retain operator-selected tools without turning captured content into shell syntax or redirecting private output. |
| Widgets render message and status text (`common.py`, `statusbar.py`). | Untrusted controls are escaped before trusted styling is attached. Width/cursor operations respect grapheme boundaries. Highlighter refusal falls back to escaped, unstyled content rather than dropping it. | Keep captured traffic from controlling the terminal while preserving readable content. |
| Protocol flow summaries carry per-token method, status, URL, content-type, focus, interception and error palette attributes (`common.py`). | Flow-list rows and the flow-view header currently render in the text colour. Headings, status, quick-help keys and commander tokens retain palette styles. | Per-token flow styling is a named follow-up; the six frozen frame expectations are regenerated under independent review when it lands, never automatically in CI. |
| Request/response newline trimming is configurable (`consoleaddons.py`). | `console_strip_trailing_newlines` retains that behaviour; the source's separate URL and stream-message final-newline rules remain separate. | Do not turn an editing option into an unrelated byte rewrite. |
| Startup requires interactive output and checks the console encoding (`master.py`). | Nonterminal stdout is refused. A non-UTF Unix locale warns and continues using UTF-8. Windows has compile-only evidence pending native terminal acceptance. | Preserve startup diagnostics and state the tested platform boundary explicitly. |
| SIGINT asks for confirmation and SIGTERM requests shutdown (`mitmproxy/tools/main.py:117–129`). | SIGINT opens the anchored Quit confirmation prompt; confirming it exits successfully. SIGTERM requests orderly shutdown. Both paths restore persistent terminal modes and join the owned program and senders. | Keep the operator confirmation policy while separating transient kernel pending-input state from actual terminal modes. |
| The Python main loop owns terminal shutdown (`master.py`). | With terminal ownership, the assembled master requests orderly program Quit and joins it before cancelling the bridge and its senders; a five-second last-resort Kill is exceptional, not normal cleanup. `Master.NewModel` and `Master.NewProgram` are mutually exclusive presentation selections; a NewModel harness owns its own program Quit/join. Standalone `NewProgram` defaults to the bridge context, whose cancellation uses Bubble Tea's kill path; callers should Quit and join before closing that lifetime. | Avoid racing the terminal input reader during ordinary shutdown and keep owned command/process joins outside dispatch. |
| `--set` values/configuration are applied before metadata exits (`mitmproxy/tools/main.py:24–26,85–103`); TLS configuration opens the CA store in the selected confdir (`mitmproxy/addons/tlsconfig.py:471–486`). | Constructing the console master itself performs no I/O. Applying explicit configuration can initialize CA files in the selected confdir before `--version`, `--options` or `--commands` output. | Preserve configuration ordering without incorrectly describing metadata paths as never initializing a CA. |
| urwid invalidates its cached dimensions on resize and queries the current size when that cache is absent (`urwid/event_loop/main_loop.py`, version 4.0.13). | Known startup-size deviation: Bubble Tea v2.1.0 captures startup dimensions and sends them asynchronously. A stale startup size can arrive after a newer resize; the console installs sizes in delivered order and the next real resize corrects them. | Startup size messages have no freshness sequence; frozen frame tests do not prove that this race is fixed. |
| Upstream Python can upgrade the console integration fixture `dumpfile-7.mitm`, which uses flow format 11. | The Go reader supports formats 18–21, not 11. Console integration uses a reproducibly transcoded current-format copy with pinned input/output digests; no legacy reader support was added. | Preserve the existing codec compatibility boundary rather than implying that the console extends it. |
| Bindings can invoke clipboard and script commands. | Clipboard uses the existing optional build tag, without an OSC52 fallback. The script prompt targets the registered synchronous `script.run` command of the default Starlark loader. | Clipboard remains optional; scripting is registered by the default addon sets. |

### Renderer and terminal evidence boundary

The live pinned-Python text-oracle contract covers flowlist, flowview and commander at 80×24 only. Both runtimes
receive the same generated flow file, fixed IDs/timestamps/listen values, UTC timezone, options and keystrokes.
Only CRLF-to-LF transport conversion and removal of trusted renderer controls are permitted; content spacing,
line count, truncation, headers, bodies and hints remain exact. The 200×50 Go frames require independently reviewed
frozen expectations; they are not live-Python 200×50 comparisons. Colour encoding, cursor negotiation/blink and
alternate-screen behaviour have separate style/cursor/terminal observations. Native captured macOS/Linux tmux QA
is distinct from in-memory teatest frames and from compile-only Windows evidence.

Teatest's pinned process-scoped SIGINT listener (`NewTestModel.func2`, blocked at `teatest.go:168`) is the only
explicit third-party allowance in frame-test goroutine checks, counted once per constructor. Product-owned
senders, commands and child processes must still join. The Linux timed-storm helper exits as an owned PTY process;
no process-wide SIGINT is used to clean up in-memory tests.

The timed Linux acceptance uses an owned PTY process and an explicit child CPU profile of one. Its deciding Debian
campaign retains one terminal inventory and five repetitions with all 10,000 distinct flow IDs presented in order,
a complete visible counter, first/last/deep navigation and strict lifecycle joins. Measured flow production took
1,843,930,097–1,861,754,579 ns inside measured update holds of 2,000,052,602–2,001,043,909 ns. These are Debian
measurements, not a hosted-runner timing guarantee. The local cross-worker gate's original SHA256 is
`864ef17f2961971d126405f9f8db6804a4d2ed0f7a45a27cd3f0235b116b85b4`; the Linux wrapper's is
`2caca1f31c087abbc5fd9adb929e625a8f3a62f27dcdf2691eae87fa9db3e85e`, differing only in the lock path.
Dedicated hosted runners do not need that local cross-worker mutex; their own first-pass timing and artifacts
must pass independently before the carrier is relied on.

## internal/tools/web

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| Tornado's static handler derives `Last-Modified` from the file's checkout mtime (`py:mitmproxy/tools/web/app.py:925-928` at `3368a0a`; inherited Tornado 6.5.10 `tornado/web.py:3229-3250`). | The embedded static handler uses the pinned upstream commit timestamp, Unix `1791038697`, for every static asset (`internal/tools/web/assets.go:23-27,153-167`). | Embedded files have zero mtimes; a fixed source timestamp makes validators reproducible across builds and checkouts. |

Reproduced on purpose: the ten static files and index are byte-exact upstream
references with the MIT notice. Static ETags are quoted SHA-512 digests; JavaScript
uses `text/javascript` independently of the host MIME registry. Ordinary static
responses add no explicit `Cache-Control`; a `v` query parameter selects
`max-age=315360000` and `Expires`. Static files remain unauthenticated, as upstream;
index authentication belongs to the composed backend, not `IndexHandler` itself.
The static handler and index remain the same pinned frontend (`py:mitmproxy/tools/web/app.py:52-55,361-368,925-928`
at `3368a0a`; `internal/tools/web/assets.go:23-24,31-112`, `assets.tsv:1-16`, `UPSTREAM_LICENSE:1-19`).

### Routes and metadata

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| The API Server header identifies mitmproxy (`py:mitmproxy/tools/web/app.py:300-312` at `3368a0a`). | Identifies mitmproxy-go; the other security headers retain upstream values (`internal/tools/web/routes.go:136-141`). | Name the implementation serving the response, without normalizing response bodies. |
| Malformed JSON reports Python parser line/column wording; non-object option updates report Python's keyword-argument error (`py:mitmproxy/tools/web/app.py:314-323,805-814` at `3368a0a`). | The same 400 status uses the Go JSON parser's byte offset or JSON-kind diagnostic (`internal/tools/web/errors.go:99-125`, `routes.go:298-309`). | Diagnostics describe the parser actually used; there is no broad diagnostic exclusion. |
| With `web_debug`, generic errors render Python/Tornado tracebacks; explicit `APIError` bodies bypass the generic renderer (`py:mitmproxy/tools/web/app.py:354-358,935-936` at `3368a0a`). | Generic errors render Go stack frames, not Python tracebacks, when debug is enabled. The stack contains function/file/line frames, not request lines, headers, cookies, bodies, snapshots or option values. Default debug-off HTML 500 and explicit APIError bodies are unchanged (`internal/tools/web/errors.go:38-97`). | Report the actual runtime without disclosing request values or enabling a frontend build/autoreloader. |

Reproduced on purpose (compatibility, not differences):

| Upstream contract | Go contract | Reason |
|---|---|---|
| `/commands` returns wrapped docstring help, or null when absent (`py:mitmproxy/command.py:77-81`, `py:mitmproxy/tools/web/app.py:758-777` at `3368a0a`). | Removes continuation-line common indentation as Python 3.13 does for docstrings, strips and wraps at 70 columns; empty help serializes as null (`command/command.go:107-145`, `internal/tools/web/routes.go:250-269`). | Preserve help layout and nullable metadata, including the existing CLI help-line layout. |
| `content.data` calls `write(message.get_content(strict=False))`; an uncaptured body is None and produces the generic 500 (`py:mitmproxy/tools/web/app.py:670-688,354-358`, `py:mitmproxy/http.py:390-391` at `3368a0a`). | Missing `RawContent` produces the centralized generic 500, or the Go stack under `web_debug`; a present empty body retains 200, empty `application/text` content and Content-Disposition. POST and contentview paths are unchanged (`internal/tools/web/content.go:91-123`, `errors.go:60-97`). | Reproduce upstream's `write(None)` result without conflating absent and empty bodies. |
| Authenticated `/state` includes mode-server JSON, including client-private-key-bearing `wireguard_conf` (`py:mitmproxy/tools/web/app.py:826-843`, `py:mitmproxy/proxy/mode_servers.py:393-417` at `3368a0a`). | `/state` and `state/update` include the first client's configuration, never the server private key. Treat server snapshots and their Servers maps as secret-bearing: do not log or expose their values outside authenticated readers (`internal/tools/web/routes.go:239-249`, `updates/broadcast.go:97-99`, `internal/proxy/modeserver/wireguard.go:94-108`, `addons/proxyserver/web_state.go:14-28`). | Client configuration parity is intentional; it is not public status metadata. Event identities are described under [addons/eventstore](#addonseventstore). |
| State reports the host platform and local-mode availability; process and icon routes delegate to native process information (`py:mitmproxy/tools/web/app.py:826-879` at `3368a0a`). | Preserves host/effective-UID availability policy (`internal/tools/web/routes.go:165-194,239-249`, `internal/local/spec.go:65-80`). Handler tests and Linux root/nonroot evidence do not certify native process listing/icons on other hosts. Windows remains build/vet-only, with native execution deferred as described under [internal/processinfo](#internalprocessinfo). | Cross-compilation and host-independent HTTP contracts are not native process or driver evidence. |

### Static viewer

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| Updating `web_static_viewer` exports synchronously inside configure (`py:mitmproxy/tools/web/static_viewer.py:108-118` at `3368a0a`). | Configure captures immutable inputs; a single owned worker exports outside dispatch, serializing/coalescing pending work. Runtime completion is asynchronous after the option update. Failures are logged, not raised to that update, and the option is not rolled back. Startup drains before readiness and existing errorcheck decides startup failure (`internal/tools/web/static_viewer.go:37-40,57-207`, `webaddons.go:63-73`). | Filesystem I/O must not hold the shared dispatch lock. An identical successful input is not exported again. |
| Export replaces an existing static subtree and writes files directly with ambient permissions (`py:mitmproxy/tools/web/static_viewer.py:22-38,46-64,114-118` at `3368a0a`). | Requires an absent destination, including refusal of an empty directory, symlink or previous export. Builds a private 0700 sibling stage with 0600 files, validates the complete inventory, then atomically publishes without replacement (`internal/tools/web/static_publication.go:38-101,182-255`, `static_viewer.go:400-417`). | Never expose a partial export or overwrite caller-owned files; updating requires a fresh absent destination. Parents must already exist and be trusted. |
| Direct export has no owner-marker recovery protocol (`py:mitmproxy/tools/web/static_viewer.py:22-38,114-118` at `3368a0a`). | Recovery validates stage name, ownership, exact permissions, a locked marker of at most 4096 bytes, and matching destination/stage fields before removing an abandoned owned stage. It never promotes an incomplete stage, merges destinations or recursively deletes through a replaced parent entry (`internal/tools/web/static_publication.go:104-179,258-310`). | Recover only identified owned staging work; refuse foreign or unrecognized contents. |
| Ordinary Python filesystem operations supply publication behavior (`py:mitmproxy/tools/web/static_viewer.py:22-38,114-118` at `3368a0a`). | macOS uses `renameatx_np(RENAME_EXCL)` and Linux uses `renameat2(RENAME_NOREPLACE)`. Unsupported platforms/filesystems fail without a replacing fallback (`internal/tools/web/static_publish_darwin.go:22-33`, `static_publish_linux.go:22-33`, `static_publish_other.go:13-20`). | Atomic no-overwrite publication is required. Windows compile/static checks are not native export proof. |

Reproduced on purpose (compatibility, not differences):

| Upstream contract | Go contract | Reason |
|---|---|---|
| An absent response object exports `No content.` and its corresponding Auto view; an empty captured message exports empty bytes, while missing message content fails (`py:mitmproxy/tools/web/static_viewer.py:51-95` at `3368a0a`). | Preserves these distinctions. Safe opaque flow-ID components are accepted; repeated IDs retain all flows.json records and the last content payload wins. Empty/dot/dotdot, separators, NUL and escaping paths are refused (`internal/tools/web/static_viewer.go:315-378`). | Keep payload semantics without allowing flow IDs to escape the private export tree. |
| The viewer copies the pinned static frontend and index (`py:mitmproxy/tools/web/static_viewer.py:22-33` at `3368a0a`; upstream `LICENSE:1-19`). | Keeps those bytes and additionally exports the upstream MIT notice at `static/UPSTREAM_LICENSE` (`internal/tools/web/static_viewer.go:290-312`). | Preserve provenance and redistribution notice. |

### Web options

All eight options are functional; their names, types, defaults, help and theme choices retain upstream metadata.
The resource, debug and export differences above do not add option names.

| Option | Type and default | Source |
|---|---|---|
| `web_columns` | sequence of str, `tls, icon, path, method, status, size, time` | `py:mitmproxy/tools/web/webaddons.py:94-99` at `3368a0a`; `internal/tools/web/webaddons.go:44`. |
| `web_debug` | bool, `false` | `py:mitmproxy/tools/web/webaddons.py:91` at `3368a0a`; `internal/tools/web/webaddons.go:41`. |
| `web_host` | str, `127.0.0.1` | `py:mitmproxy/tools/web/webaddons.py:93` at `3368a0a`; `internal/tools/web/webaddons.go:43`. |
| `web_open_browser` | bool, `true` | `py:mitmproxy/tools/web/webaddons.py:90` at `3368a0a`; `internal/tools/web/webaddons.go:40`. |
| `web_password` | str, empty | `py:mitmproxy/tools/web/webaddons.py:30-41` at `3368a0a`; `internal/tools/web/webauth/webauth.go:51-54`. |
| `web_port` | int, `8081` | `py:mitmproxy/tools/web/webaddons.py:92` at `3368a0a`; `internal/tools/web/webaddons.go:42`. |
| `web_static_viewer` | optional str, empty string (not null) | `py:mitmproxy/tools/web/static_viewer.py:100-106` at `3368a0a`; `internal/tools/web/static_viewer.go:52-55`. |
| `web_theme` | str, `system`; choices `system`, `dark`, `light` | `py:mitmproxy/tools/web/webaddons.py:100-106` at `3368a0a`; `internal/tools/web/webaddons.go:45`. |

### Update stream

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| Each connection has an unbounded application send queue (`py:mitmproxy/tools/web/app.py:376-417` at `3368a0a`). | Each `/updates` client has 1024 ordinary FIFO slots. Enqueue never waits for capacity or socket I/O. Overflow selects terminal 1011, stops ordinary admission, allows an already claimed frame to finish, discards backlog and writes Close 1011 before another ordinary message (`internal/tools/web/updates/client.go:23-29,74-98,183-240`). | A nonreader cannot block dispatch or retain an unlimited per-client backlog. A completed graceful close can be peer-observed as 1011. |
| The application queue has no equivalent terminal-write grace (`py:mitmproxy/tools/web/app.py:388-417` at `3368a0a`). | After 15 seconds from terminal selection, a still-blocked or partial transport is aborted and owned workers are joined. The outcome is recorded as transport-aborted/local-1011, separately from peer-observed 1011 (`internal/tools/web/updates/client.go:100-179`). | Bound cleanup without claiming that a local close intent or failed write delivered a wire Close frame. |
| The inherited Tornado WebSocket handler has a default 10 MiB message limit but no separate data-fragment count limit (`py:mitmproxy/tools/web/app.py:376-386` at `3368a0a`; Tornado 6.5.10 `tornado/websocket.py:100,1171-1210`). | Retains the 10 MiB assembled-message ceiling and additionally permits at most 1024 data fragments per message, including empty fragments; control frames do not count. Fragment 1025 closes with 1009 (`internal/tools/web/updates/client.go:23-29,243-313`, `hub.go:139`). | Bound fragment bookkeeping independently of payload bytes; the byte ceiling is unchanged. |

Reproduced on purpose (compatibility, not differences):

| Upstream contract | Go contract | Reason |
|---|---|---|
| The inherited Tornado handler checks `Origin`, falling back to `Sec-WebSocket-Origin` only when absent; missing headers pass and empty Origin fails. The lowercase parsed Origin authority must equal raw Host, including port (`py:mitmproxy/tools/web/app.py:376-386` at `3368a0a`; Tornado 6.5.10 `tornado/websocket.py:256-273,559-566`). | Applies the same comparison, preserving Host case and port rather than normalizing default ports or forwarded hosts (`internal/tools/web/updates/hub.go:126-139,161-175`). | Preserve Tornado's exact Origin contract instead of gows' permissive zero-value Origin policy. |
| Per-client named filters have no count cap; changing a filter scans the current view. WebSocket compression is not enabled (`py:mitmproxy/tools/web/app.py:428-485` at `3368a0a`; inherited Tornado 6.5.10 `tornado/websocket.py:399-421`). | No per-client named-filter cap; filter updates scan the view, and frame writes do not compress (`internal/tools/web/updates/client.go:218,361-379`, `hub.go:132-139`). | This behavior is unchanged. The queue is a per-client message bound, not a global memory or work bound; matching scales with clients, retained filters and affected flows. |

### Authentication

Upstream references in this section use the Python pin `3368a0a`.

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| Hash configuration and verification delegate to argon2/libargon2 (`py:mitmproxy/tools/web/webaddons.py:43-57,75-85` at `3368a0a`). | Accepts only Argon2i/Argon2id version 19, unique decimal `m`, `t`, `p`, `8*p <= m <= 262144` KiB, `t` 1–10, `p` 1–16, decoded salt 8–64 bytes, digest 16–64 bytes, and encoded PHC length at most 1024 bytes. Base64 must be canonical, standard and unpadded. Invalid configuration fails before derivation, without plaintext fallback (`internal/tools/web/webauth/phc.go:33-85`, `webauth.go:82-103`). | Bound configuration-driven decoding and derivation; these are deliberate restrictions on upstream hash acceptance. |
| Verification has no equivalent process-wide concurrent-memory admission budget (`py:mitmproxy/tools/web/webaddons.py:75-85` at `3368a0a`). | Across addon instances and configuration generations, at most two derivations and 262144 KiB aggregate reserved memory are admitted. Exhaustion returns HTTP 503 without queueing or derivation, not an incorrect-password 403. Cancellation is checked before admission; an admitted derivation retains its reservation until it finishes (`internal/tools/web/webauth/phc.go:88-136`, `handler.go:93-100`). | Bound resource use without claiming that x/crypto derivation can be interrupted. |
| Unsafe requests with a present `Sec-Fetch-Site` other than `same-origin` or `none` raise `tornado.httpclient.HTTPError(403)`, not the web error class (`py:mitmproxy/tools/web/app.py:284-290` at `3368a0a`); the pinned Tornado 6.5.10 runtime returns 500. | Returns 403 for `same-site`, `cross-site` and other disallowed values. XSRF is checked first; an absent header is permitted subject to XSRF (`internal/tools/web/webauth/handler.go:37-45`). | Enforce the intended refusal instead of reproducing the upstream error-class mismatch. |

Reproduced on purpose (compatibility, not differences):

| Upstream contract | Go contract | Reason |
|---|---|---|
| A valid signed session takes precedence; otherwise `Authorization: Bearer` precedes the `token` argument. Empty `web_password` generates a random token; the cookie name is `mitmproxy-auth-<web_port>` (`py:mitmproxy/tools/web/app.py:249-278`, `webaddons.py:26-28,43-85` at `3368a0a`). | Preserves that precedence, generated-token URL and port scope (`internal/tools/web/webauth/handler.go:77-117`, `webauth.go:82-131`). Cookies retain Tornado-v2 `y`/HMAC-SHA256 signing, 400-day browser expiry, default 31-day validation, HttpOnly and SameSite Strict (`cookie.go:17-77`). | Existing authentication behavior is unchanged; the PHC resource restrictions above are separate. |
| XSRF uses the readable `_mitmproxy_xsrf` cookie and strict SameSite policy (`py:mitmproxy/tools/web/app.py:383-386,929-934` at `3368a0a`). | Unsafe methods require the decoded token from `_xsrf`, `X-XSRFToken` or `X-CSRFToken` to match the cookie; masked and legacy forms are decoded before comparison (`internal/tools/web/webauth/xsrf.go:19-57,88-133`, `handler.go:37-45`). | Preserve token semantics rather than compare randomized masked strings. |
| Authenticated WebSocket upgrades retain pending auth and XSRF cookies (`py:mitmproxy/tools/web/app.py:263-269,383-386` at `3368a0a`). | `PrepareUpgrade` sets the pending cookies and the hub opts into gows `ForwardResponseHeaders`, retaining separate `Set-Cookie` fields on the real 101 (`internal/tools/web/webauth/handler.go:53-75`, `internal/tools/web/updates/hub.go:123-139`; integration contract `internal/tools/web/webauth/handshake_test.go:113-239`). | Use the response-header API rather than a synthetic handshake; existing gows callers remain unchanged unless they opt in. |
| Upload handlers select the first file in wire order, or the exact raw body when no file exists (`py:mitmproxy/tools/web/app.py:325-334` at `3368a0a`). | A bounded scan records the first file before the standard storage parse; exact raw bytes are replayed through the wrapped handler, and owned temporary storage is cleaned afterward (`internal/tools/web/webauth/handler.go:124-179`). | Form parsing must not reorder file selection or consume the raw-body fallback. |

### Acceptance infrastructure

These are test-harness and runner boundaries, not changes to mitmweb's application shutdown or the user's browser.

| Upstream product contract | Go acceptance boundary | Reason |
|---|---|---|
| The pinned executable installs SIGTERM handling before running the master (`py:mitmproxy/tools/main.py:122-140` at `3368a0a`). | Normal harness shutdown sends SIGTERM once to the direct owned child; uv forwards it once to Python. The existing 15-second grace, whole-group SIGKILL on timeout, direct-child reap, leftover-group failure and immediate port-rebind checks remain. Any nonzero exit, including 143, fails (`internal/tools/web/acceptance/subprocess_unix_test.go:59-95`, `subprocess_stop_unix_test.go:21-88`, `differential_unix_test.go:108-113`). | Signalling the whole uv-owned group also signals Python directly, so uv's forwarding can deliver a second TERM during interpreter teardown. The real supervisor/descendant sensitivity pins one forwarded signal and an orderly descendant exit; no exit-143 waiver is used. |
| The product opens a suitable installed GUI browser (`py:mitmproxy/tools/web/webaddons.py:123-158` at `3368a0a`); it does not provision a headless test browser. | The hosted `ubuntu-26.04` carrier uses frozen Chrome's setuid sandbox because unprivileged user namespaces are restricted there. Before configuring the helper, two bounded negative controls must fail: no helper with `No usable sandbox`, and an unprivileged helper with `The SUID sandbox helper binary was found, but is not configured correctly`. The unchanged helper hash, root:root ownership, mode 4755 and a non-nosuid mount are checked; `CHROME_DEVEL_SANDBOX` propagates to later launches (`.github/workflows/ci.yaml:201-244`). | Keep the sandbox enabled rather than change the runner's namespace policy or use `--no-sandbox`. Native Debian uses the namespace sandbox instead; the hosted provisioner is not its setup procedure. |
| Upstream browser opening makes no claim about this port's Linux acceptance browser (`py:mitmproxy/tools/web/webaddons.py:108-119,123-158` at `3368a0a`). | The same unprivileged chromedp browser session used for UI acceptance navigates to `chrome://sandbox`, saves the full status text as `sandbox-status.txt`, and requires `You are adequately sandboxed.` (`internal/tools/web/acceptance/browser_linux_test.go:41-49,208-228`). | A successful about:blank render alone does not prove sandbox status; a command-line headless chrome:// URL can dump a fallback start page. The recorded SUID/Namespace/Seccomp rows distinguish hosted and native modes without disabling either sandbox. |

### Differential comparison boundaries

The seven-fixture oracle reuses identical input tuples sequentially, resets the confdir and verifies teardown between
runtimes (`internal/tools/web/acceptance/differential_unix_test.go:56-84,108-113`). Comparisons retain strict flow/schema,
HTTP status/content type, raw-body and metadata checks; the named exceptions below are not a registry intersection or
a general help, whitespace, empty/null, error-text or content-body normalizer.

| Pinned upstream surface | Named exclusion or adapter | Reason |
|---|---|---|
| `/options` dumps the upstream registry (`py:mitmproxy/tools/web/app.py:805-807` at `3368a0a`). | Removes Go-only `content_decode_limit` (decoded-body bound), `max_client_connections` (client-admission bound) and `script_max_steps` (Starlark execution budget) from Go equality when present (`testdata/options-go-only.txt`, `internal/tools/web/acceptance/differential_unix_test.go:228-234`). | These three controls have no upstream counterpart and are registered by the current default addon sets. |
| `/options` dumps the upstream registry (`py:mitmproxy/tools/web/app.py:805-807` at `3368a0a`). | The same manifest-only removal names `local_redirector_path` (redirector override), `otel_exporter_endpoint` (telemetry) and `pprof_addr` (profiling), if present (`testdata/options-go-only.txt`, `internal/tools/web/acceptance/differential_unix_test.go:228-234`). | These three names remain reserved, not runtime registrations; the six-entry manifest is not a claim of six active extra options. |
| Python registers the `scripts` option and `script.run` command (`py:mitmproxy/addons/script.py:163-169` at `3368a0a`). | Both are registered by mitmweb's default Starlark loader and compared without a scripting-specific exclusion from `/options` or `/commands`. | Scripting metadata is part of the live parity contract; only the Go-only execution-budget option is removed through the separate manifest rule above. |
| `browser.start(browser: str = "chrome")` has an ordinary parameter (`py:mitmproxy/addons/browser.py:39-40` at `3368a0a`). | Guards exact Python `browser:str` / `POSITIONAL_OR_KEYWORD` and `browser.start browser`, then compares against `arg0:str` / `VAR_POSITIONAL` and `browser.start *arg0` (`internal/tools/web/acceptance/differential_unix_test.go:239-248`). | The existing Go variadic/default API is documented under [addons/browser](#addonsbrowser); this is a guarded metadata adapter, not altered help text. |
| `export` returns text after backslash replacement (`py:mitmproxy/addons/export.py:218-232` at `3368a0a`). | Guards Python return `str` and `export format f -> str`, then compares as `bytes` and `export format f -> bytes` (`internal/tools/web/acceptance/differential_unix_test.go:249-254`). | The existing Go byte-result contract is documented under [addons/export](#addonsexport); no unrelated signature is adapted. |
| `/state` includes `version`, `platform`, `localModeUnavailable`, `contentViews` and `servers` (`py:mitmproxy/tools/web/app.py:826-840` at `3368a0a`). | Fixture equality compares only `contentViews` and `servers` (`internal/tools/web/acceptance/differential_unix_test.go:189-200`); it does not compare `version`, `platform` or `localModeUnavailable`. | Version identifies the implementation; platform and availability depend on the host/effective UID. Separate handler and Linux root/nonroot checks cover the availability contract; no native Windows evidence is inferred. |
| Process/icon results use native host state, and contentview rendering uses the runtime's renderer (`py:mitmproxy/tools/web/app.py:691-755,846-879` at `3368a0a`). | Fixture equality does not compare `/processes`, `/executable-icon` or highlighted `/flows/<id>/<part>/content/<view>` output; it compares flow schemas and raw `content.data` replies instead (`internal/tools/web/acceptance/differential_unix_test.go:135-204`). | Host process/icon results and highlighter output are not portable cross-runtime values. Their handler/native/rendering contracts remain separate; raw bytes and error statuses are not normalized away. |

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
| Any received GOAWAY closes every stream (`mitmproxy/proxy/layers/http/_http2.py:278-286`). | A NO_ERROR GOAWAY stops new origin leases while accepted streams finish on their existing transports. `OpenStream` returns `ErrDraining` before writing request bytes; the HTTP adapter obtains a fresh connection only for an unsent request. Error GOAWAY fails existing streams with its typed error code. | Drain accepted work without replaying a request that might already have been processed. |
| GOAWAY closes peer-initiated requests as well as local streams (`mitmproxy/proxy/layers/http/_http2.py:278-286`). | The LastStreamID threshold of a NO_ERROR GOAWAY excludes only locally initiated streams; incoming requests remain usable in server role. | RFC 9113 section 6.8 defines LastStreamID relative to the sender's peer, not all stream numbers. |
| HTTP/2 receive windows are 2^31−1, and DATA is acknowledged immediately (`mitmproxy/proxy/layers/http/_http_h2.py:50-67`, `_http2.py:238-240`). | Each receive endpoint independently reserves at most 128 MiB of aggregate stream grants. Initial stream windows are 1 MiB and grow on consumption up to 16 MiB, with at most 100 concurrent streams. Credit is returned only after the original input, including padding, has been consumed; transformed output does not determine the receipt size. | Bound retained input and keep unrelated streams progressing when one stream's reader or transformed output stalls. The two receive directions do not share a budget. |
| HTTP/1 h2c upgrade bodies are admitted under maximal receive windows and immediately acknowledged (`mitmproxy/proxy/layers/http/_http_h2.py`, `_http2.py`). | The endpoint constructor rejects an upgrade body larger than its 1 MiB initial stream window. Accepted bodies are charged to stream 1 and delivered in chunks no larger than `ChunkSize`, with original-byte receipts and the terminal flag only on the final chunk. The default addon set still disables h2c. | Seeding an upgraded stream must obey the same receive-window and ownership bounds as ordinary DATA. |
| hyper-h2 separates StreamReset events from protocol exceptions on malformed frames (`py:mitmproxy/proxy/layers/http/_http2.py:252-277` at 3368a0a). | The present-identity framer raises a StreamError that retains the typed stream/protocol cause and the framer diagnostic, queues the matching RST_STREAM, and fails only that stream; genuine peer resets and connection-level labels are unchanged. | Pins the framer boundary between malformed-frame classification and peer resets; does not claim byte-identical hyper-h2 wording or universal malformed-frame classification parity. |

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
| HTTP connection failures retain origin diagnostics in error responses (`mitmproxy/proxy/layers/http`). | Typed origin HTTP/2 connection failures produce the fixed client-facing 502 message `upstream closed the HTTP/2 connection`; flow diagnostics remain available. Stream resets and other error policies are unchanged. | Do not expose origin connection diagnostics in client bodies; typed/wrapped-cause and reset-source tests distinguish the policies. |
| HTTP/3 reverse proxying uses the QUIC HTTP layer and HTTP flow hooks (`mitmproxy/proxy/layers/http/_http3.py`). | A registered HTTP3 UDP listener and reverse:http3 scheme feed the private HTTP adapter over raw QUIC. Buffered/streamed headers, bodies and trailers, ordered duplicate fields, reset codes, hook rerouting, sibling isolation and HTTP1/HTTP2/HTTP3 pairing involving HTTP3 are implemented. Connection metadata reports `tls_version` `QUICv1`. | Real QUIC/frame-level peers and Handler acquisition/race tests verify these mechanisms. Default executable and isolated Linux timing acceptance are separate, not inferred from explicit-selector tests. |
| The pinned Python HTTP3 handler and test suite do not establish the same informational-response policy (`mitmproxy/proxy/layers/http/_http3.py`, `test/mitmproxy/proxy/layers/http/test_http3.py`). | Received HTTP3 1xx responses are swallowed like the Go HTTP2 adapter and are not forwarded downstream. Outbound 1xx encoding is supported without terminating the final response. | Deliberate Go-side policy, not inherited Python parity. Adapter response-event and informational-send tests cover the distinction. |
| Upstream uses general connection/event ownership machinery (`mitmproxy/proxy/layers/http`). | QUIC origin acquisition uses a private destination/SNI-keyed HTTP3 session table over handler-owned packet acquisition. Generic `ServerPool` is unchanged. At most 100 keys are retained; idle entries may be evicted, active/borrowed/establishing entries are protected, and busy-table overflow opens valid destinations unretained. | Bounded-state deviation avoids widening shared byte-connection APIs. Retention, cancelled-waiter and rerouting tests verify once-only release/join. The cap does not bound all simultaneous active sessions. |
| Connection close terminates associated HTTP flows (`mitmproxy/proxy/layers/http/_http3.py`). | Physical QUIC close grants exchanges a three-second terminal-event drain before cancellation, joining exchanges/publications before `RunQUIC` returns. External cancellation while the connection stays open interrupts immediately. | Bounded drain preserves terminal hooks. Raw ownership cancels the consumer context on physical close, making later external cancellation unobservable; total latency can include the drain interval plus hook/worker join, not a universal three-second return guarantee. |
| Reverse-proxy Alt-Svc can be retained with `keep_alt_svc_header` (`mitmproxy/addons/update_alt_svc.py`). | UpdateAltSvc rewrites to the actual client listener port unless the keep option is true; real HTTP3 Handler cases exercise both. | Existing addon behavior consumes the listener's published Sockname port; no separate HTTP3 addon rewrite is needed. |
| Regular proxy mode is TCP, not an HTTP3 UDP listener (`mitmproxy/proxy/mode_specs.py:186-191`). | HTTP3 is provided by reverse/QUIC-based paths, not by a new regular-mode UDP listener. Saved HTTP3 replay remains rejected as documented under addons/clientplayback. | Scoped reverse-mode integration; live proxying does not imply saved replay support. |
| Synthetic StreamReset injection after the request FIN is observed by the layer (`py:test/mitmproxy/proxy/layers/http/test_http3.py:1011-1058`). | After quic-go fully reads the request FIN, its completed receive stream drops a later RESET_STREAM (quic-go v0.63.0 `receive_stream.go:137-155`), so that order is transport-owned; real-peer acceptance certifies RESET/STOP orders while the request is open and STOP_SENDING on the still-open response side after the request FIN. | The Go layer sits on a real QUIC implementation rather than upstream's synthetic event injection; the completed-request RESET boundary is pinned, not emulated. |

HTTP/2 direct-load invocations write one terminal JSON sidecar under
`NETWORK_GATE_OUTPUT` before cleanup on success or failure. It records phase,
stream, expected bytes, actual received DATA payload, separately validated
payload, last payload-progress offset, frozen measurement elapsed time, outcome
and the original typed cause, plus race-safe client/origin failure, done,
context, credit and progress snapshots. Uncreated or unmeasured fields are null.
Actual bytes include partial DATA payload before a read error; validated bytes
count complete frames accepted by the existing framer, not a new body validator.
Raw wire bytes are separate. Accounting retains counters and a frame header,
not response bodies. Cleanup cannot replace the first cause; protocol failure
still takes precedence over timeout, and queued deadline completion still counts.

The narrow failed-construction lifecycle exception prevents joining a reader
that never started and closes each acquired connection once. Direct-origin setup
errors are delivered to the owner before teardown, so the sidecar retains their
original cause. Successful peer parsing, flow control and measured behavior, and
non-direct callers' existing success/error reporting, remain unchanged.

The existing first/retry artifact directories retain direct sidecars, with the
first attempt uploaded before an eligible retry. `hack/netem-gate.sh` is unchanged
and does not consume them: absent, present or malformed sidecars cannot change
its verdict or authorize a retry. Separate terminal contracts reject missing,
duplicate, malformed or contradictory receipts; classifier acceptance is not
sidecar validation. The 256 MiB transfer, 16 MiB windows, 0.8 floor, 30-second
measured wait, five-minute peer context, 600-second attempt and two-attempt limit
remain unchanged. Diagnostics do not establish a cause or remediate throughput;
20 retry-enabled successful runs would not be 20 first-pass successes.

Each HTTP/3 load row publishes one terminal receipt before cleanup, on success
or failure, with phase and stream, expected bytes, actual read bytes, separately
validated payload bytes, elapsed time, last-progress offset and the original typed
cause (`internal/proxy/layers/httplayer/http3_load_test.go` and
`http3_load_diagnostics_test.go`). Available client/origin QUIC state is included;
state not yet created is explicitly unavailable. Partial reads count before their
error is checked, and cleanup cannot replace the first cause. The 64 MiB/30-second
transfer and 4 MiB/2-second sibling limits, HTTP/2 netem thresholds and deadlines,
and `hack/netem-gate.sh` classifier are unchanged. HTTP/3 receipts have their own
log namespace and do not enter that classifier. The hosted HTTP/2 netem throughput
and HTTP/3 large-transfer failures remain open observations: these diagnostics
improve evidence, not throughput, and a green rerun is not a repair.

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
| Connection lifecycle and failed-connection reuse live in the Python proxy server (`mitmproxy/proxy/server.py`). | Detached pool cleanup preserves context values with private five-second admission budgets. Shutdown retains one owner until actual completion while callers may stop waiting. Completed failed flights are capped at 256 with oldest-insertion eviction; active flights, live leases and current waiters remain valid. | Bound cleanup waiting and failed-entry retention without abandoning ownership or evicting active work. Timeout does not certify joining; the failure cache has no TTL. |

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
| Reverse mode accepts `http3`, `quic`, and `dns` targets (`mitmproxy/proxy/layers/modes.py`, `mitmproxy/addons/next_layer.py`). | Registered reverse schemes select the DNS, raw QUIC and HTTP/3 owners. UDP reverse HTTPS always uses QUIC; an h3 Initial ALPN selects the HTTP/3 owner, otherwise it stays raw QUIC. | Default selector regression tests pin upstream routing. Protocol support no longer fails solely because these layers are absent. |

## internal/platform

Linux uses `SO_ORIGINAL_DST` in the accepted socket's IPv4/IPv6 family, as
`mitmproxy/platform/linux.py` does. The Go resolver borrows the descriptor
through `SyscallConn.Control`, normalizes mapped IPv4 before choosing the
syscall family, and validates sockaddr length/family/port before publication.
UDP transparent interception is not implemented. Invalid metadata must fail
rather than become a connection to the redirected listener.

Unlike upstream's PF-text-only lookup (`mitmproxy/platform/osx.py`, `pf.py`),
macOS and FreeBSD use generated per-OS `pfioc_natlook` layouts from Apple
`xnu-12377.1.9` and FreeBSD `release/14.3.0`, with pinned header digests and
size/offset checks. The first usable connection must match the exact ioctl and
PF-text tuples before ioctl results are trusted. Mismatch or layout refusal
disables that unvalidated path and falls back to strict text matching. The
raw-syscall path does not use a Darwin libSystem trampoline. After a validated
native path fails, text lookup also requires its redirected/listener endpoint
to match the accepted local IP/port; initial pre-validation fallback retains
upstream's peer-only lookup. Capture has a five-second deadline and 4 MiB
combined stdout/stderr cap; wrong-peer, malformed, truncated or oversized state
is refused.

Upstream's PF parser searches an established line for a peer substring
(`mitmproxy/platform/pf.py`). The Go parser instead matches the complete peer
address/port and established state, including mapped IPv4, IPv6 and FreeBSD
parentheses: a substring can identify another connection. Missing state retains
`Could not resolve original destination.`; privilege failure retains upstream's
documented message. OpenBSD uses the accepted socket's local address, matching
`mitmproxy/platform/openbsd.py`; this source-level contract does not certify
native OpenBSD execution.

Linux IPv4/IPv6 REDIRECT acceptance, ordinary macOS parser tests and mandatory
manual macOS root ioctl/self-check are separate evidence rows. Native Windows
CLI/refusal execution coverage is deferred; its source-level refusal and any
cross-build checks are not runtime certification. FreeBSD cross-builds do not
certify native FreeBSD lookup; no native FreeBSD/OpenBSD execution is claimed.
See the [transparent-mode runbook](runbooks/transparent-mode.md) for privilege,
own-flow exemptions, cleanup and unfilled result fields. This does not close
the separate native local-mode requirements.

## internal/proxy/layers/socks5

SOCKS5 uses the existing dedicated layer, `socks5_auth` hook and proxyauth
validators/cache; no duplicate authentication addon or option is installed.
Accepted credentials authenticate the same client for later HTTP/HTTPS requests,
so those requests do not receive another HTTP proxy-auth challenge. LDAP uses the
same bounded real-directory path outside addon dispatch. Existing HTTP-only
proxyauth behavior remains unchanged.

Reproduced on purpose from `mitmproxy/proxy/layers/modes.py` at `3368a0a`:

- A missing configured method sends the pinned ten-byte `05 ff 00 01 00 00 00 00
  00 00` refusal, rather than only the two-byte SOCKS method-selection response.
- RFC 1929 subnegotiation does not separately validate its version byte or reject
  empty username/password fields before validator dispatch. Authentication still
  depends on the configured validator; this is wire compatibility, not a claim
  of stricter RFC validation. Credential bytes use UTF-8 decoding with backslash
  replacement for invalid bytes; domain bytes use ASCII replacement.
- CONNECT accepts IPv4, IPv6 and domain destinations; success uses upstream's
  zero BND tuple. BIND and UDP ASSOCIATE remain refused with reply `07`; unknown
  address types use `08`, and eager origin failure uses `04`. Lazy strategy can
  acknowledge CONNECT before dialing, as upstream does.

For premature handshake closure, upstream can log the complete buffered frame,
including credentials (`mitmproxy/proxy/layers/modes.py:158–162`). Go instead
reports `authentication stage, <count> bytes` after the normal handshake-close
prefix during credential subnegotiation. No username, password or raw auth frame
is emitted. This preserves failure location without disclosing credentials.

Unsupported-request diagnostics keep upstream's message prefix and Python
byte-repr style but include only the bounded consumed five-byte request prefix,
not the rest of Python's delivered event. For the pinned BIND vector Go reports
`Unsupported SOCKS5 request: b'\x05\x02\x00\x01\x7f'`.
Reply bytes/status remain identical; no read-ahead is introduced to reconstruct
Python event boundaries.

The invalid-version HTTP-guess hint likewise examines the consumed two-byte
greeting prefix rather than up to three bytes in Python's event. Go requires at
least one ASCII uppercase letter and no ASCII lowercase letter in those two
bytes, versus upstream's `self.buf[:3].isupper()`. Pinned GET/abcd cases match;
for coalesced `GEt`, only Go emits the hint:
`Probably not a SOCKS request but a regular HTTP request.` (followed by a space).
Version-error text and no-reply behavior are unchanged. These consumed-prefix
choices affect diagnostics only, not protocol handling.

## addons/errorcheck

| Upstream | Go | Reason |
|---|---|---|
| The constructor installs a process-global Python logging handler (`mitmproxy/addons/errorcheck.py`). | The application explicitly composes `LogHandler()` into its logger. Collection is synchronous and mutex-protected, independent of the bounded `add_log` queue. | Embedders own logger configuration, and dropping a startup error could allow an invalid startup to succeed. |
| Repeated errors use Python's log formatter, and terminal summaries may use red ANSI text (`mitmproxy/addons/errorcheck.py`). | Summaries are plain text; repeated messages preserve their text and append any structured slog attributes in text-handler format. | No Python logging formatter or implicit terminal capability detection in the library. |

## addons/readfile

| Upstream | Go | Reason |
|---|---|---|
| `ReadFileStdin` reads `sys.stdin.buffer` and leaves it open; the reading task is abandoned to the event loop on shutdown (`mitmproxy/addons/readfile.py`). | `-` reads and owns configured stdin. A retained cleanup operation snapshots/cancels under dispatch and closes/joins outside it. Callers wait within their cancellation or a private five-second budget; unfinished ownership prevents restart. | Keep blocking I/O out of shared dispatch. A timeout ends waiting, not ownership, and is not a successful join or arbitrary-I/O termination guarantee. |
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
| aioquic QUIC settings expose cipher-suite selection (`mitmproxy/addons/tlsconfig.py:379-464`). | Certificates/chain, ALPN, verification and CA paths are applied to a TLS 1.3 crypto/tls configuration. TLS 1.3 wire cipher selection remains controlled by Go; QUIC policy does not snapshot `CipherSuites`, and its TLS configuration sets no `KeyLogWriter`. | crypto/tls has no per-configuration TLS 1.3 suite selector. Configurable QUIC cipher parity and QUIC key logging are not provided. |

QUIC TLS policy clones ALPN/CA paths/certificate DER under dispatch and shares only immutable signing material,
as `tls.Config.Clone` does. Hook installers must not mutate private-key internals after installation. Opaque
signers remain supported; no standard-key-only serialization restriction is imposed.

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
| TCP lifecycle hook dispatch has no separate cleanup deadline (`mitmproxy/proxy/layers/tcp.py`). | Terminal hooks use a detached 30-second budget, independent of idle timeout. Final Resume and `Live=false` dispatch use a fresh independent budget after hook expiry. | An expired hook context cannot admit final cleanup. Dispatch admission is cancellation-aware; arbitrary addon callbacks must still cooperate. |

## internal/proxy/layers/udplayer

| Upstream | Go | Reason |
|---|---|---|
| Every UDP flow receives `udp_end` or `udp_error`, and a connection-close event emits `udp_end` before clearing `live` (`mitmproxy/proxy/layers/udp.py:44-51,121-126`). | Every captured flow emits exactly one terminal hook, including on shutdown, idle expiry and cancellation: `udp_end` for closure or cancellation, `udp_error` for failure. The hook uses `WithoutCancel`; dispatch then clears `Live`, including on dial failure. An interception retained into or requested during a terminal hook is immediately resumed. | Preserve upstream's terminal-hook lifecycle and release the finished tuple. Unlike upstream's suspended hook coroutine, a terminal interception cannot retain a connection owner after its transport has finished. |
| UDP lifecycle hook dispatch has no separate cleanup deadline (`mitmproxy/proxy/layers/udp.py`). | Terminal hooks use a detached 30-second budget, independent of idle timeout. Final Resume and `Live=false` dispatch use a fresh independent budget after hook expiry. | An expired hook context cannot admit final cleanup. Dispatch admission is cancellation-aware; arbitrary addon callbacks must still cooperate. |

## Additional compatibility decisions

The scripting behavior below is implemented. Go-only option names that remain reserved are distinguished from
registered runtime options.

Scripting (Starlark instead of Python):

The default addon sets of **mitmdump, mitmweb and mitmproxy** register the
script loader, `-s` / `--scripts`, `scripts` (sequence of strings, default
`[]`) and `script_max_steps` (integer, default `0`). Script custom options
and zero-argument commands are available in `--options` / `--commands`.
The interpreter pin and upgrade checks are in [dependencies.md](dependencies.md).

Authenticated mitmweb `PUT /options` requests can also set `scripts`, matching
upstream. Script paths refer to the proxy host's filesystem and use the same
trusted-code execution model as `-s`; authenticated configuration access is
operator authority, not a scripting sandbox.

| Upstream | Go | Reason |
|---|---|---|
| Addon scripts are Python modules. | Scripts are trusted operator-supplied Starlark modules. The `load` hook is named `on_load`, because `load` is a Starlark keyword; the other 45 hook names are unchanged. Python classes, decorators, `async` functions and Python imports are not interpreted. Module-level functions/dictionaries and bounded `module(name, **handlers)` child addons replace classes. | No embedded Python interpreter or Python package loader. |
| Ordinary Python hooks may keep mutable module state. | Ordinary Starlark globals remain mutable across hooks. A fresh thread is used for each initialization, hook and registered command; ordinary evaluation runs under addon dispatch. | `Program.Init` is used without implicit global freezing; cancellation and execution budgets are invocation-local. |
| `@concurrent` decorates a handler. | Write `def _request(flow): ...` followed by `request = concurrent(_request)`. Eligibility comes from every global or child-member binding name, not the function's definition name. Reassigning an already-defined global `request` remains a resolver error. | Starlark has no decorator syntax, and global reassignment is disabled. |
| A concurrent handler shares module globals and live model objects. | A script with any accepted root or child wrapper is initialized twice per load: ordinary hooks retain the mutable first instance, workers share a separately initialized frozen instance. Top-level effects run twice; a script without wrappers initializes once. A worker receives a detached flow preserving the invocation's original ID/live flag, with read-only connection snapshots. Mutable frozen dictionaries/lists reject writes. | Concurrent Starlark execution requires frozen module state; workers must not borrow dispatch-owned mutable storage. |
| `@concurrent` is accepted on any hook except `load` and `configure`. | Only the 23 single-flow hooks accept `concurrent`. Other hooks and helper bindings fail loading with `Concurrent decorator not supported for '<name>' method.` Child-only wrappers use the same rule and the same script-owned frozen instance. | Only flow hooks have a defined copy/merge boundary. |
| Calling a decorated handler directly produces an unawaited coroutine. | A direct call fails with `concurrent(<fn>) cannot be called directly; it runs only when invoked as a hook`; the wrapped function is not invoked. | Starlark has no coroutine value to return. |
| Workers freely mutate the shared flow and protocol-message lists. | Merge applies changed semantic fields and original message indices, preserving untouched live edits and opposite-direction/live-appended suffixes. Worker appends follow the live suffix; structural deletion/reordering of the original prefix is rejected. Connection fields, timestamps and identity are not worker-writable. Action-generated state is not merged as a generic field delta. | Preserve ownership and avoid applying a changed message to a different live index. |
| Worker command-argument ownership: Python commands receive shared input objects and may retain them. | Mutable worker arguments are copied into a separate command-owned graph with repeated-reference relationships preserved. Promised immediate mutations are copied back from detached post-call snapshots under the same `master.Do`; returned values are detached there too. Later queue/worker mutations do not cross that boundary. For example, real `replay.client` may retain its command-owned flow without sharing the worker's later request edits. | Intentional asynchronous-sharing difference. `TestScriptConcurrent/contracts/{retained_copy_command,command_copyback,command_argument_aliases}` cover retention, immediate mutation and aliases; no change to the native command implementation. |
| Public backup/revert and flow actions operate on the shared object immediately. | Workers checkpoint ordinary field deltas around `backup`, `revert`, `intercept`, `resume` and `kill`, then replay each action in order on the live flow through its public methods. A replayed backup captures the live state plus preceding worker edits, not the copy's private backup. Revert otherwise restores the full public backed-up state. | Keep action ordering, live IDs and native backup semantics without installing copied mutex/private state. |
| Protected killed terminal state: a later action can alter interception or restore backed-up state. | Once a replayed worker kill succeeds or the live flow was killed under `master.Do`, merge preserves the exact killed error and `live=false`, and calls public `Resume` after every later replayed backup/revert/intercept/resume and at completion. A later intercept/revert cannot strand a killed flow. Other backed-up fields still obey public Revert. This normalization applies only to a protected killed outcome, not every naturally non-live flow. | Terminal-state precedence, covered by `action_order` and `kill_precedence`: intercept→backup→kill→revert, an existing intercepted backup followed by kill→revert, and a live kill during a worker followed by worker revert. Each observes waiter release, hook completion and actual transport closure. |
| Fixed registered child set: upstream re-reads `addons` on every traversal; replacing children after load affects dispatch and can break removal. | Child adapters and wrapper paths are fixed when load, including `on_load`, completes. Dispatch, remove, done and owned-command cleanup use that registered set. Clear/replace/reorder/append or any topology difference fails the affected hook with a logged error rather than silently registering/remapping children. Teardown still removes the registered lookup entries/commands and delivers done once before fresh same-name registration. | Explicit adapter-lifetime difference. `child_topology_drift` covers clear/replace/reorder followed by remove and same-name reload, including command re-registration, no partial/stale residue and joined retired workers. |
| A worker reads live option attributes directly. | Each `ctx.options.<name>` read uses the copying, locked native option getter at read time, producing a frozen Starlark value. It may see a transient update that is later rolled back. Writes, command calls and logs re-enter the master's dispatch; ordinary aliases remain writable in a valid ordinary invocation. | Avoid a second option publication protocol and preserve native update/rollback behavior. |
| Blocking work runs in Python's asyncio/executor environment. | `ctx.sleep(seconds)` and `ctx.http_get(url)` release dispatch only at eligible ordinary depth; synchronous/nested calls stay bounded and inline, and concurrent workers wait independently. Admission is cancellable. Active workers are bounded to `min(32, GOMAXPROCS+4)` per loaded instance; this is not a process-wide heap bound across scripts/reloads. Retirement allows already-admitted work to finish/merge into a still-waiting flow; cancellation suppresses merge, and final Close cancels/joins outside dispatch. | Preserve dispatch ownership and avoid joining a worker while holding the lock it needs. |
| Python scripts can import arbitrary networking, filesystem and package APIs. | No filesystem/network `load()` imports are provided. `ctx.http_get` uses HTTP(S), standard TLS validation, no inherited proxy environment, cookies or authentication, and rejects userinfo and this master's actual proxy-listener dial tuples. Limits are 10s total, 3s dial, 64KiB response headers, 1MiB response body, three redirects and 32 simultaneously admitted HTTP operations per script. Unsupported schemes or missing listener-address capability fail closed. | Explicit builtin safety limits, not Python `requests` compatibility and not a network sandbox. Other owned loopback origins remain supported. |
| Python source loading and object conversion have no corresponding Starlark adapter bounds. | Source must be an operator-selected regular file and is limited to 1MiB; selected symlinks are deliberately followed and re-resolved at load. Child trees are acyclic, at most 32 levels and 1,024 modules. Converted graphs are bounded to depth 64 and 65,536 container entries, with cycle rejection. Values are validated before mutation; binary content remains bytes through `byteops`. The one-second watcher reloads only a newer mtime, records failed-load mtimes, and cannot revive a removed generation. | Explicit refusal rather than silent truncation; trusted paths are not a pathname sandbox. |
| Python `script.run` initializes a temporary module and invokes its lifecycle and recorded-flow events synchronously. | `script.run(flows, path)` initializes once, never calls `on_load`, registers no temporary addon/command, and invokes configure(all option names), running and native event sequences only on that module and its children. It rejects root/child wrappers at every dispatch depth, logs once and stops at the first hook error. The sync-context message names the script path instead of Python's module repr. Nested runs are limited to 16 frames per Loader before path resolution/init; exceeding that limit stops the chain with one outermost logged error while the external command caller retains success semantics. | No asynchronous synchronous-run adapter or unrelated-addon dispatch; bound fresh-interpreter recursion that Starlark's ordinary recursion check cannot see. |
| Explicit copy of a requestless DNS flow raises in Python's state conversion. | Concurrent DNS hooks preserve absent request/client/server snapshots as `None`; no placeholder request is exposed or merged. Explicit `f.copy()` of a requestless DNS flow returns an ordinary Starlark error instead of reaching the native flow-copy panic. | The worker clone is an adapter-owned construct; the underlying DNS state round-trip limitation is a separate native-flow follow-up. |
| Python scripts execute without Starlark step budgets. | `script_max_steps` is registered in all three tools. Zero is deliberately unlimited; a positive value bounds each fresh initialization/hook/command evaluation, and a negative value is rejected as an option error. Budget failure logs an ordinary error and ends that handler while the proxy continues. Go builtin work is not metered, and the interpreter imposes no heap quota. | Trusted-code execution, not a CPU/memory sandbox. |

The example disposition is explicit rather than a blanket Python-compatibility claim:

| Upstream example | Unsupported behavior / supported alternative |
|---|---|
| `commands-flows.py` | Arbitrary typed Python-decorated command registration is not exposed; `loader.add_command` supports zero-argument Starlark commands only. |
| `commands-paths.py` | Typed Python command registration and direct file I/O are unavailable; native save commands accept explicit paths. |
| `contentview-interactive.py` | Python contentview class/reencode registration is not exposed. |
| `contentview.py` | Python contentview class/plugin registration is not exposed; mutating a body is not an equivalent plugin port. |
| `duplicate-modify-replay.py` | `ctx.master.addons` membership introspection is unavailable; dropping its view-dependent conditional would change the example. |
| `filter-flows.py` | Python `flowfilter` imports are unavailable; existing native filter options and commands remain callable. |
| `http-stream-modify.py` | A general Starlark streaming callback has no safe dispatch-frame adapter; boolean streaming remains supported. |
| `io-read-saved-flows.py` | Standalone Python argv/open/FlowReader program; use Go `flowio` or `script.run` on loaded flows. |
| `io-write-flow-file.py` | Direct Python random/environment/file-handle APIs are unavailable; use native save options/commands. |
| `options-configure.py` | Raising Python's typed OptionsError is unavailable; generic Starlark `fail` is not identical rollback behavior. |
| `websocket-inject-message.py` | The full example requires asyncio periodic task creation; native injection commands do not by themselves port that lifetime. |
| `wsgi-flask-app.py` | Python Flask/WSGI execution is not embedded; a native apphost is a different integration. |

The other eighteen examples have recognizable `.star` translations and real
built-mitmdump cases in `script/acceptance`; `nonblocking.star` ports only the
thread-based alternative, not the active asyncio branch. Source provenance,
upstream notices and translation digests are in
[examples/addons/README.md](../examples/addons/README.md) and
[testdata/README.md](../testdata/README.md#scripting-references). Python-frozen
ImportError guidance and Python traceback-object slicing have no Starlark
counterpart; the source-test inventory records those non-ports separately.

Options that only the Go port has (`testdata/options-go-only.txt:1-6`):
`content_decode_limit`, `max_client_connections` and `script_max_steps` are registered by the default addon sets.
`local_redirector_path`, `otel_exporter_endpoint` and `pprof_addr` remain reserved,
not runtime options. The historical four-name description is not the current registry difference.

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
| Reverse HTTPS opens TCP and UDP listeners (`mitmproxy/proxy/mode_servers.py`, `mitmproxy/proxy/mode_specs.py`). | Instances bind same-port TCP and UDP listeners, with independently registered protocol factories. | Listener and factory contracts verify startup, address publication and shutdown; final executable dual-transport acceptance is separate from factory registration. |
| WireGuard mode accepts decrypted inner TCP/UDP through a userspace network engine (`mitmproxy/proxy/mode_servers.py`, `mitmproxy-rs/src/packet_sources/wireguard.rs`). | The instance owns its UDP socket, WireGuard source and gVisor stack, feeds accepted inner streams into existing Handler/HandlePackets, and joins owned work on Stop. Default configuration uses the effective confdir; explicit configuration paths remain supported. | `TestWireGuardModeLifecycle`, `TestWireGuardModeEncryptedFlows`, `TestWireGuardDestinationHandoff`, `TestWireGuardConfDir` and the integration-tagged `TestWireGuardExecutableMode` cover lifecycle, destination handoff, encrypted flows, configuration and actual CLI TCP. This is separate from script-addon/uppercasing acceptance. |
| TUN mode owns an interface rather than TCP/UDP listen sockets (`mitmproxy/proxy/mode_servers.py`, `mitmproxy-rs/src/packet_sources/tun.rs`). | Linux TUN startup publishes a live source without listen addresses; interface lifetime is independent of socket listeners. The bridge and stack feed accepted TCP/UDP to the existing handler path and join on Stop. | `TestTunModeAdmission`, `TestTunModeLifecycle`, `TestTunModeTCPHTTPOrigin` and `TestTunModeUDPOrigin` cover admission/lifetime and userspace flows. The recorded private-netns Linux CLI proof covers native IPv4 HTTP/TCP/UDP, not native IPv6 or the entire privileged packet-mode catalogue. |
| Local mode reuses a daemon across one current frontend without binding listen sockets (`mitmproxy/proxy/mode_servers.py:420-470`). | Local frontends are admitted without a listen port and reserve one active frontend process-wide. Linux Unix-datagram and Windows named-pipe packet IPC feed a gVisor stack; macOS stream IPC feeds the existing TCP/UDP handlers directly. The original destination is available before the first nextlayer hook, and optional PID/process-name values are copied from native metadata. | `TestLocalIPCOrigins`, `TestLocalMetadataSnapshot` and the Linux/Windows packet IPC tests cover real IPC, socket roundtrips and handoff. This is frontend integration, not proof of installed host interception or live process attribution. |
| The daemon is a class-level singleton; stopping a frontend clears its interception rules but retains the daemon (`mitmproxy/proxy/mode_servers.py:421-424,465-470`). | `modeserver.Config.LocalRedirector` supplies an explicitly owned daemon. Frontend Stop disables interception, cancels and joins its readers/flows, and releases the singleton reservation without closing the daemon. The default proxyserver addon owns final daemon Close outside dispatch after frontends stop. Startup failures release the reservation; live IPC failures and cleanup causes remain observable. | Explicit ownership lets embedders supply the daemon without a package-global process lifetime. `TestLocalIPCDefaultAndDaemonReuse`, `TestLocalIPCSingleFrontend`, the lifecycle tests and addon-owner tests cover reuse, singleton handover and final cleanup. |

## addons/proxyserver

| Upstream | Go | Reason |
|---|---|---|
| No global cap on concurrent accepted clients (`mitmproxy/addons/proxyserver.py`, `mitmproxy/proxy/mode_servers.py`). | The Go-only `max_client_connections` integer defaults to 0 (unlimited). A positive cap is shared across all mode listeners; excess clients are closed immediately after accept, warned once, and never registered as active connections. Lowering the cap retains existing clients. | Bound concurrent sockets and handler resources without changing HTTP idle-deadline semantics. |
| `configure` accepts every parseable proxy mode; backends without an implementation fail later, at listen time (`mitmproxy/addons/proxyserver.py`). | `configure` rejects modes whose server backend is not implemented with `Proxy mode <spec> is not supported by mitmproxy-go yet.` | Failing at configure time names the unsupported mode instead of starting a server that cannot serve it. |
| `server_connect` refuses a TCP destination on a listen port only for the four literal host strings `localhost`, `127.0.0.1`, `::1` and the listen host (`mitmproxy/addons/proxyserver.py`). | The TCP dialer's `Control` checks each resolved address actually dialled against the current listeners on the same port: any loopback or unspecified address, the bound address, and, for a wildcard listener, every local interface address. This covers every address spelling, including libc numeric forms, and names that resolve to the proxy, without resolving names twice. The pre-dial host check remains; both checks use upstream's refusal text. Custom dialers must delegate to `ProxyServer.Dialer()` to retain the dial-time guard. | Checking only a host string lets a DNS name or another numeric spelling loop one unauthenticated request into the proxy without end; checking the dialled address also prevents DNS rebinding from bypassing the guard. |
| `inject.tcp`, `inject.websocket` and `inject.udp` only warn when an event cannot be delivered (`mitmproxy/addons/proxyserver.py`). | All three commands are registered. A full injection queue, an oversized message or a wrong message type is returned to the command caller as an error; nonmatching-flow and not-live warnings match upstream. `inject.websocket` defaults its optional `is_text` argument to true. | The bounded injection queue is a deliberate backpressure divergence, and its errors must reach the caller to be actionable. |
| Transparent mode initialises platform redirection at configure time (`mitmproxy/addons/proxyserver.py`). | Configuration admits transparent mode; Start checks platform availability before creating listeners. Each accepted TCP connection requires original-destination lookup and captured metadata before entering the Handler. Windows Start refuses with the pinned warning quoted in the [transparent-mode runbook](runbooks/transparent-mode.md). | Fail closed on lookup failure rather than treating an arbitrary HTTP Host header as the captured destination. Windows refusal is a deliberate Go limitation: pinned Python warns but still implements a legacy WinDivert path. |
| Local mode keeps the native daemon across frontend reconfiguration (`mitmproxy/proxy/mode_servers.py:420-470`). | The proxyserver addon constructs the platform controller lazily when local mode is configured, using the effective confdir. Launch occurs at frontend Start. Disabling local mode stops only the frontend; final addon shutdown closes the retained daemon outside the dispatch lock. Local and TUN frontends do not participate in listen-address collision accounting. | Preserve daemon reuse without waiting for process or flow joins under dispatch, or treating packet-source modes as socket listeners. `TestLocalAddonLazyOwnerFinalClose`, `TestLocalAddonLiveOwnerShutdown` and `TestLocalConfigureNoPort` cover the ownership and no-port paths. |

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
| Synchronous Python signals (`py:mitmproxy/addons/view.py:169-184` at `3368a0a`). | Bounded `Subscribe` channels; overflow still closes and removes the subscriber, which must resnapshot. Synchronous `Observe` callbacks additionally receive a detached deep copy per non-nil flow, observer and event, retaining ID and Live (`addons/view/view.go:89-130,174-190`). | Existing channel behavior is unchanged. Observer copies isolate the store and other observers; copying, serialization and filter fanout still consume dispatch time. |
| `intercept`, `resume` and `kill` are directly dispatched hooks (`mitmproxy/addons/view.py`). | Runtime changes arrive through `update`; direct methods remain available. | The Go core dispatches the shared update hook for lifecycle notifications. |

## addons/eventstore

| Upstream behaviour | Go behaviour | Reason |
|---|---|---|
| The constructor installs a process-global Python logging handler (`py:mitmproxy/addons/eventstore.py:18-26,41-56` at `3368a0a`). | The frontend explicitly composes one `EventStore.LogHandler`, delivering `Add` through `manager.Do`, and owns Flush/Close outside dispatch before manager closure. Construction/loading installs no global logger; the store no longer implements the deprecated `add_log` hook (`addons/eventstore/eventstore.go:44-65,92-119`, `internal/tools/web/master.go:127-140,290-295`). | Embedders own logger composition and lifetime while store mutation stays synchronized. |
| Web event IDs are Python object-address integers (`py:mitmproxy/tools/web/app.py:212-217,800-802` at `3368a0a`). | A monotonic per-store uint64 identifies both `/events` and `events/add`, without reuse after clear or eviction (`addons/eventstore/eventstore.go:83-126`, `internal/tools/web/routes.go:234-238`, `internal/tools/web/updates/broadcast.go:91-96`). | Keep one stable identity source without exposing Go object addresses. |
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
| HTTP/2 and HTTP/3 flows pass the replay check (`mitmproxy/addons/clientplayback.py:196-210`). | Saved HTTP/2 requests use the negotiated origin protocol, including conversion to HTTP/1. HTTP/3 remains refused with `Can't replay HTTP/3 flows: HTTP/3 is not supported yet.` | Live HTTP/3 proxying is implemented, but saved HTTP/3 replay remains intentionally unavailable; the refusal retains legacy diagnostic wording. |
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
| These output paths use ordinary Python file opens on Windows. | Windows creates a protected current-token-user-only DACL atomically. Existing handles must be regular, non-reparse and current-user-owned; their DACL is narrowed before truncation or append. No SYSTEM/Admin ACE is added. Other unsupported platforms refuse private output. | Validate the opened target and restrict access before changing credential-bearing content. Parent directories must be trusted; hard links and already-open foreign descriptors are not revoked. Native Windows ACL tests cover creation, append, narrowing and foreign-owner refusal. |

## addons/dnsresolver

| Upstream | Go | Reason |
|---|---|---|
| Hickory applies its request timeout/retry and positive/negative TTL caches (`mitmproxy-rs/src/dns.rs`). | A lookup, including CNAME resolution and TCP fallback, has an aggregate five-second budget and at most 16 cumulative CNAME hops. Resolver configuration snapshots are reused, but DNS answers are not cached. System and explicit servers are queried directly without search-suffix expansion. | Bound total lookup work; TTL answer caching is deferred, not proved by repeated-answer tests. Real UDP/TCP, OS fallback, hosts and cancellation tests cover the implemented lookup paths. |
| Resolver configuration/hosts loading uses native facilities (`mitmproxy-rs/src/dns.rs`, `mitmproxy/addons/dns_resolver.py`). | Configuration and hosts input are capped at 1 MiB. Windows server discovery uses IP Helper. Standalone answers use `DefaultTTL`; reverse DNS bypasses this resolver. | Bound configuration loading. Option names/defaults and upstream addon positions are pinned by dump assembly tests. |

## internal/proxy/layers/dnslayer

| Upstream | Go | Reason |
|---|---|---|
| All complete DNS TCP frames from one socket read are parsed before dispatch; a later malformed frame suppresses earlier frames in that read (`mitmproxy/proxy/layers/dns.py`). | Dispatches complete frames in order and closes at the first malformed frame. | Avoid flow construction depending on socket read boundaries. The difference is runtime-read-boundary-dependent, not a DNS message-semantic change. |
| Retains each transaction ID's flow until shutdown, without an aggregate entry bound (`py:mitmproxy/proxy/layers/dns.py:61,67,164-169,180`). | Evicts after forwarding a response and running `dns_response`, or after `dns_error`, first calling Resume and clearing Live. Unanswered retransmissions reuse the flow, run `dns_request` per arrival and forward again. A response for an evicted or never-seen ID creates a requestless flow, fires `dns_response`, and is forwarded, finalized and removed (`py:mitmproxy/proxy/layers/dns.py:71-101`). A response hook clearing `Response` retains the entry, including a requestless one. The cap is 1,024 retained transaction-ID entries per client connection or UDP tuple, not just unanswered queries. At capacity, an existing ID still reuses its entry; a new ID is refused before flow creation or hooks and follows the invalid-message path, ending the connection or evicting the UDP tuple. | Bound all retained DNS entries while preserving retransmissions and intercepted-flow ownership; ordinary forwarded unsolicited responses do not accumulate. |

Malformed UDP/TCP input closes/logs without creating a DNS flow or firing dns_error. A separate valid-flow failure
fires one error hook and answers SERVFAIL; no FORMERR response is fabricated. Other active tuples remain usable.

`TestDNSTransactionCompletion` pins the intentional deviation:
"resend after the answer creates a new flow".

## internal/h3

| Upstream | Go | Reason |
|---|---|---|
| Python peers advertise QPACK capacity 4096 and 16 blocked streams, delegating to aioquic (`test/mitmproxy/proxy/layers/http/test_http3.py:140-175`, `mitmproxy/proxy/layers/http/_http_h3.py:113-131`). | Advertises zero dynamic-table capacity and zero blocked streams. Static/literal QPACK preserves ordered duplicate fields; dynamic references/insertion instructions are rejected. Encoded/decoded field sections are capped at 128 KiB. | Bounded static-table policy; QPACK contract/malformed/bounds/instruction tests and HEADERS fuzz cover it. |
| Python suppresses MAX_PUSH_ID and aborts if a push promise reaches the HTTP layer (`mitmproxy/proxy/layers/http/_http_h3.py:133-141`, `_http3.py:189-193`). | Never advertises MAX_PUSH_ID; parses a received push ID and emits CANCEL_PUSH rather than the Python abort. | Push-refusal policy. Parser ID vectors do not independently certify a complete real push-refusal exchange. |
| Python sends readable protocol connection-close reasons (`mitmproxy/proxy/layers/http/_http3.py:170-174,189-193`, `_http_h3.py:171-180`). | Application close carries the code with an empty wire reason; Shutdown keeps at most 1024 debug bytes for the local log. | Log-only diagnostic policy. The real QUIC contract covers empty reason/code propagation; not every diagnostic logger assertion is independently mapped. |
| Python uses aioquic's event/command coupling (`mitmproxy/proxy/layers/http/_http3.py:60-196`, `_http_h3.py:59-131`). | Independent events use 64 KiB owned DATA chunks, 256 KiB per stream including borrowed DATA, at most 100 streams, eight pending events per stream and 200 connection notifications. Original-byte receipts govern release; quic-go owns transport credit. | This is not an HTTP2 grant budget. Receive-bound/sibling/cancellation tests cover DATA reservation; not all concurrency/event limits have separate saturation proofs. |
| Frame truncation is reported through combined aioquic events. | Clean EOF is distinguished from truncated integers, frame headers and ignored payloads with `io.ErrUnexpectedEOF`, mapped through request/critical-stream semantics. | A partial frame must not become clean completion; frame-parser truncation tests cover the distinction, not identical error text. |
| quic-go handles PRIORITY_UPDATE (`http3/frames_test.go:417-446`, v0.63.0). | Skips unknown extension frames with constant-memory draining; no scheduling-priority update is applied. | Priority scheduling is outside the Endpoint contract. Unknown/GREASE skipping is tested; exact PRIORITY_UPDATE vectors are not independently mapped. |

These policy rows are not a claim that every upstream HTTP3 event/hook sequence is independently reproduced.
Extended CONNECT, HTTP Datagrams, priority scheduling and received-1xx forwarding are not provided by this contract.

## internal/proxy/layers/quic

| Upstream | Go | Reason |
|---|---|---|
| Raw QUIC forwards peer connection-close code, frame type and reason (`py:mitmproxy/proxy/layers/quic/_raw_layers.py:290-302`). | Peer application close codes/reasons are preserved. Transport-level CONNECTION_CLOSE frame/type/code re-emission remains unimplemented; a real peer-induced transport-error certification preserves the original typed transport diagnostic and observes opposite-peer application cleanup code 0 with an empty reason. Closed-handler-retirement parity remains unrepaired. | quic-go v0.63.0 exposes only application `CloseWithError` for caller-originated closes; no private library API or protected-frame synthesis is used in production. A future public transport-close API reopens this decision. |
| Stream owners are event-loop-driven (`mitmproxy/proxy/layers/quic/_raw_layers.py`). | Wire admission limits bidirectional and unidirectional streams to 100 each; the raw owner permits at most 100 combined active stream owners. Injection uses the bounded connection queue; reads retain fixed 64 KiB windows. | Bound goroutines/read buffers while preserving hooks, FIN/reset and sibling progress. |

## internal/netstack

| Upstream | Go | Reason and verification |
|---|---|---|
| Emits ConnectionEstablished on the first new SYN (`mitmproxy-rs/src/network/tcp.rs:123-161`). | TCPConns publishes only after the TCP handshake completes. | Exclude unestablished connections from proxy admission; IPv4/IPv6 forwarder tests assert no accept before ACK. |
| UDP expiry cleanup is polled every five seconds (`mitmproxy-rs/src/network/udp.rs:60-78,169-180`). | TCP idle and UDP tuple expiry are 60 seconds; explicit clock timers close expired tuples at the deadline. Incoming tuple traffic refreshes activity; UDP reads/writes also refresh LRU activity. | Injected-clock tests verify expiry, no early expiry and activity refresh. |
| TCP keepalive uses 28 seconds (`mitmproxy-rs/src/network/tcp.rs:134`). | Idle and probe interval are both 28 seconds. | IPv4/IPv6 clock tests verify the on-wire empty ACK probe. |
| ICMP echo is answered locally (`mitmproxy-rs/src/network/icmp.rs:8-54,57-110`). | Synthesizes IPv4/IPv6 replies with reversed addresses and unchanged identifier, sequence and payload; opens no origin connection. | Echo tests and packet fuzz exercise this subset, not general ICMP forwarding. |
| Stream metadata uses Python values/defaults or KeyError (`mitmproxy-rs/mitmproxy-rs/src/stream.rs:150-198`). | GetExtraInfo returns `(any, bool)`: transport_protocol is `connection.TransportProtocol`, peername/sockname are `net.Addr`, original addresses are `netip.AddrPort`, pid is uint32, process_name/remote_endpoint are strings. Missing keys return false and mutable byte metadata is copied. | Language-binding adaptation; captured original addresses remain distinct from the inner tuple. |
| TCP secondary send buffering is unbounded; half-close becomes full close with FIN (`mitmproxy-rs/src/network/tcp.rs:28-35,210-220`). | Writes copy below a 1 MiB pending cap; at the cap only that stream waits with deadline/cancellation. Drain waits for queue/send-buffer capacity; Close flushes before FIN and CloseWrite requests full close. Buffered peer bytes precede reset errors. | Finite-cap adaptation with admission/deadline, buffered-reset and sibling-isolation tests. |
| Packet-source queues rely on upstream packet-engine ownership. | Nonblocking Inject reports sentinels; queues cap pending packets/accepts at 256, active tuples at 1024, UDP buffering at 64 packets/1 MiB per tuple. Outbound saturation drops packets without blocking siblings. | Bounded-resource adaptation; capacity/ownership and same-stack isolation tests cover it. |
| Rust owns its packet engine and uses smoltcp wire types (`rs:src/network/core.rs:8,17-20`), not gVisor. | The `gvisor.dev/gvisor` pin `20261009-bd481cb1` bounds IPv6 parsing by the declared payload length and rejects a zero payload length followed by Hop-by-Hop Options with a parameter-problem error; drops oversized reassembled IPv4 datagrams as malformed rather than truncating; updates TCP TS.Recent on a zero-window probe; and inherits TCP_NODELAY on accepted sockets. | These are dependency packet-path behaviour changes relative to the previous Go pin, not new adapter APIs or reported regressions. Netstack, WireGuard and TUN contract evidence accompanied the bump; no unmeasured Rust parsing equivalence is claimed. |

## internal/wireguard

| Upstream | Go | Reason |
|---|---|---|
| Configuration is written directly with ambient umask (`mitmproxy/proxy/mode_servers.py:349-367`). | Generates a complete private sibling file, then publishes by a non-overwriting hard link. Concurrent starts cannot replace identities or observe partial JSON. | Trusted parents and filesystem hard-link support are required; there is no unsafe overwrite fallback. |
| Configuration JSON loading has no explicit file-size bound (`mitmproxy/proxy/mode_servers.py:349-367`). | Reads at most 4096 bytes and sanitizes decoder errors to avoid quoting key material. Unknown fields and duplicate-last-wins semantics remain. | Bound secret-bearing input and diagnostics. |
| The pinned engine logs idle-peer handshake failure as Error (`wireguard-go/device/send.go:135`). | Only `Failed to send handshake initiation: no known endpoint for peer` is demoted to Debug; keepalive remains 25 seconds and all other engine errors remain Error. | Endpoint absence before the first client handshake is normal; no dependency patch is applied. |
| Rust injects packets through its packet-source engine (`mitmproxy-rs/src/packet_sources/wireguard.rs`). | Bounded, nonblocking admission drops invalid/full-queue packets with logarithmically limited diagnostics. Caller owns the stack; shutdown joins engine/socket workers without waiting for proxy hooks. | Bound traffic-driven state without changing caller stack lifetime. |
| Python generates/reads one server_key/client_key and prints one configuration (`py:mitmproxy/proxy/mode_servers.py:349-388,392-415` at 3368a0a). | Legacy/default bytes unchanged; ordered Go-only `client_keys` is mutually exclusive, nonempty and unique by public identity, with at most 255 configured peers. Printed addresses remain `10.0.0.1/32` through `10.0.0.255/32`, with DNS/AllowedIPs unchanged. | Multi-key input and multiple printed configurations are Go-only extensions, defaults preserved. |
| Rust learns checked IPv4/IPv6 sources and routes by destination (`rs:src/packet_sources/wireguard.rs:254-298,321-333` at 51fe2b7). | Last authenticated successfully admitted sender owns the source. One least-recently-used (LRU) table retains at most 4096 learned IPv4/IPv6 sources per listener, shared across all configured peers, not 4096 per peer. Destination hits and admitted relearning refresh recency. There is no per-peer reservation: one peer can displace another. Missing or evicted destinations use the first configured peer until a newly admitted authenticated packet relearns sender ownership. | Bound aggregate learned-source state while preserving authenticated admission and deterministic Go fallback versus Rust `HashMap.values().next()` (:117, :331); Go learns after admission, Rust inserts before `try_send`. |
| Rust selects peers within its packet-source engine (`rs:src/packet_sources/wireguard.rs:62-100,197-199,321-333`). | One unchanged wireguard-go device per peer/shared UDP socket; initiation fanout; outgoing type1/2 sender indices route incoming response/cookie/data; collision fanout only to registered devices. | Authentication stays in wireguard-go; separate devices overcome shared AllowedIPs/TUN identity constraint without dependency patch; per-peer overhead accepted. |
| Handshake ownership/rekey mapping is backend-specific, not a Rust protocol extension. | Indices expire after twice RejectAfterTime (360 s), prune on registration, never receive expired packets; bounded nonblocking queues. Source routes have no TTL but remain only while resident in the listener's shared LRU. | Bound obsolete handshake state and learned-source retention while preserving rekeys and caller-owned stack/shutdown. |

Core encrypted TCP/UDP component tests alone do not prove full CLI-addon or
privileged/platform acceptance. Script loading (`-s`) is available in the default frontends, but the retained
WireGuard acceptance uses a subprocess DumpMaster harness with default addons and an uppercasing TCP/UDP addon
registered through `Manager.Add`; it exercises the proxyserver/Handler/flow path, not a scripted WireGuard flow. TUN acceptance uses
the built CLI.

## internal/tun

| Upstream | Go | Reason |
|---|---|---|
| rp_filter contents are compared raw with `"0"`, so procfs's newline causes redundant traversal/write/debug output (`mitmproxy-rs/src/packet_sources/tun.rs:183-211`). | Trims before comparison and returns early if disabled. Kernel end state is unchanged. | Avoid redundant configuration I/O. |
| Every rejected packet is logged with bytes (`mitmproxy-rs/src/packet_sources/tun.rs:142-143`). | Fixed no-payload malformed/full/segmentation diagnostics occur at most once per second per device. Valid returned GSO segments remain usable after `ErrTooManySegments`. | Bound logging and respect the pinned device API's nonfatal overflow contract. |

TUN creation is Linux-only. Kernel-specific ioctl context is Go-owned diagnostic text; the creation/refusal
prefixes retain upstream wording. Device MTU 65,535 and stack NIC MTU 1420 are distinct. Privileged device, routing
and cleanup acceptance are separate from descriptor/component tests.

## internal/local

The controller/IPC contracts below are connected to the local frontend described under
[internal/proxy/modeserver](#internalproxymodeserver). The proxyserver addon owns the platform daemon;
frontend Stop disables interception without closing that daemon. Installed native interception remains
separate from frontend/IPC integration.

| Upstream | Go | Reason |
|---|---|---|
| Installed Python packages resolve redirector resources (`mitmproxy-rs/mitmproxy-rs/src/server/local_redirector.rs:104-137`). | AcquireArtifact verifies pinned 0.12.11 platform-wheel SHA-256 in private staging, bounds archive entries/extracted bytes and atomically publishes/revalidates the cache. Explicit executable/macOS app overrides avoid downloads. | No Python resource lookup; cached native payloads must preserve verified integrity. |
| macOS copies/updates the app into /Applications using archive/Info.plist mtimes and MITMPROXY_KEEP_REDIRECTOR (`mitmproxy-rs/mitmproxy-rs/src/server/local_redirector.rs:138-155,171-213`). | Requires an installed app or explicit executable/app override. Acquisition returns a verified tar but does not install it or approve the extension. | Automatic installation/updating and OS approval remain separate native acceptance work, not reproduced or waived. |
| macOS starts its helper before a five-second control wait (`mitmproxy-rs/src/packet_sources/macos.rs:37-67,85-95`). | Starter completion/control connection share a bounded startup context; lifetime cancellation and Close release/join controller work. | Bound owned launch/IPC work; OS approval remains manual. |
| macOS handshake tasks have no explicit aggregate admission bound (`mitmproxy-rs/src/packet_sources/macos.rs:123-159,185-198`). | Bounds per-flow handshake/admission concurrency and pending TCP/UDP queues. Messages cap at 8 MiB; reads do not allocate solely from a prefix. Raw TCP tail is untouched. | Bound incomplete/unconsumed IPC state without mixing flows. |
| macOS UDP fixes destination at the first packet and has a ten-packet queue (`mitmproxy-rs/src/packet_sources/macos.rs:243-271`). | First packet stays readable; ten reserved slots include queued/in-flight packets. Destination change closes only that tuple. Empty/truncated packets and independent deadlines are preserved. | Retain native datagram identity with explicit Go ownership. |
| Linux truncates configuration to a twenty-action eBPF table (`mitmproxy-rs/mitmproxy-linux/src/main2.rs:142-155`, `mitmproxy-linux-ebpf-common/src/lib.rs:11`). | Rejects more than twenty encoded actions, including final own-PID exclusion, instead of truncating. Native command-name matching stays with the pinned executable. | Truncation can discard self-exclusion. |
| Native interception rules exclude the proxy's own process (`mitmproxy-rs/src/intercept_conf.rs`, `mitmproxy-rs/mitmproxy-rs/src/server/local_redirector.rs:39-51,64-83`). | Nonempty encoded rules end with the canonical own-PID exclusion; an existing normalized final exclusion is retained without duplication. Empty rules remain disabled, and DescribeSpec describes only the supplied rules. | `TestEncodeInterceptSpec` and `TestDescribeSpec` preserve grammar/default descriptions and explicit-final-own-PID behavior. `TestLocalIPCDefaultAndDaemonReuse` covers the frontend's default own-PID rule and daemon reuse; native process-attribution acceptance remains separate. |
| Linux/Windows use native message boundaries with 65,535 packet bytes plus 1024 IPC headroom (`mitmproxy-rs/src/packet_sources/mod.rs:45,67-89,118-124`, `src/network/mod.rs:14`). | Protobuf preserves native boundaries/caps with a sixteen-level known/unknown-group budget. Oversized/partial native messages are rejected; no macOS length prefix is added. | Bound parsing and prevent fragments becoming independent packets. |
| Windows starts an elevated executable through ShellExecuteW (`mitmproxy-rs/src/packet_sources/windows.rs:38-79,119-130`). | Uses ShellExecuteExW with an owned process handle, message-mode overlapped I/O, cancellation completion/join and bounded-stop errors. | Release owned handles/workers. An IPC timeout does not claim to cancel UAC approval. |
| Linux reports `Failed to elevate privileges` when sudo preflight fails (`mitmproxy-rs/src/packet_sources/linux.rs`). | Startup retains the `Failed to elevate privileges:` prefix and wraps the underlying process error; errorcheck still classifies the failure as exit 1. | Preserve the startup diagnostic while exposing the cause to Go callers; `TestLinuxElevationFailureStartupLog` uses a failing sudo subprocess fixture. |
| Upstream platform frontends launch the native redirectors (`rs:src/packet_sources/linux.rs`, `macos.rs`, `windows.rs`). | Native Linux local-mode interception is evidenced on the CI `ubuntu-26.04` privileged packet-modes job. The remote Debian 13 kernel 6.12 host cannot load the pinned redirector BTF. Native macOS and Windows capture, approval/elevation and process attribution remain manual acceptance through the [macOS](runbooks/local-mode-macos.md) and [Windows](runbooks/local-mode-windows.md) runbooks. | The Debian BTF failure is a host limitation, not a product finding. Synthetic IPC evidence is not driver activation or process attribution; native manual evidence remains absent until filled results are committed. |

Local frontend packet coverage uses subprocess and real-IPC fixtures rather than attaching a host interceptor,
as the WireGuard acceptance harness also separates subprocess proxy coverage from script loading. Linux
`TestLocalLinuxPacketIPCTCPOrigin` and `TestLocalLinuxPacketIPCOrigin` use the public controller with a
native-protocol Unix-datagram subprocess peer and real IPv4/IPv6 TCP/UDP origins. Windows
`TestLocalWindowsPacketIPCTCPNoElevation` and `TestLocalWindowsPacketIPCNoElevation` use a test-only
Redirector backed by real message-mode named pipes, native protobuf and real sockets, avoiding UAC in
unattended tests. This fixture is not a production launch seam or evidence of elevated driver activation.
These controller/IPC fixtures do not exercise the separately available Starlark script-loading path.

Native installed-app/system-extension capture on macOS, UAC/WinDivert process attribution on Windows, and
sudo/TUN/eBPF capture/reinjection on Linux remain manual acceptance boundaries. Native Windows synthetic
pipe/subprocess/ABI tests do not certify driver activation or real process-attribution capture.

## internal/processinfo

| Upstream | Go | Reason |
|---|---|---|
| On macOS an icon comes only from a running `NSRunningApplication` whose process executable matches the path; any other executable fails with `unable to extract icon` (`mitmproxy-rs/src/processes/macos_icons.rs:57-79`). | The running application whose `executableURL` path equals the requested path is used first. Otherwise `NSWorkspace iconForFile:` gives the icon for the existing, non-directory file, so a bundle-less executable such as a command-line tool or daemon gets the system icon for its file type. Missing paths, directories, and paths containing NUL or invalid UTF-8 return an error; no placeholder image is made up. | Every listed process can show an icon. Under `go test` the bundle-less test binary therefore gets the generic document icon, which is the expected native result. |
| The macOS TIFF representation is decoded with the `image` crate, resized to fit 32×32 with a triangle filter and encoded as PNG (`mitmproxy-rs/src/processes/macos_icons.rs:46-55`). | The icon's CGImage is drawn into a Quartz bitmap in the device RGB colour space (premultiplied alpha, RGBA bytes), fitted within 32×32 with its aspect ratio kept, and encoded as PNG in Go. A source image larger than 4096 pixels on either side is rejected before a bitmap is allocated, and the PNG is capped at 1 MiB. No sRGB colour management is applied, and pixel values can differ from upstream's resize. | Bound native memory and output size; Quartz scales the image, so no TIFF decoder is needed. |
| The icon cache maps every executable path and icon for the life of the process and is never cleared (`mitmproxy-rs/src/processes/mod.rs:36-38`, `macos_icons.rs:13-44`). | Icons are cached per path in a least-recently-used cache of at most 256 paths and 16 MiB of PNG data; identical PNGs are stored once. An evicted icon is fetched again. | Bound memory in a long-running proxy that sees many executables. |
| The process-wide icon cache sits behind one mutex (`mitmproxy-rs/src/processes/mod.rs:36-38`). | All AppKit and Quartz calls run under one mutex on a locked OS thread inside an autorelease pool, so concurrent `ExecutableIcon` calls that miss the cache wait for each other; cache hits make no AppKit call. | NSImage may be used by only one thread at a time, and goroutines move between OS threads. |
| Windows lists processes and their visibility with Win32 calls, including `IsWindowVisible`, `IsIconic` and the DWM cloak attribute, and reads icons with `ExtractAssociatedIconW` (`mitmproxy-rs/src/processes/windows_list.rs`, `windows_icons.rs`). | The Windows listing, icon and window-visibility code builds and passes `go vet` for windows/amd64 but has not run on Windows. No native Windows process list, icon, visibility or DWM-cloak result is claimed. A follow-up runs the shared and Windows-specific tests on a native Windows host or the `windows-2025` runner, decodes the real current-binary icon, records the desktop session type for the visibility check, and gets a scoped review of handle ownership and buffer bounds. | Native Windows CI is paused. This row changes only after that native evidence exists. |
