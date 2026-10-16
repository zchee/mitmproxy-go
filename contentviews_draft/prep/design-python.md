# Python contentview design

Model: claude-gpt-6.1-sol-ultrafast[1m]

Read against Python `3368a0a06ae6195aad817a1ece1aaeb6fe0353a1`; source inspection timestamp 2026-10-17 08:56:43 JST (date command). Consumer fixtures are already imported at `68a413e604c9c37ef5a902bc9d54ca0f909150db`. The immutable case identities are in case-map-python.md. This is preparation only: source remains in contentviews_draft/, and production registration waits for recorded transfer and the first Rust-view landing.

## Common boundaries and delivery

Each view keeps View signatures, exact upstream names, syntax strings and priorities. New calls have 64 MiB input/output limits, depth 64 and 1,000,000 logical nodes/entries. Validate declared counts/lengths against remaining input before allocation; reserve escaped text growth before emitting. Use the shared typed LimitError and per-call budget, never a global option. Existing registry/Raw/error/cutoff behavior remains unchanged.

The shared YAML proposal is parseBoundedYAML plus dumpBoundedYAML/emitBoundedYAML, using one budget and a bounded writer. Before transfer, thin draft interfaces remain replaceable rather than inventing a second YAML parser. The final consumer uses the landed adapter; draft fixture adapters are not production preflight evidence.

Deliver the simple independent views first (GraphQL, MQTT, Socket.IO), then WBXML, ZIP and HTTP/3. One coherent view plus tests/fuzz seeds per signed push, no PR from the preparation branch. Existing fixtures and shared docs stay read-only. The frozen default and differential sets contain 33 terminal children each; local safety sensitivities are additional.

## GraphQL

Source `_view_graphql.py:8–69`. Parse with the existing ordered JSON machinery where possible; keep object insertion order and Python number/string semantics. A single object qualifies only when query exists and its string contains a newline. A batch qualifies when nonempty and its first object contains query; formatting still validates every later operation rather than panicking on a malformed element. Wrong shape yields a finite error.

Clone the operation's header representation, replace its query value at the same key position with `...`, and emit Python json.dumps indentation 2 followed by `\n---\n`, original query and final newline. Batch operation i is preceded by `--- i/(count-1)\n`. Do not mutate the decoded input or metadata. Priority 2 requires nonempty application/json and the same shape predicate; malformed JSON/wrong MIME have priority 0. Syntax defaults to none, not YAML/JSON highlighting.

The existing contentviews/json.go reader already retains ordered object positions, duplicate-key behavior, scalar formatting and surrogate handling. Integration should share that machinery with narrowly parameterized indentation/ASCII-escaping while keeping existing JSON formatting unchanged. GraphQL's Python json.dumps uses ensure_ascii=True; the current JSON view's formatter behavior must not be blindly copied. Before any DOM/map construction, a jsontext token pass charges node/depth limits. Output goes through a bounded writer; query and header expansion share the same limit. No GraphQL query parser or network call is needed.

## MQTT

Source `_view_mqtt.py:10–277`. Parse the fixed header, remaining-length varint, declared body, two-byte length-prefixed fields, and only the supported payload shapes. Keep the upstream packet-name table and exact [PINGREQ]/[PINGRESP], unsupported-type messages, PUBLISH body/topic quoting, SUBSCRIBE topic list, and CONNECT multiline fields/final newline. The pinned remaining-length parser rejects a fourth length byte; do not silently expand its acceptance to a different protocol version.

Use bounded cursor reads; validate every field before slicing; charge topic/CONNECT entries before append. Recognize PUBLISH QoS and skip its packet ID for QoS 1/2. Parse CONNECT's fixed ten-byte variable header, flag-driven client/will/username/password fields and strict UTF-8 text. Preserve None for absent optional fields. Deduplicate repeated subscription topics at their first position, as Python's insertion-ordered dict does. Binary payload and password display use the existing strutil.BytesToEscapedStr semantics rather than ad-hoc quoting. No credentials are logged or included in failure diagnostics; rendering intentionally displays selected fields as upstream does.

The view has no automatic selection override in the pin, so its priority stays the base value 0. No broker, socket, connection state or MQTT transport behavior is introduced. Malformed/truncated length fields are finite errors, with no guessed bytes or out-of-bounds indexing.

## Socket.IO

Source `_view_socketio.py:20–95`. Parse one Engine.IO byte in 0–6; if it is MESSAGE (4), parse one Socket.IO byte in 0–6. Missing/invalid packet bytes are finite errors. Engine.IO PING/PONG and Socket.IO ACK/BINARY_ACK produce empty output. Other packets emit exact `EngineIO.NAME ` or `SocketIO.NAME ` plus strutil byte escaping; an empty payload still retains the separating space. Do not implement a transport or packet accumulator.

Priority 1 requires nonempty data, a real HTTPFlow with nonnil WebSocket state and `/socket.io/?` in the flow request path. An HTTP request alone or a non-WebSocket flow is insufficient. Preserve syntax none and public name Socket.IO. Test no metadata mutation and repeat calls independently.

## WBXML

Read all seven contrib source files. The vocabulary is exactly the 25 pages in ASWBXML.py:55–815 (including the retired empty AirNotify page), plus GlobalTokens.py:30–50. Generate unexported read-only Go array literals with explicit token indexes; no mutable map construction on every render and no newer vocabulary. Retain the full David P. Shaw 2014 MIT notice with copied tables/provenance.

Implement an iterative cursor and a bounded node/element stack. Read/ignore version and public ID as the source does, require charset 0x6a and zero string-table length, then consume page switch, END, STR_I, OPAQUE and supported tag tokens. Reject unknown page, unsupported global token, attribute-bearing tag and unrecognized tag. Reserve nodes and depth before pushing; check multibyte integers, inline terminators and opaque lengths before copying. Unlike the upstream blocking Queue.get path, a truncated token/string returns a finite error. Do not feed malformed vectors that may block into an unbounded differential oracle.

Reproduce byte-to-character semantics: each payload byte becomes the corresponding Unicode code point, not a UTF-8 decode. Tags are bare names; the source does not emit the page namespace/xmlns. Match the XML declaration, four-space indentation, self-closing empty elements and inline single text/CDATA child formatting from minidom. Use a bounded XML serializer over the small explicit node structure, preserving text versus CDATA and escaping exactly as required by the imported golden. Do not use Go's default XML marshal formatting as an assumed equivalent. Empty body after the four-byte header emits only `<?xml version="1.0" ?>\n`.

Local tests cover all page-table identities, page changes, depth/node/output bounds, attribute/unknown-global refusal, multi-byte/unterminated string truncation and exact fixture output. EOF behavior for a complete open element stack must be oracle-checked separately rather than conflated with incomplete token reads.

## ZIP

Source `_view_zip.py:9–19`; public name ZIP Archive, syntax yaml, priority 1 only for nonempty application/zip. List central-directory names without opening entries or decompressing data. Empty listing emits exactly `(empty zip file)`.

Before archive/zip.NewReader, perform a bounded structural preflight over the immutable capped byte slice. Locate the effective EOCD/ZIP64 end record and validate its disk/count/range fields and base-prefix arithmetic. Scan every actual central-directory record the reader will consume: check signature, 46-byte fixed header, filename/extra/comment lengths and remaining bytes; charge the actual entry and cumulative metadata/name budget before any File allocation. Declared EOCD count alone is not a bound. Reject overflow, overlap/truncation and invalid ZIP64 lengths. Reader construction happens only after this proof; tests count constructions and require zero for rejected forged-low-count or oversized metadata cases.

Use archive/zip's nonnil reader even when it returns ErrInsecurePath; never change GODEBUG. Other errors fail. Recheck actual reader count against the preflight for consistency. Decode each raw filename using flag bit 11: strict UTF-8 when set, otherwise CP437 via existing x/text/charmap.CodePage437, even when bytes happen to form valid UTF-8. Preserve central-directory order and YAML string escaping through the shared emitter. Fixture sensitivities include CP437, UTF-8 flagged, valid UTF-8 flag-clear, invalid flag-set UTF-8, insecure path names and ZIP64 arithmetic.

## HTTP/3 Frames

Source `_view_http3.py:18–150`. Public name HTTP/3 Frames, syntax none. Priority 2 requires TCPFlow and HTTP/3 ALPN on its client connection. No network endpoint or QPACK policy changes.

Unlike upstream's indefinitely retained per-flow defaultdict, reconstruct from the immutable flow message snapshot per call. Locate the selected TCPMessage by pointer identity, then replay messages in order with separate client/server partial buffers. Charge aggregate replay bytes and frames before buffering. If quic_is_unidirectional is true, decode the initial stream type from the appropriate first stream bytes with checked QUIC-varint reads. Handle partial prefix/body without guessing; assign a completed frame to the message that supplies its final bytes. Return only that selected message's annotations, with `\n\n` between frames. Repeated renders, appends, old-message selection and two directions/flows cannot share mutable state.

Reuse the existing github.com/quic-go/qpack codec used by internal/h3/qpack.go; its private endpoint helpers are not callable from contentviews and must not be exported or modified merely for this display view. Decode supported static/literal headers preserving order, and render unsupported/malformed dynamic sections as HEADERS error plus existing HexDump output. Use no endpoint settings/capacity changes. Settings IDs display known names or lowercase hex keys, values hex; malformed settings display error plus hex. Frame labels DATA, HEADERS, SETTINGS, unknown hex and stream names match upstream. Error wording from the different QPACK library is a documented deviation, not an excuse to normalize other text.

Replay costs O(total bytes through the selected snapshot) per render and stores at most the bounded partial buffers/output, with no global cache. Tests cover all literal upstream flow vectors, partial frame completion attribution, stream-type truncation, malformed varints/settings, independent rerender/append/directions and aggregate bounds.

## Certification boundary

No parser inherits safety merely by calling another library. YAML-native preflight, ZIP central-directory preflight, WBXML bounded cursor/stack and HTTP/3 replay budgets are explicit local checks. The complete six default and differential groups plus six 30-second fuzzers remain required after binding and registration; preparation tests do not claim those absent gates passed.
