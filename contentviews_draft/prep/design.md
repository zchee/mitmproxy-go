# Interactive view implementation design

Model: claude-gpt-6.1-sol-ultrafast[1m]

Prepared against consumer `86e74ccf8b076b06041f8caba5349f23a2720b90` and Rust `51fe2b7c5aa8439c162abb665db61c6669d146d6`. Source inspection date: 2026-10-17 08:31:58 JST (date command).

## Ownership and staging

Until the lead records transfer, `contentviews/**` is read-only. Draft source and tests live in root `contentviews_draft/`, with no registry changes and no go.mod/go.sum changes. The draft reuses the existing public Metadata alias where possible. It is preparation, never a landable view candidate. MsgPack/schema consumers that require absent dependency adapters remain build-excluded until those adapters land; do not fake them with stubs. After transfer, integrate against the actual `yaml_bounded.go`, `msgpack_codec.go`, and `protobuf_schema.go` APIs rather than preserving duplicate draft infrastructure.

The production sequence is MsgPack + registration, then protobuf/schema + metadata sibling, then gRPC + registration. A single author owns the package. Each coherent production candidate must pass its nonempty exact subset of the frozen inventories, local sensitivities, applicable fuzz, unchanged-contract gates and scoped decoder review before a PR can land.

## Shared resource seam

One mutable per-call budget, passed by pointer through every parse, classification attempt, schema-assisted attempt, fallback, frame, YAML document and emission. No global mutable parser/schema state. Encoded input and output each cap at 64 MiB; decompressed gRPC bytes cap at 64 MiB aggregate; collection/message depth caps at 64; logical work caps at 1,000,000 nodes/fields/entries. Check additions as `cost > limit-used`, never overflowing counters. Validate lengths against remaining bytes before slicing or allocating. Charge wire field entries, generated YAML keys/values/containers, and nested probes before construction; a rejected speculative nested parse still spends work.

A stage-labelled typed limit error supplies view/stage/bound, not payload or schema source text. Limits are explicit compatibility restrictions separate from content_decode_limit and add no user option.

Input is bounded before snapshot copying. Reencoding uses the shared native-event preflight before any YAML Loader/Composer creation. Count documents, scalars, mapping/sequence starts and aliases; mapping keys and values count separately. Anchor metadata and effective alias expansion are bounded, cycles rejected. Use the identical bounded bytes/options for the composition pass. The bootstrap owns the 1,000,001-child / zero-composed-node proof. No draft hand-written YAML scanner may replace it. Generated nodes reserve budget before allocation. A bounded writer feeds `yaml.NewDumper`, accounting for escapes, separators and framing before growth; no dump-then-length-check path.

## Protobuf ordered field model

Use `protowire.ConsumeTag`, `ConsumeVarint`, `ConsumeFixed32`, `ConsumeFixed64`, and `ConsumeBytes`; inspect negative byte counts before advancing. A field carries its number, wire type, raw integer bits or borrowed payload bytes, and occurrence order. Group fields in numeric order for unknowns while retaining value order within each field. No float conversion in the wire layer. Reject invalid field numbers/wire forms; group acceptance/rejection must be checked against the actual pinned Rust oracle, not old Python text fixtures.

Unknown length-delimited values are classified per field, across all occurrences, as in raw_to_proto.rs:165–195: strict UTF-8 containing ASCII graphic or ASCII whitespace first (including vacuously empty strings); otherwise probe nested protobuf and accept only compatible complete parses for all occurrences; otherwise binary. Repeated fields emit a YAML sequence even when the underlying field values are heterogeneous only where the Rust parser permits that shape. Invalid mixed wire types fail according to the oracle. Bare binary becomes lowercase hexadecimal under `!binary`, with YAML scalar quoting controlled by the YAML emitter, not a textual global replacement.

Use node kinds and tags, not protojson/prototext. Unknown keys are integers. Known descriptor fields use their declared names/order; unknown fields follow in numeric order. Scalars retain bool, integer, float, enum name/unknown enum number, string, byte and nested-message semantics. Duplicate values are sequences. The five public local tags are `!varint`, `!sint`, `!fixed32`, `!fixed64`, `!binary`.

Numeric display ports yaml_to_pretty.rs:21–108 directly into node value/comment construction: candidates are ordered unsigned, float where eligible, signed where the sign bit is set. Choose minimum `(type-name length, rendered-value length)` with stable first tie. Fixed floats participate only when not NaN and absolute magnitude exceeds 0.0000001; retain .0 for integral floats. A varint with the high bit clear displays unsigned and comments !sint; high bit set compares signed/unsigned and omits zigzag. The selected visible varint is untagged; fixed tags stay on the scalar. This avoids regex edits to user strings and preserves exact pinned vector text.

Empty protobuf is exactly `{}  # empty protobuf message`, without newline. Ordinary YAML maps use the upstream two-space indentation, indentless sequences and final newline. Exact vector tests must expose any emitter style differences before the draft is promoted.

Reencode accepts mapping roots; string keys resolve descriptor name then numeric field number, numeric keys require valid integral field numbers. Null omits; sequences add repeated occurrences; strings encode bytes; booleans encode varints; integer numbers encode varints unless descriptor fixed wire kind applies; floating numbers use fixed64 unless descriptor selects fixed32. Explicit fixed tags preserve raw bits for integer scalars and reinterpret floating scalars. `!sint` requires an int64 and uses zigzag. `!binary` requires a string of even valid hex length before allocation. Unknown tags follow upstream discard-and-recurse semantics, with bounded diagnostic logging. Known schema maps retain the upstream unsupported edit shape as a documented tested error, not a TODO branch.

## Schema loader and dynamic values

Consume the bootstrap protocompile v0.14.1 loader and its bounded local resolver, never network imports or protoc. Inputs are one explicit file or recursive root. At most 1024 files, 16 MiB per file, 64 MiB source aggregate and 64 import/directory depth; bound reads with limit+one, track canonical identities, deduplicate imports and detect cycles/symlink traversal outside allowed roots. Standard well-known descriptors are the only non-root resolution source. No indefinite global schema cache; subsequent calls observe file changes.

Resolve `/pkg.Service/Method` from the HTTPFlow request path. Any query or extra slash component makes RPC matching ineligible. Search matching package/service/method, choosing request input or response output. Preserve the pinned fallback sequence: matching top-level message named by method where applicable, then first file's first service/method, then first message. Bootstrap ordering must be deterministic and preserve each source's descriptor order. A schema parse error is an error, never silent unknown-proto success.

Use `dynamicpb` for known-field descriptor semantics while retaining the ordered wire model for unknown bytes, duplication and type-mismatched edits. A wire/descriptor mismatch retries schema-less once, spending the same remaining budget, and only a successful fallback emits `Existing protobuf definition does not match, parsing as unknown proto.` (gRPC uses its own exact message). No fallback resets work or decompression counters. Schema-map edits are tested and rejected clearly until upstream defines them.

## gRPC

Read the five-byte frame header without allocation: byte 0 must be 0 or 1, bytes 1–4 are big-endian u32 length, and the complete declared body must fit. Header-selected `grpc-encoding` matters only for flag 1: gzip uses gzip reader; deflate uses raw flate reader, not zlib; identity passes bytes unchanged; any other value fails. Bounded streamed reads reject aggregate expanded size before proportional growth. Corrupt/truncated compressed streams fail; do not return completed earlier frames on any later failure.

Resolve one schema per call, then render frames with the same budget. If a descriptor mismatch requires retry, retry the full call with the same consumed budget. Join with exactly `\n---\n\n`, reserving separator bytes. Empty wire input returns empty text. Reencode each preflighted YAML document to protobuf and append flag 0 plus checked u32 length and payload; preserve empty-input behavior from the actual YAML iterator, and reject framing/output growth before writing.

## Metadata sibling and unchanged contracts

Keep `PrettifyMessage(message any, f flow.Flow, viewName string, registry *Registry, lineCutoff int) Result` unchanged and make it delegate with `Metadata{Flow:f}` to `PrettifyMessageWithMetadata(message any, metadata Metadata, viewName string, registry *Registry, lineCutoff int) Result`.

Refactor only the existing extraction helper to retain Flow and ProtobufDefinitions while deriving message pointers/protocol/content type from the actual message argument. Never trust stale caller message pointers. Request/response direction uses actual identity: a Request is request; a Response is response; an explicit *httpmsg.Message compares against the flow request's embedded Message. The path comes from flow request (or explicit request when flow-less). Header lookup uses the rendered HTTP message. Preserve all existing missing-body, decoded-body, auto Raw fallback, explicit-error, panic containment, control escaping and cutoff behavior. Test input/metadata nonmutation and concurrency with an injected capturing View, not a mock protocol service.

## Verification and decision points

The case-map enumerates 62 upstream terminal identities. Add deterministic counters/limited-reader tests for all bounds, including aggregate multi-frame/document/retry work, oversized declared lengths, aliases, malformed hex, depth, schema cycles/changes, and output escape growth. Preallocate only after reservation; never demonstrate memory safety with wall-clock thresholds. Four fuzzers cover binary decoding and YAML reencoding with small malicious-length seeds, not giant corpus blobs.

Alternative rejected: protojson/prototext loses required numeric keys/tags/comments and unknown-field fidelity. Alternative rejected: map[string]any loses nonstring MsgPack keys, ordering and numeric bits. The chosen explicit ordered models add code but preserve editable wire semantics and bounded allocations; no service/network work is introduced. Main bottleneck is exact YAML formatting and schema merge fidelity, not CPU parallelism. No throughput/scalability performance claims are made before measurement.

Stop for a lead decision if pinned oracle conflicts with the immutable case set, bootstrap signatures cannot carry the shared aggregate budget, group wire semantics cannot be matched safely, or emitter differences cannot preserve exact goldens. Missing adapters and the recorded ownership transfer are current production blockers, not failed certification.
