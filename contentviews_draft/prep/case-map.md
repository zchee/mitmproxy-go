# Interactive view case map

Model: claude-gpt-6.1-sol-ultrafast[1m]

Verified 2026-10-17 08:31:58 JST (command-derived date). Consumer base: `86e74ccf8b076b06041f8caba5349f23a2720b90`. Rust source checkout HEAD: `51fe2b7c5aa8439c162abb665db61c6669d146d6`. Python source checkout HEAD: `3368a0a06ae6195aad817a1ece1aaeb6fe0353a1`.

All Rust paths below are relative to `mitmproxy-contentviews/` in the pinned checkout. These identities reproduce the immutable plan appendix, not a new selection. Every terminal child runs 60 times in the focused campaign (count 20, CPU 1/2/8) and separately 15 times in the changed-package campaign (count 5, CPU 1/2/8). No skip, missing identity, partial run, or weakened assertion counts as completion.

## Paired protobuf vectors

Source `src/protobuf/view_protobuf.rs`. Each row expands to exactly two terminal children: `TestProtobufRoundTrip/upstream/<name>/prettify` and `TestProtobufRoundTrip/upstream/<name>/reencode`. The macro at lines 103–123 asserts literal output YAML and literal output bytes respectively. Semantic stability is additional, not a replacement.

| Name | Source lines | Required value |
|---|---|---|
| varint | 126 | 150 and zigzag alternative 75 |
| varint_zigzag_negative | 127 | 11 and zigzag alternative -6 |
| varint_int64_negative | 128–132 | signed -2, unsigned 18446744073709551614 |
| binary | 133 | !binary '010203' |
| string | 134 | hello |
| nested | 135 | field 5 contains field 1 |
| nested_twice | 136–140 | two nested field-5 levels |
| fixed64 | 141–145 | -1.0 with unsigned/signed bit alternatives |
| fixed64_positive | 146–150 | 3.14159 with unsigned bits |
| fixed64_no_float | 151–155 | -1 with unsigned bits; NaN not selected |
| fixed64_positive_no_float | 156–160 | 9221120237041090561 |
| fixed32 | 161–165 | -1.0 with unsigned/signed bit alternatives |
| fixed32_positive | 166–170 | 3.14159 with unsigned bits |
| fixed32_no_float | 171–175 | -1 with unsigned bits; NaN not selected |
| fixed32_positive_no_float | 176–180 | 2143289345 |
| repeated_packed | 183–187 | opaque binary 038e029ea705, not guessed packed integers |
| repeated_varint | 188–192 | ordered sequence 1,2,3 with zigzag comments |

Subtotal: 17 vector identities, 34 terminal children.

## Direct protobuf tests

| Exact terminal child | Source lines | Assertion retained |
|---|---|---|
| TestProtobufRoundTrip/upstream/direct/test_invalid_protobuf | view_protobuf.rs:195–198 | ff ff is an error |
| TestProtobufRoundTrip/upstream/direct/test_no_crash | view_protobuf.rs:201–209 | exact gRPC testing-server descriptor text, not merely no panic |
| TestProtobufRoundTrip/upstream/direct/test_empty_protobuf | view_protobuf.rs:212–215 | exact `{}  # empty protobuf message` without newline |
| TestProtobufDefinitions/upstream/existing_definition/prettify | view_protobuf.rs:223–230 | simple.proto changes field 1 to `example: 150` |
| TestProtobufDefinitions/upstream/existing_definition/prettify_mismatch | view_protobuf.rs:235–242 | valid mismatching string bytes fall back to numeric field YAML |
| TestProtobufDefinitions/upstream/existing_definition/reencode | view_protobuf.rs:245–252 | named field YAML emits original varint bytes |
| TestProtobufDefinitions/upstream/existing_definition/reencode_mismatch | view_protobuf.rs:255–262 | named field with string edit emits original string bytes |

RoundTrip total: 37 terminal children. Definitions upstream subtotal: 4.

## gRPC tests

Source `src/protobuf/view_grpc.rs`. Preserve literal TEST_YAML/TEST_GRPC/TEST_GZIP/TEST_DEFLATE at lines 119–134, plus actual request direction, path and definitions metadata.

| Exact terminal child | Source lines | Assertion retained |
|---|---|---|
| TestGRPC/upstream/test_empty | 136–140 | empty text |
| TestGRPC/upstream/test_prettify_two_messages | 142–146 | exact separator and two texts |
| TestGRPC/upstream/test_prettify_gzip | 148–153 | gzip payload and header |
| TestGRPC/upstream/test_prettify_deflate | 155–160 | raw DEFLATE payload and header |
| TestGRPC/upstream/test_reencode_two_messages | 162–166 | literal two uncompressed frames |
| TestGRPC/upstream/test_render_priority | 168–184 | both application/grpc=1 and text/plain=0 |
| TestGRPC/upstream/existing_definition/existing_proto | 191–199 | simple.proto named fields |
| TestGRPC/upstream/existing_definition/existing_service_request | 201–212 | /Service/Method request uses Empty; numeric unknown field |
| TestGRPC/upstream/existing_definition/existing_service_response | 214–225 | /Service/Method response uses Response; named field |
| TestGRPC/upstream/existing_definition/existing_package | 227–237 | /example.simple.Service/Method resolution |
| TestGRPC/upstream/existing_definition/existing_nested | 239–249 | /example.nested.Service/Method resolution |
| TestGRPC/upstream/existing_definition/existing_mismatch | 253–261 | mismatch.proto safely falls back to numeric fields |

Subtotal: 12 terminal children.

## MsgPack tests

Source `src/msgpack.rs`. Preserve literal TEST_MSGPACK and TEST_YAML at lines 59–77.

| Exact terminal child | Source lines | Assertion retained |
|---|---|---|
| TestMsgPack/upstream/test_msgpack_deserialize | 79–85 | exact YAML order/indent/newline |
| TestMsgPack/upstream/test_msgpack_serialize | 87–119 | map shape; name John Doe; numeric age 30; two tags developer/rust |
| TestMsgPack/upstream/test_msgpack_roundtrip | 121–139 | decoded original and reencoded values equal |
| TestMsgPack/upstream/test_invalid_yaml | 141–147 | Invalid YAML error class/prefix |

Subtotal: 4 terminal children.

## Existing schema fixtures

Use the existing consumer bytes at `testdata/mitmproxy-rs/contentviews/protobuf/`, not new imported copies. Source root `testdata/protobuf/`.

| Exact terminal child | File/lines | Descriptor assertion |
|---|---|---|
| TestProtobufDefinitions/fixtures/mismatch.proto | mismatch.proto:1–5 | TestMessage.example field 1 is string |
| TestProtobufDefinitions/fixtures/nested.proto | nested.proto:1–17 | example.nested.Service.Method input Empty/output Response; Response.Nested.example int32; Response.nested message |
| TestProtobufDefinitions/fixtures/simple.proto | simple.proto:1–5 | TestMessage.example field 1 is int32 |
| TestProtobufDefinitions/fixtures/simple_package.proto | simple_package.proto:1–18 | package example.simple, ordered Other then Service, Method input Empty/output Response, Response.example int32 |
| TestProtobufDefinitions/fixtures/simple_service.proto | simple_service.proto:1–16 | ordered Other then Service, Method input Empty/output Response, Response.example int32 |

Fixture subtotal: 5. Definitions total: 9. All four frozen groups total: **62 terminal children** (37 + 9 + 12 + 4).

## Additional certification, not substitutes

`TestContentviewLimits`, `TestContentviewMetadata`, registry selection/no-mutation, priority aliases, byte/YAML malformed inputs, unsupported schema-map edits, tag errors, field-number/wire errors, per-call aggregate budgets, descriptor changes, symlink/import boundaries, and concurrent calls are extra local identities. `FuzzMsgPack`, `FuzzProtobuf`, `FuzzProtobufReencode`, `FuzzGRPC` each receive the pinned seeds plus bounded malformed seeds and run for 30 seconds with one worker after their implementations exist. The first draft will not claim absent adapters, absent tests, or excluded draft files pass these gates.
