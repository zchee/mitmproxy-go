# Python contentview case map

Model: claude-gpt-6.1-sol-ultrafast[1m]

Source inspection: 2026-10-17 08:56:43 JST (date command). Python pin: `3368a0a06ae6195aad817a1ece1aaeb6fe0353a1`. Consumer fixture base: `68a413e604c9c37ef5a902bc9d54ca0f909150db` (imported bytes under `testdata/mitmproxy/contentviews/`). This reproduces the approved plan's frozen identities; it does not define a replacement inventory.

For each row below, create BOTH the default parent and its identically suffixed Differential parent. Default terminal children execute 60 times in the focused campaign and 15 times in the changed-package campaign; differential children execute once against the pinned Python. Preserve all statements/assertions in a nonparameterized source function, not merely the first successful call.

## GraphQL

Parents: `TestGraphQL` and `TestGraphQLDifferential`. Source root: `test/mitmproxy/contentviews/test__view_graphql.py`.

| Child suffix under each parent | Source lines | Assertions retained |
|---|---|---|
| upstream/test_render_priority | 9–26 | Object and batch priority 2; wrong MIME, xquery, empty list and malformed JSON priority 0 |
| upstream/test_format_graphql | 29–30 | Format the literal query object successfully |
| upstream/test_format_query_list | 33–34 | Format the literal one-query batch successfully |
| upstream/test_view_graphql | 37–45 | Object and batch prettify; valid JSON string rejects as non-GraphQL |

Expected terminal count: **4 per parent**.

## MQTT

Parents: `TestMQTT` and `TestMQTTDifferential`. Source: `test/mitmproxy/contentviews/test__view_mqtt.py`.

| Child suffix under each parent | Source lines | Assertions retained |
|---|---|---|
| upstream/test_view_mqtt/PINGREQ | 10, 50–52 | c000 → exact [PINGREQ] |
| upstream/test_view_mqtt/PINGRESP | 11, 50–52 | d000 → exact [PINGRESP] |
| upstream/test_view_mqtt/SUBACK | 12–14, 50–52 | Exact unsupported packet text |
| upstream/test_view_mqtt/UNSUBSCRIBE | 15–19, 50–52 | Exact unsupported packet text |
| upstream/test_view_mqtt/SUBSCRIBE | 20–24, 50–52 | Full literal packet and quoted topic-filter list |
| upstream/test_view_mqtt/PUBLISH | 25–31, 50–52 | Full literal packet and exact body/topic text |
| upstream/test_view_mqtt/CONNECT | 32–47, 50–52 | Full literal packet; client ID, will topic/body, None user/password and final newline |
| upstream/test_mqtt_malformed/c0ffffffff | 55–58 | Literal overlong remaining-length field rejects |

Expected terminal count: **8 per parent**. The seven packet identities retain their full names, not abbreviations. These are display parsers, not broker/service tests.

## Socket.IO

Parents: `TestSocketIO` and `TestSocketIODifferential`. Source: `test/mitmproxy/contentviews/test__view_socketio.py`.

| Child suffix under each parent | Source lines | Assertions retained |
|---|---|---|
| upstream/test_parse_packet | 11–14 | EngineIO.OPEN payload; SocketIO.CONNECT empty and nonempty payload |
| upstream/test_view | 17–29 | HTTP/1.1 and GET errors; visible 0, 6, 40, 42, 42eventdata; incomplete 4 error; invisible 2 empty output |
| upstream/test_render_priority | 32–41 | Empty/no-flow/ordinary WebSocket paths reject; nonempty WebSocket with /socket.io/? matches; empty still rejects |

Expected terminal count: **3 per parent**.

## WBXML

Parents: `TestWBXML` and `TestWBXMLDifferential`. Source: `test/mitmproxy/contentviews/test__view_wbxml.py`.

| Child suffix under each parent | Source lines | Assertions retained |
|---|---|---|
| upstream/test_wbxml | 9–21 | 03016a00 emits exact XML declaration; foo errors; imported data.wbxml equals imported data-formatted.wbxml byte-for-byte |
| upstream/test_render_priority | 24–31 | Both registered MIME types match nonempty bytes; text/plain does not |

Expected terminal count: **2 per parent**. Use existing fixture paths `testdata/mitmproxy/contentviews/test_wbxml_data/{data.wbxml,data-formatted.wbxml}`; no new copy. Table provenance: `mitmproxy/contrib/wbxml/ASWBXML.py:55–815`; parser: 828–903; all imported code-page strings retain the David P. Shaw MIT notice.

## ZIP

Parents: `TestZIP` and `TestZIPDifferential`. Source: `test/mitmproxy/contentviews/test__view_zip.py`. Helper `meta` at 9–15 is not a test; retain its media-type stripping and HTTP-message context when forming metadata.

| Child suffix under each parent | Source lines | Assertions retained |
|---|---|---|
| upstream/test_view_zip | 18–40 | Create all six literal filenames in order; assert all six literal substrings and YAML syntax |
| upstream/test_view_zip_empty | 43–49 | Empty archive emits exact (empty zip file) |
| upstream/test_render_priority | 52–55 | Nonempty application/zip=1; wrong MIME=0; empty=0 |
| filename_encoding/cp437 | Plan-fixed addition | Flag-clear filename bytes decode as CP437 |
| filename_encoding/utf8_flagged | Plan-fixed addition | Bit-11 filename bytes decode as strict UTF-8 |
| filename_encoding/valid_utf8_flag_clear | Plan-fixed addition | Valid UTF-8 byte sequence with bit 11 clear still decodes as CP437 |

Expected terminal count: **6 per parent** (3 upstream plus 3 fixed additions). Additional local sensitivities: invalid bit-11 UTF-8; insecure-path policy independence; structural count/length preflight; zero reader construction on rejection. They do not replace the fixed set.

## HTTP/3 Frames

Parents: `TestHTTP3Frames` and `TestHTTP3FramesDifferential`. Source: `test/mitmproxy/contentviews/test__view_http3.py`. Every fixture creates the literal TCPFlow/TCPMessage metadata, direction (`len(data)>16`) and quic_is_unidirectional flag used upstream.

| Child suffix under each parent | Source lines | Assertions retained |
|---|---|---|
| upstream/test_view_http3/headers | 13, 27–30 | Full literal HEADERS input produces text |
| upstream/test_view_http3/broken_headers | 15, 27–30 | Full malformed QPACK input produces diagnostic/hex text |
| upstream/test_view_http3/headers_and_data | 17–23, 27–30 | Full combined HEADERS and HTML DATA input produces text |
| upstream/test_view_http3/empty | 24, 27–30 | Empty input renders empty |
| upstream/test_view_http3_unidirectional/settings | 37, 48–51 | Control stream plus literal SETTINGS produces text |
| upstream/test_view_http3_unidirectional/unknown_setting | 39, 48–51 | Unknown setting uses hexadecimal key |
| upstream/test_view_http3_unidirectional/out_of_bounds | 41, 48–51 | Invalid/incomplete setting produces diagnostic text |
| upstream/test_view_http3_unidirectional/incomplete | 43, 48–51 | Incomplete frame still renders its stream type |
| upstream/test_view_http3_unidirectional/qpack_encoder_stream | 45, 48–51 | Stream type 2 renders QPACK Encoder Stream |
| upstream/test_render_priority | 54–55 | No-flow random bytes do not match |

Expected terminal count: **10 per parent**. The actual implementation additionally tests attribution to the message completing a frame, append/rerender, old-message selection, both directions, two-flow isolation and aggregate bounds.

## Inventory total and fuzz

Default frozen terminal set: **33** = 4 + 8 + 3 + 2 + 6 + 10. Differential frozen terminal set: **33**. Six implemented fuzz targets are required before final acceptance: `FuzzGraphQL`, `FuzzMQTT`, `FuzzSocketIO`, `FuzzWBXML`, `FuzzZIP`, `FuzzHTTP3Frames`; each runs 30 seconds with one worker, exact upstream seeds and small malformed-length/truncation seeds. Draft tests are not a substitute for that complete final campaign or for the real bounded frontend.
