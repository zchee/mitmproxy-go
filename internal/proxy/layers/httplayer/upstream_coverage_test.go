// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

// Upstream coverage at mitmproxy 3368a0a. Source paths are relative to
// test/mitmproxy/proxy/layers/http. Each row names an upstream test function,
// with class qualification where needed, and its Go cases in this package.
// Counts: 55 functions, 54 ported, one partially ported, none not applicable.
// The only deferred branch is WebSocket protocol dispatch in test_upgrade;
// its TCP/disabled-protocol branches and the HTTP/1 upgrade bytes are covered.
// The WebSocket branch belongs to the HTTP/2, WebSocket and gRPC protocol phase.
// There are no HTTP/2-only or HTTP/3-only functions in these two pinned files.
// Deliberate representation differences are documented in docs/compat.md.
//
// test_http.py:
//
// Upstream function                              | Go cases / coverage
// ---------------------------------------------- | -------------------
// test_http_proxy                                | TestLayerWireRoundTrips/absolute_target_with_query; TestLayerRegularExchanges
// test_https_proxy                               | TestLayerConnectHTTPMatrix (eager/lazy, Host present/absent)
// test_redirect                                  | TestLayerRedirect (source/destination schemes, request/requestheaders)
// test_multiple_server_connections               | TestLayerMultipleRewrittenDestinations; TestLayerRegularExchanges
// test_pipelining                                | TestLayerWireRoundTrips/pipelined_identity_responses and pipelined_chunked_responses
// test_http_reply_from_proxy                      | TestLayerSyntheticResponse; TestStreamSyntheticResponseAndInformational
// test_response_until_eof                         | TestLayerWireRoundTrips/response_ends_at_EOF; TestHTTP1ClientReadUntilClose
// test_disconnect_while_intercept                 | TestLayerDisconnectWhileIntercepted (origin retirement before resume)
// test_store_streamed_bodies                      | TestLayerStoredStreamTransforms; TestStreamTransforms (stored/discarded)
// test_response_streaming                         | TestLayerResponseStreamingMatrix (identity/chunked, thresholds)
// test_stream_modify                              | TestStreamTransforms; TestLayerStoredStreamTransforms (both directions, final flush)
// test_request_streaming                          | TestLayerRequestStreamingMatrix; TestLayerEarlyResponseKeepsUploadUntilOriginCloses
// test_body_size_limit                            | TestLayerBodyLimitWire; TestStreamThresholdAndLimits; TestStreamResponseLimit
// test_server_unreachable                         | TestLayerLazyConnectFailure; TestStreamConnect/eager_connect_failure_yields_502
// test_server_aborts                              | TestLayerAbortedMessages/server_sends_no_response and server_sends_incomplete_invalid_head
// test_upstream_proxy                             | TestLayerUpstreamRedirectMatrix; TestLayerUpstreamHTTP; TestLayerUpstreamTunnel
// test_upstream_proxy_ipv6                        | TestUpstreamConnectHandshake/IPv6_authority (CONNECT target and Host)
// test_http_proxy_tcp                             | TestLayerConnectTCPMatrix (regular/upstream, both close orders, injection)
// test_proxy_chain                                | TestLayerRejectProxyChain (eager/lazy)
// test_no_headers                                 | TestLayerWireRoundTrips/no_headers
// test_http_proxy_without_empty_chunk_in_head_request | TestLayerWireRoundTrips/chunked_HEAD_has_no_terminal_chunk
// test_http_proxy_relative_request                | TestLayerWireRoundTrips/relative_target
// test_http_proxy_relative_request_no_host_header | TestLayerRequestRejections/relative_target_has_no_host
// test_http_expect                                | TestLayerExpectContinueWire; TestStreamExpectContinue
// test_http_client_aborts                         | TestLayerAbortedMessages/client_aborts_buffered_body and client_aborts_streamed_body
// test_http_server_aborts                         | TestLayerAbortedMessages/server_aborts_buffered_body and server_aborts_streamed_body
// test_kill_flow                                  | TestStreamKilledHooks; TestStreamAdditionalKillHooks; TestStreamConnect/killed_connect
// test_close_during_connect_hook                  | TestLayerCloseDuringConnectHook
// test_connection_close_header                    | TestLayerConnectionCloseMatrix (client/server/both)
// test_upgrade                                   | PARTIAL: TestLayerUpgradeDispatch covers TCP/none and documented WebSocket fallback; WebSocket protocol phase supplies its native branch
// test_dont_reuse_closed                          | TestUpstreamPoolReuse (retire/reopen); TestLayerDisconnectWhileIntercepted
// test_reuse_error                                | TestLayerInheritedServerError (no redial)
// test_transparent_sni                            | TestLayerSNISelection/transparent_destination_preserves_client_SNI
// test_reverse_sni                                | TestLayerSNISelection/reverse_destination_preserves_configured_SNI
// test_original_server_disconnects                | TestLayerOriginalServerDisconnects (idle inherited origin, no HTTP hooks)
// test_request_smuggling                          | TestLayerRequestRejections/conflicting_framing; TestStreamRequestValidation
// test_request_smuggling_whitespace               | TestLayerRequestRejections/whitespace_in_header_name
// test_request_smuggling_response                 | TestLayerResponseValidation; TestStreamResponseValidation
// test_request_smuggling_validation_disabled      | TestLayerFramingEdits/explicitly_disabled_inbound_validation
// test_request_smuggling_te_te                    | TestLayerRequestRejections/non-ASCII_transfer_encoding
// test_invalid_content_length                     | TestLayerRequestRejections/nonnumeric_content_length and negative_content_length
// test_chunked_and_content_length_set_by_addon     | TestLayerFramingEdits/addon_sets_chunked_alongside_content_length
// test_connect_more_newlines                      | TestHTTP1ServerTakeover (buffered newline stripping, tunnel replay)
// test_connect_unauthorized                       | TestLayerConnectRetryAfterRefusal; TestHTTP1ConnectResponseMessageBoundary
// test_memory_usage_completed_flows               | TestLayerReleasesFlows/completed_flow_is_collectable_during_keepalive
// test_memory_usage_errored_flows                  | TestLayerReleasesFlows/errored_flow_is_collectable
// test_drop_stream_with_paused_events              | TestLayerQueuedBodyAfterDialFailure; TestLazyServerFailedSend
//
// test_http1.py:
//
// Upstream function             | Go cases / coverage
// ----------------------------- | -------------------
// TestServer.test_simple        | TestHTTP1ServerExchanges/simple_exchange and simple_exchange_pipelined
// TestServer.test_connect       | TestHTTP1ServerExchanges/connect_tunnel and connect_tunnel_pipelined; TestHTTP1ConnectRequestMessageBoundary
// TestServer.test_upgrade       | TestHTTP1ServerExchanges/upgrade and upgrade_pipelined
// TestServer.test_upgrade_denied | TestHTTP1ServerExchanges/upgrade_denied
// TestClient.test_simple        | TestHTTP1ClientSimple (sequential reuse and refused pipelining)
// TestClient.test_connect       | TestHTTP1ClientConnect; TestHTTP1ConnectResponseMessageBoundary
// TestClient.test_upgrade       | TestHTTP1ClientUpgrade
// TestClient.test_upgrade_denied | TestHTTP1ClientUpgradeDenied
