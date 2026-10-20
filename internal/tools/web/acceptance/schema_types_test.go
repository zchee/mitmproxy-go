// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package acceptance_test

import (
	"bytes"
	"encoding/json/jsontext"
)

// These types describe the pinned frontend contract independently of flowjson.
// Pointers distinguish nullable values; required-key presence is checked separately.
type schemaBaseFlow struct {
	ID               string        `json:"id"`
	Intercepted      bool          `json:"intercepted"`
	IsReplay         *string       `json:"is_replay"`
	Type             string        `json:"type"`
	Modified         bool          `json:"modified"`
	Marked           string        `json:"marked"`
	Comment          string        `json:"comment"`
	TimestampCreated float64       `json:"timestamp_created"`
	ClientConn       schemaClient  `json:"client_conn"`
	ServerConn       *schemaServer `json:"server_conn,omitzero"`
	Error            *schemaError  `json:"error,omitzero"`
}

type schemaHTTPFlow struct {
	schemaBaseFlow
	Type      string               `json:"type"`
	Request   schemaHTTPRequest    `json:"request"`
	Response  *schemaHTTPResponse  `json:"response,omitzero"`
	WebSocket *schemaWebSocketData `json:"websocket,omitzero"`
}

type schemaTCPFlow struct {
	schemaBaseFlow
	Type         string             `json:"type"`
	MessagesMeta schemaMessagesMeta `json:"messages_meta"`
}

type schemaUDPFlow struct {
	schemaBaseFlow
	Type         string             `json:"type"`
	MessagesMeta schemaMessagesMeta `json:"messages_meta"`
}

type schemaDNSFlow struct {
	schemaBaseFlow
	Type     string            `json:"type"`
	Request  schemaDNSMessage  `json:"request"`
	Response *schemaDNSMessage `json:"response,omitzero"`
}

type schemaError struct {
	Msg       string  `json:"msg"`
	Timestamp float64 `json:"timestamp"`
}

// Tuple elements and scalar unions are validated by the raw contract walker.
type (
	schemaAddress []jsontext.Value
	schemaKeyInfo [2]jsontext.Value
	schemaSNI     jsontext.Value
	schemaDNSData jsontext.Value
)

func (s *schemaSNI) UnmarshalJSON(raw []byte) error {
	*s = schemaSNI(bytes.Clone(raw))
	return nil
}

func (d *schemaDNSData) UnmarshalJSON(raw []byte) error {
	*d = schemaDNSData(bytes.Clone(raw))
	return nil
}

type schemaConnection struct {
	ID                string             `json:"id"`
	Peername          *schemaAddress     `json:"peername,omitzero"`
	Sockname          *schemaAddress     `json:"sockname,omitzero"`
	TLSEstablished    bool               `json:"tls_established"`
	Cert              *schemaCertificate `json:"cert,omitzero"`
	SNI               *schemaSNI         `json:"sni,omitzero"`
	Cipher            *string            `json:"cipher,omitzero"`
	ALPN              *string            `json:"alpn,omitzero"`
	TLSVersion        *string            `json:"tls_version,omitzero"`
	TimestampStart    *float64           `json:"timestamp_start,omitzero"`
	TimestampTLSSetup *float64           `json:"timestamp_tls_setup,omitzero"`
	TimestampEnd      *float64           `json:"timestamp_end,omitzero"`
}

type schemaClient struct {
	schemaConnection
	Peername       schemaAddress `json:"peername"`
	Sockname       schemaAddress `json:"sockname"`
	TimestampStart float64       `json:"timestamp_start"`
}

type schemaServer struct {
	schemaConnection
	Address           *schemaAddress `json:"address,omitzero"`
	TimestampTCPSetup *float64       `json:"timestamp_tcp_setup,omitzero"`
}

type schemaCertificate struct {
	KeyInfo   schemaKeyInfo `json:"keyinfo"`
	SHA256    string        `json:"sha256"`
	NotBefore float64       `json:"notbefore"`
	NotAfter  float64       `json:"notafter"`
	Serial    string        `json:"serial"`
	Subject   [][2]string   `json:"subject"`
	Issuer    [][2]string   `json:"issuer"`
	AltNames  []string      `json:"altnames"`
}

type (
	schemaHTTPHeader  = [2]string
	schemaHTTPHeaders = []schemaHTTPHeader
)

type schemaHTTPMessage struct {
	HTTPVersion    string             `json:"http_version"`
	Headers        schemaHTTPHeaders  `json:"headers"`
	Trailers       *schemaHTTPHeaders `json:"trailers,omitzero"`
	ContentLength  *float64           `json:"contentLength,omitzero"`
	ContentHash    *string            `json:"contentHash,omitzero"`
	TimestampStart float64            `json:"timestamp_start"`
	TimestampEnd   *float64           `json:"timestamp_end,omitzero"`
}

type schemaHTTPRequest struct {
	schemaHTTPMessage
	Method     string  `json:"method"`
	Scheme     string  `json:"scheme"`
	Host       string  `json:"host"`
	Port       float64 `json:"port"`
	Path       string  `json:"path"`
	PrettyHost string  `json:"pretty_host"`
}

type schemaHTTPResponse struct {
	schemaHTTPMessage
	StatusCode float64 `json:"status_code"`
	Reason     string  `json:"reason"`
}

type schemaMessagesMeta struct {
	ContentLength float64  `json:"contentLength"`
	Count         float64  `json:"count"`
	TimestampLast *float64 `json:"timestamp_last,omitzero"`
}

type schemaWebSocketData struct {
	MessagesMeta   schemaMessagesMeta `json:"messages_meta"`
	ClosedByClient *bool              `json:"closed_by_client,omitzero"`
	CloseCode      *float64           `json:"close_code,omitzero"`
	CloseReason    *string            `json:"close_reason,omitzero"`
	TimestampEnd   *float64           `json:"timestamp_end,omitzero"`
}

type schemaDNSQuestion struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type schemaDNSResourceRecord struct {
	Name  string        `json:"name"`
	Type  string        `json:"type"`
	Class string        `json:"class"`
	TTL   float64       `json:"ttl"`
	Data  schemaDNSData `json:"data"`
}

type schemaDNSMessage struct {
	ID                  float64                   `json:"id"`
	Query               bool                      `json:"query"`
	OpCode              string                    `json:"op_code"`
	AuthoritativeAnswer bool                      `json:"authoritative_answer"`
	Truncation          bool                      `json:"truncation"`
	RecursionDesired    bool                      `json:"recursion_desired"`
	RecursionAvailable  bool                      `json:"recursion_available"`
	ResponseCode        string                    `json:"response_code"`
	StatusCode          float64                   `json:"status_code"`
	Questions           []schemaDNSQuestion       `json:"questions"`
	Answers             []schemaDNSResourceRecord `json:"answers"`
	Authorities         []schemaDNSResourceRecord `json:"authorities"`
	Additionals         []schemaDNSResourceRecord `json:"additionals"`
	Size                float64                   `json:"size"`
	Timestamp           *float64                  `json:"timestamp,omitzero"`
}
