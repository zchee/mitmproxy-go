// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package acceptance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"io"
	"maps"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/flowio/flowjson"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

const flowSchemaSHA256 = "ce651e37eeb796a681c99ba007b4f39dc62f948302e72effc1828d6c9742313d"

var schemaInterfaces = map[string]reflect.Type{
	"_Flow":             reflect.TypeFor[schemaBaseFlow](),
	"HTTPFlow":          reflect.TypeFor[schemaHTTPFlow](),
	"TCPFlow":           reflect.TypeFor[schemaTCPFlow](),
	"UDPFlow":           reflect.TypeFor[schemaUDPFlow](),
	"DNSFlow":           reflect.TypeFor[schemaDNSFlow](),
	"Error":             reflect.TypeFor[schemaError](),
	"Connection":        reflect.TypeFor[schemaConnection](),
	"Client":            reflect.TypeFor[schemaClient](),
	"Server":            reflect.TypeFor[schemaServer](),
	"Certificate":       reflect.TypeFor[schemaCertificate](),
	"HTTPMessage":       reflect.TypeFor[schemaHTTPMessage](),
	"HTTPRequest":       reflect.TypeFor[schemaHTTPRequest](),
	"HTTPResponse":      reflect.TypeFor[schemaHTTPResponse](),
	"MessagesMeta":      reflect.TypeFor[schemaMessagesMeta](),
	"WebSocketData":     reflect.TypeFor[schemaWebSocketData](),
	"DNSQuestion":       reflect.TypeFor[schemaDNSQuestion](),
	"DNSResourceRecord": reflect.TypeFor[schemaDNSResourceRecord](),
	"DNSMessage":        reflect.TypeFor[schemaDNSMessage](),
}

// Declaration identities, not expanded JSON paths: Client overrides three of
// Connection's optional members, so those Client members remain required.
var schemaOptionalDeclarations = []string{
	"_Flow.server_conn", "_Flow.error",
	"HTTPFlow.response", "HTTPFlow.websocket",
	"Connection.peername", "Connection.sockname", "Connection.cert",
	"Connection.sni", "Connection.cipher", "Connection.alpn", "Connection.tls_version",
	"Connection.timestamp_start", "Connection.timestamp_tls_setup", "Connection.timestamp_end",
	"Server.address", "Server.timestamp_tcp_setup",
	"HTTPMessage.trailers", "HTTPMessage.contentLength", "HTTPMessage.contentHash", "HTTPMessage.timestamp_end",
	"MessagesMeta.timestamp_last", "WebSocketData.closed_by_client", "WebSocketData.close_code",
	"WebSocketData.close_reason", "WebSocketData.timestamp_end", "DNSMessage.timestamp", "DNSFlow.response",
}

type schemaField struct {
	typ      reflect.Type
	optional bool
}

func schemaFields(typ reflect.Type) map[string]schemaField {
	fields := make(map[string]schemaField)
	for field := range typ.Fields() {
		if field.Anonymous {
			maps.Copy(fields, schemaFields(field.Type))
		}
	}
	for field := range typ.Fields() {
		if field.Anonymous {
			continue
		}
		key, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		owner := ""
		for name, candidate := range schemaInterfaces {
			if candidate == typ {
				owner = name
				break
			}
		}
		fields[key] = schemaField{field.Type, slices.Contains(schemaOptionalDeclarations, owner+"."+key)}
	}
	return fields
}

func decodeSchema(raw []byte, typ reflect.Type) error {
	value := reflect.New(typ).Interface()
	if err := json.Unmarshal(raw, value, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("typed schema %s: %w", typ, err)
	}
	return walkSchema(raw, typ, "$")
}

func decodeFlowSchema(raw []byte) error {
	var discriminator struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &discriminator); err != nil {
		return err
	}
	var typ reflect.Type
	switch discriminator.Type {
	case "http":
		typ = reflect.TypeFor[schemaHTTPFlow]()
	case "tcp":
		typ = reflect.TypeFor[schemaTCPFlow]()
	case "udp":
		typ = reflect.TypeFor[schemaUDPFlow]()
	case "dns":
		typ = reflect.TypeFor[schemaDNSFlow]()
	default:
		return fmt.Errorf("unknown flow discriminator %q", discriminator.Type)
	}
	if err := decodeSchema(raw, typ); err != nil {
		return err
	}
	var base schemaBaseFlow
	if err := json.Unmarshal(raw, &base); err != nil {
		return err
	}
	if base.IsReplay != nil && *base.IsReplay != "request" && *base.IsReplay != "response" {
		return fmt.Errorf("invalid is_replay %q", *base.IsReplay)
	}
	return nil
}

func walkSchema(raw []byte, typ reflect.Type, path string) error {
	if typ.Kind() == reflect.Pointer {
		if bytes.Equal(raw, []byte("null")) {
			return nil
		}
		return walkSchema(raw, typ.Elem(), path)
	}
	if bytes.Equal(raw, []byte("null")) {
		return fmt.Errorf("%s: null is not %s", path, typ)
	}
	switch typ {
	case reflect.TypeFor[schemaSNI]():
		var value string
		if err := json.Unmarshal(raw, &value); err == nil {
			return nil
		}
		var boolean bool
		return json.Unmarshal(raw, &boolean)
	case reflect.TypeFor[schemaDNSData]():
		var value string
		if err := json.Unmarshal(raw, &value); err == nil {
			return nil
		}
		var object map[string]jsontext.Value
		if err := json.Unmarshal(raw, &object); err != nil {
			return err
		}
		for key, value := range object {
			if err := walkSchema(value, reflect.TypeFor[string](), path+"/"+key); err != nil {
				return err
			}
		}
		return nil
	case reflect.TypeFor[schemaAddress](), reflect.TypeFor[schemaKeyInfo]():
		var tuple []jsontext.Value
		if err := json.Unmarshal(raw, &tuple); err != nil {
			return err
		}
		address := typ == reflect.TypeFor[schemaAddress]()
		if len(tuple) != 2 && (!address || len(tuple) != 4) {
			return fmt.Errorf("%s: invalid tuple length %d", path, len(tuple))
		}
		for i, value := range tuple {
			elementType := reflect.TypeFor[float64]()
			if i == 0 {
				elementType = reflect.TypeFor[string]()
			}
			if err := walkSchema(value, elementType, fmt.Sprintf("%s/%d", path, i)); err != nil {
				return err
			}
		}
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]jsontext.Value
		if err := json.Unmarshal(raw, &object); err != nil {
			return err
		}
		fields := schemaFields(typ)
		for key, field := range fields {
			value, exists := object[key]
			if !exists {
				if field.optional {
					continue
				}
				return fmt.Errorf("%s/%s: required key absent", path, key)
			}
			if err := walkSchema(value, field.typ, path+"/"+key); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var values []jsontext.Value
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		if typ.Kind() == reflect.Array && len(values) != typ.Len() {
			return fmt.Errorf("%s: tuple length %d, want %d", path, len(values), typ.Len())
		}
		for i, value := range values {
			if err := walkSchema(value, typ.Elem(), fmt.Sprintf("%s/%d", path, i)); err != nil {
				return err
			}
		}
	default:
		if err := json.Unmarshal(raw, reflect.New(typ).Interface()); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}

func schemaExample(typ reflect.Type) jsontext.Value {
	if typ.Kind() == reflect.Pointer {
		return schemaExample(typ.Elem())
	}
	switch typ {
	case reflect.TypeFor[schemaAddress]():
		return jsontext.Value(`["127.0.0.1",8080]`)
	case reflect.TypeFor[schemaKeyInfo]():
		return jsontext.Value(`["RSA",2048]`)
	case reflect.TypeFor[schemaSNI](), reflect.TypeFor[schemaDNSData]():
		return jsontext.Value(`"example.test"`)
	}
	switch typ.Kind() {
	case reflect.Struct:
		object := make(map[string]jsontext.Value)
		for key, field := range schemaFields(typ) {
			object[key] = schemaExample(field.typ)
		}
		raw, err := json.Marshal(object)
		if err != nil {
			panic(err) // Only fixed schema types and valid JSON literals reach this builder.
		}
		return raw
	case reflect.Slice, reflect.Array:
		length := 1
		if typ.Kind() == reflect.Array {
			length = typ.Len()
		}
		values := make([]jsontext.Value, length)
		for i := range values {
			values[i] = schemaExample(typ.Elem())
		}
		raw, err := json.Marshal(values)
		if err != nil {
			panic(err)
		}
		return raw
	case reflect.String:
		return jsontext.Value(`""`)
	case reflect.Bool:
		return jsontext.Value(`false`)
	default:
		return jsontext.Value(`0`)
	}
}

func TestMitmwebFlowSchema(t *testing.T) {
	t.Run("source_contract", func(t *testing.T) {
		source := testutil.Fixture(t, "mitmproxy/web/src/js/flow.ts")
		sum := sha256.Sum256(source)
		if got := hex.EncodeToString(sum[:]); got != flowSchemaSHA256 {
			t.Fatalf("flow.ts SHA256 = %s, want %s", got, flowSchemaSHA256)
		}
		interfaces := regexp.MustCompile(`(?m)^(?:export )?interface (\w+)(?: extends (\w+))? \{\n([\s\S]*?)^\}`).FindAllSubmatch(source, -1)
		declarations := regexp.MustCompile(`(?m)^    (\w+)(\?)?: ([^\n]+);$`)
		var optional []string
		seen := make(map[string]bool)
		for _, definition := range interfaces {
			name := string(definition[1])
			typ, exists := schemaInterfaces[name]
			if !exists {
				t.Fatalf("untranscribed interface %s", name)
			}
			seen[name] = true
			var want, got []string
			for _, field := range declarations.FindAllSubmatch(definition[3], -1) {
				want = append(want, string(field[1]))
				if len(field[2]) != 0 {
					optional = append(optional, name+"."+string(field[1]))
				}
			}
			for field := range typ.Fields() {
				if !field.Anonymous {
					key, _, _ := strings.Cut(field.Tag.Get("json"), ",")
					got = append(got, key)
				} else if string(definition[2]) == "" || field.Type != schemaInterfaces[string(definition[2])] {
					t.Fatalf("%s: incorrect inheritance", name)
				}
			}
			slices.Sort(want)
			slices.Sort(got)
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("%s declarations (-source +Go):\n%s", name, diff)
			}
		}
		if diff := cmp.Diff(slices.Sorted(maps.Keys(schemaInterfaces)), slices.Sorted(maps.Keys(seen))); diff != "" {
			t.Error(diff)
		}
		slices.Sort(optional)
		expected := slices.Sorted(slices.Values(schemaOptionalDeclarations))
		if len(optional) != 27 || len(expected) != 27 {
			t.Fatalf("optional declarations: source=%d Go=%d, want exactly 27", len(optional), len(expected))
		}
		if diff := cmp.Diff(expected, optional); diff != "" {
			t.Errorf("optional declarations (-want +source):\n%s", diff)
		}
	})

	t.Run("declaration_mutations", func(t *testing.T) {
		for name, typ := range schemaInterfaces {
			t.Run(name, func(t *testing.T) {
				example := schemaExample(typ)
				if err := decodeSchema(example, typ); err != nil {
					t.Fatalf("complete example: %v", err)
				}
				for key, field := range schemaFields(typ) {
					t.Run(key, func(t *testing.T) {
						var object map[string]jsontext.Value
						if err := json.Unmarshal(example, &object); err != nil {
							t.Fatal(err)
						}
						delete(object, key)
						raw, err := json.Marshal(object)
						if err != nil {
							t.Fatal(err)
						}
						err = decodeSchema(raw, typ)
						if (err == nil) != field.optional {
							t.Fatalf("remove %s.%s: optional=%v error=%v", name, key, field.optional, err)
						}
					})
				}
				var object map[string]jsontext.Value
				if err := json.Unmarshal(example, &object); err != nil {
					t.Fatal(err)
				}
				object["unknown_member"] = jsontext.Value(`0`)
				raw, err := json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
				if err := decodeSchema(raw, typ); err == nil {
					t.Fatal("unknown member accepted")
				}
			})
		}
	})

	t.Run("unions_and_tuples", func(t *testing.T) {
		tests := map[string]struct {
			raw   string
			typ   reflect.Type
			valid bool
		}{
			"IPv4":                 {`["127.0.0.1",8080]`, reflect.TypeFor[schemaAddress](), true},
			"IPv6 scoped":          {`["::1",8080,0,2]`, reflect.TypeFor[schemaAddress](), true},
			"address bad length":   {`["::1",8080,0]`, reflect.TypeFor[schemaAddress](), false},
			"address bad port":     {`["::1","8080"]`, reflect.TypeFor[schemaAddress](), false},
			"address null host":    {`[null,8080]`, reflect.TypeFor[schemaAddress](), false},
			"SNI string":           {`"example.test"`, reflect.TypeFor[schemaSNI](), true},
			"SNI false":            {`false`, reflect.TypeFor[schemaSNI](), true},
			"SNI number":           {`12`, reflect.TypeFor[schemaSNI](), false},
			"DNS string":           {`"127.0.0.1"`, reflect.TypeFor[schemaDNSData](), true},
			"DNS object":           {`{"1":"h2","port":"443"}`, reflect.TypeFor[schemaDNSData](), true},
			"DNS invalid value":    {`{"port":443}`, reflect.TypeFor[schemaDNSData](), false},
			"DNS null value":       {`{"port":null}`, reflect.TypeFor[schemaDNSData](), false},
			"header pair":          {`["X-Example","a"]`, reflect.TypeFor[schemaHTTPHeader](), true},
			"header short":         {`["X-Example"]`, reflect.TypeFor[schemaHTTPHeader](), false},
			"header long":          {`["X-Example","a","b"]`, reflect.TypeFor[schemaHTTPHeader](), false},
			"key info":             {`["RSA",2048]`, reflect.TypeFor[schemaKeyInfo](), true},
			"key info string size": {`["RSA","2048"]`, reflect.TypeFor[schemaKeyInfo](), false},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				err := decodeSchema([]byte(tt.raw), tt.typ)
				if (err == nil) != tt.valid {
					t.Fatalf("decode %s: valid=%v, error=%v", tt.raw, tt.valid, err)
				}
			})
		}
	})

	tests := map[string]struct{ input flow.Flow }{
		"HTTP":      {testflow.TFlow(testflow.WithResponse, testflow.WithError)},
		"WebSocket": {testflow.TFlow(testflow.WithResponse, testflow.WithWebSocket)},
		"TCP":       {testflow.TTCPFlow(testflow.WithError)},
		"UDP":       {testflow.TUDPFlow(testflow.WithError)},
		"DNS":       {testflow.TDNSFlow(testflow.WithResponse, testflow.WithError)},
	}
	for name, tt := range tests {
		t.Run("controlled/"+name, func(t *testing.T) {
			checkFlowSchema(t, tt.input)
		})
	}
	for _, fixture := range []string{"corrupted_gzip_body.mitm", "diff_data.mitm", "error_log.mitm", "event_stream.mitm", "incomplete_log.mitm", "successful_log.mitm", "websocket.mitm"} {
		t.Run("fixtures/"+fixture, func(t *testing.T) {
			file, err := os.Open(testutil.FixturePath(t, "mitmproxy/flows/"+fixture))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := file.Close(); err != nil {
					t.Errorf("close flow fixture: %v", err)
				}
			}()
			reader := flowio.NewReader(file)
			count := 0
			for {
				f, err := reader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				checkFlowSchema(t, f)
				count++
			}
			if count == 0 {
				t.Fatal("fixture selected no flows")
			}
		})
	}
}

func checkFlowSchema(t *testing.T, f flow.Flow) {
	t.Helper()
	object, err := flowjson.Flow(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeFlowSchema(raw); err != nil {
		t.Fatalf("%s flow %s: %v", f.Type(), f.Common().ID, err)
	}
}
