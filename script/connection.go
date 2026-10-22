// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"errors"
	"fmt"

	"go.starlark.net/starlark"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
)

func addressValue(a *connection.Address) starlark.Value {
	if a == nil {
		return starlark.None
	}
	return starlark.Tuple{starlark.String(a.Host), starlark.MakeInt(a.Port)}
}

func nativeAddress(value starlark.Value) (*connection.Address, error) {
	if value == starlark.None {
		return nil, nil
	}
	pair, ok := value.(starlark.Indexable)
	if !ok || pair.Len() != 2 {
		return nil, errors.New("address requires a (host, port) pair or None")
	}
	host, err := stringValue(pair.Index(0))
	if err != nil {
		return nil, err
	}
	port, err := intValue(pair.Index(1))
	if err != nil {
		return nil, err
	}
	if port < 0 || port > 65535 {
		return nil, errors.New("address port is outside 0..65535")
	}
	return &connection.Address{Host: host, Port: port}, nil
}

func wrapClient(i *invocation, c *connection.Client) starlark.Value {
	if c == nil {
		return starlark.None
	}
	return wrapConnection(i, &c.Connection, nil)
}

func wrapServer(i *invocation, s *connection.Server) starlark.Value {
	if s == nil {
		return starlark.None
	}
	return wrapConnection(i, &s.Connection, s)
}

// Connection wrappers expose endpoint metadata only, never a net.Conn. Native
// optional strings/addresses are None; byte fields stay Bytes. Ordinary setters
// run only under dispatch; detached worker connections become read-only.
func wrapConnection(i *invocation, c *connection.Connection, server *connection.Server) starlark.Value {
	if c == nil {
		return starlark.None
	}
	return &object{kind: "connection", check: i.modelCheck, names: []string{"id", "address", "peername", "sockname", "error", "tls", "sni", "alpn", "alpn_offers", "cipher", "cipher_list", "tls_version", "transport_protocol", "timestamp_start", "timestamp_end", "timestamp_tls_setup", "connected", "tls_established"}, get: func(name string) (starlark.Value, error) {
		switch name {
		case "id":
			return starlark.String(c.ID), nil
		case "address":
			if server != nil {
				return addressValue(server.Address), nil
			}
			return addressValue(c.Peername), nil
		case "peername":
			return addressValue(c.Peername), nil
		case "sockname":
			return addressValue(c.Sockname), nil
		case "error":
			return optionalString(c.Error), nil
		case "tls":
			return starlark.Bool(c.TLS), nil
		case "sni":
			return optionalString(c.SNI), nil
		case "alpn":
			if c.ALPN == nil {
				return starlark.None, nil
			}
			return starlark.Bytes(c.ALPN), nil
		case "alpn_offers":
			values := make([]starlark.Value, len(c.ALPNOffers))
			for n, b := range c.ALPNOffers {
				values[n] = starlark.Bytes(b)
			}
			return starlark.NewList(values), nil
		case "cipher":
			return optionalString(c.Cipher), nil
		case "cipher_list":
			return new(conversion).value(i, c.CipherList, 0)
		case "tls_version":
			return starlark.String(c.TLSVersion), nil
		case "transport_protocol":
			return starlark.String(c.TransportProtocol), nil
		case "timestamp_start":
			return optionalFloat(c.TimestampStart), nil
		case "timestamp_end":
			return optionalFloat(c.TimestampEnd), nil
		case "timestamp_tls_setup":
			return optionalFloat(c.TimestampTLSSetup), nil
		case "connected":
			return starlark.Bool(c.Connected()), nil
		case "tls_established":
			return starlark.Bool(c.TLSEstablished()), nil
		}
		return nil, nil
	}, set: func(name string, value starlark.Value) error {
		if i.worker {
			return fmt.Errorf("connection.%s is read-only in concurrent handlers", name)
		}
		switch name {
		case "error", "sni":
			var x *string
			if value != starlark.None {
				s, err := stringValue(value)
				if err != nil {
					return err
				}
				x = &s
			}
			if name == "error" {
				c.Error = x
			} else {
				c.SNI = x
			}
			return nil
		case "tls":
			x, err := boolValue(value)
			if err == nil {
				c.TLS = x
			}
			return err
		case "address":
			if server != nil {
				x, err := nativeAddress(value)
				if err == nil {
					server.Address = x
				}
				return err
			}
		}
		return fmt.Errorf("connection.%s is read-only", name)
	}}
}

func wrapHookContext(i *invocation, data *hookdata.Context) starlark.Value {
	if data == nil {
		return starlark.None
	}
	return &object{kind: "connection_context", check: i.modelCheck, names: []string{"client", "server"}, get: func(name string) (starlark.Value, error) {
		switch name {
		case "client":
			return wrapClient(i, data.Client), nil
		case "server":
			return wrapServer(i, data.Server), nil
		}
		return nil, nil
	}}
}

func wrapHookData(i *invocation, data any) starlark.Value {
	switch d := data.(type) {
	case *connection.Client:
		return wrapClient(i, d)
	case addon.LogEntry:
		return &object{kind: "log_entry", check: i.modelCheck, names: []string{"msg", "level"}, get: func(name string) (starlark.Value, error) {
			switch name {
			case "msg":
				return starlark.String(d.Msg), nil
			case "level":
				return starlark.String(d.LevelName()), nil
			}
			return nil, nil
		}}
	case *hookdata.ServerConnection:
		if d == nil {
			return starlark.None
		}
		return &object{kind: "server_connection", check: i.modelCheck, names: []string{"client", "server"}, get: func(name string) (starlark.Value, error) {
			switch name {
			case "client":
				return wrapClient(i, d.Client), nil
			case "server":
				return wrapServer(i, d.Server), nil
			}
			return nil, nil
		}}
	case *hookdata.Socks5Auth:
		if d == nil {
			return starlark.None
		}
		return &object{kind: "socks5_auth", check: i.modelCheck, names: []string{"client", "username", "password", "valid"}, get: func(name string) (starlark.Value, error) {
			switch name {
			case "client":
				return wrapClient(i, d.Client), nil
			case "username":
				return starlark.String(d.Username), nil
			case "password":
				return starlark.String(d.Password), nil
			case "valid":
				return starlark.Bool(d.Valid), nil
			}
			return nil, nil
		}, set: func(name string, value starlark.Value) error {
			if name != "valid" {
				return fmt.Errorf("socks5_auth.%s is read-only", name)
			}
			x, err := boolValue(value)
			if err == nil {
				d.Valid = x
			}
			return err
		}}
	case *hookdata.NextLayer:
		if d == nil {
			return starlark.None
		}
		return &object{kind: "next_layer", check: i.modelCheck, names: []string{"context", "data_client", "data_server", "layer"}, get: func(name string) (starlark.Value, error) {
			switch name {
			case "context":
				return wrapHookContext(i, d.Context), nil
			case "data_client":
				return starlark.Bytes(d.DataClient), nil
			case "data_server":
				return starlark.Bytes(d.DataServer), nil
			case "layer":
				values := make([]starlark.Value, len(d.Layer))
				for n, layer := range d.Layer {
					values[n] = starlark.String(layer.Kind)
				}
				return starlark.NewList(values), nil
			}
			return nil, nil
		}, set: func(name string, value starlark.Value) error {
			if name != "layer" {
				return fmt.Errorf("next_layer.%s is read-only", name)
			}
			if value == starlark.None {
				d.Layer = nil
				return nil
			}
			names, err := stringList(value)
			if err != nil {
				return err
			}
			layers := make(hookdata.LayerStack, len(names))
			for n, kind := range names {
				switch hookdata.LayerKind(kind) {
				case hookdata.LayerTCP, hookdata.LayerUDP, hookdata.LayerClientTLS, hookdata.LayerServerTLS, hookdata.LayerClientDTLS, hookdata.LayerServerDTLS, hookdata.LayerWebSocket, hookdata.LayerHTTP3:
					layers[n].Kind = hookdata.LayerKind(kind)
				case hookdata.LayerHTTP:
					layers[n] = hookdata.LayerSpec{Kind: hookdata.LayerHTTP, HTTPMode: hookdata.HTTPModeTransparent}
				default:
					return fmt.Errorf("unsupported layer kind %q", kind)
				}
			}
			d.Layer = layers
			return nil
		}}
	case *hookdata.ClientHello:
		if d == nil {
			return starlark.None
		}
		return &object{kind: "client_hello", check: i.modelCheck, names: []string{"context", "ignore_connection", "establish_server_tls_first"}, get: func(name string) (starlark.Value, error) {
			switch name {
			case "context":
				return wrapHookContext(i, d.Context), nil
			case "ignore_connection":
				return starlark.Bool(d.IgnoreConnection), nil
			case "establish_server_tls_first":
				return starlark.Bool(d.EstablishServerTLSFirst), nil
			}
			return nil, nil
		}, set: func(name string, value starlark.Value) error {
			x, err := boolValue(value)
			if err != nil {
				return err
			}
			switch name {
			case "ignore_connection":
				d.IgnoreConnection = x
			case "establish_server_tls_first":
				d.EstablishServerTLSFirst = x
			default:
				return fmt.Errorf("client_hello.%s is read-only", name)
			}
			return nil
		}}
	case *hookdata.TLS:
		if d == nil {
			return starlark.None
		}
		return &object{kind: "tls", check: i.modelCheck, names: []string{"conn", "context", "is_dtls"}, get: func(name string) (starlark.Value, error) {
			switch name {
			case "conn":
				return wrapConnection(i, d.Conn, nil), nil
			case "context":
				return wrapHookContext(i, d.Context), nil
			case "is_dtls":
				return starlark.Bool(d.IsDTLS), nil
			}
			return nil, nil
		}}
	case *hookdata.QUICTLS:
		if d == nil {
			return starlark.None
		}
		return &object{kind: "quic_tls", check: i.modelCheck, names: []string{"conn", "context", "is_dtls"}, get: func(name string) (starlark.Value, error) {
			switch name {
			case "conn":
				return wrapConnection(i, d.Conn, nil), nil
			case "context":
				return wrapHookContext(i, d.Context), nil
			case "is_dtls":
				return starlark.Bool(d.IsDTLS), nil
			}
			return nil, nil
		}}
	}
	return starlark.None
}
