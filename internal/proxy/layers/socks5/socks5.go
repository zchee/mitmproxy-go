// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package socks5 implements the SOCKS5 CONNECT handshake and authentication.
package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

func init() { layer.Register("socks5", newProxy) }

type socksProxy struct{}

func newProxy(_ *layer.Context, _ hookdata.LayerSpec, _ layer.Layer) (layer.Layer, error) {
	return &socksProxy{}, nil
}

// Kind returns the SOCKS5 mode's initial-layer identity.
func (*socksProxy) Kind() hookdata.LayerKind { return "socks5" }

// Run consumes only SOCKS control frames before selecting a protocol layer.
func (*socksProxy) Run(ctx context.Context, c *layer.Context) error {
	// The initial mode is not sniffed. Rewind before reading any control bytes
	// so a later selector can never replay the SOCKS handshake into its child.
	c.Client.StopRecording()
	if err := handshake(ctx, c); err != nil {
		return err
	}
	child, err := layer.Next(ctx, c)
	if err != nil {
		return err
	}
	return child.Run(ctx, c)
}

func handshake(ctx context.Context, c *layer.Context) (result error) {
	clock := c.Clock
	if clock == nil {
		clock = layer.WallClock
	}
	headCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	timedOut := make(chan struct{})
	stopTimer := clock.AfterFunc(layer.HeadReadTimeout, func() {
		cancel(context.DeadlineExceeded)
		close(timedOut)
	})
	interrupted := make(chan struct{})
	stopCancel := context.AfterFunc(headCtx, func() {
		_ = c.Client.SetDeadline(time.Unix(1, 0))
		close(interrupted)
	})
	defer func() {
		if !stopTimer() {
			<-timedOut
		}
		if !stopCancel() {
			<-interrupted
		}
		_ = c.Client.SetDeadline(time.Time{})
		if headCtx.Err() != nil {
			result = context.Cause(headCtx)
		}
	}()

	p := parser{need: 2}
	if err := c.Do(headCtx, func(context.Context) error {
		if c.Data.Options.Has("proxyauth") {
			spec := c.Data.Options.OptStr("proxyauth")
			p.auth = spec != nil && *spec != ""
		}
		return nil
	}); err != nil {
		return err
	}
	for p.stage != handover {
		if err := p.next(c.Client); err != nil {
			if protocol, ok := errors.AsType[*protocolError](err); ok {
				if protocol.reply != 0 {
					if err := sendReply(c, protocol.reply); err != nil {
						return err
					}
				}
				if c.Logger != nil {
					c.Logger.InfoContext(headCtx, protocol.message)
				}
			} else if p.n != 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) && c.Logger != nil {
				if p.stage == credentials || p.stage == username || p.stage == password {
					c.Logger.InfoContext(headCtx, fmt.Sprintf("Client closed connection before completing SOCKS5 handshake: authentication stage, %d bytes", p.n))
				} else {
					c.Logger.InfoContext(headCtx, "Client closed connection before completing SOCKS5 handshake: "+pyrepr.Bytes(p.frame[:p.n]))
				}
			}
			return err
		}
		switch p.stage {
		case methods:
			method := byte(0)
			if p.auth {
				method = 2
			}
			if _, err := c.Client.Write([]byte{5, method}); err != nil {
				return err
			}
			if p.auth {
				p.reset(credentials, 3)
			} else {
				p.reset(request, 5)
			}
		case password:
			user, secret := p.credentials()
			data := &hookdata.Socks5Auth{Username: user, Password: secret}
			if _, err := c.Hooks.FireFunc(headCtx, func(context.Context) error {
				data.Client = c.Data.Client
				return nil
			}, addon.Socks5AuthHook{Data: data}); err != nil {
				return err
			}
			valid := false
			if err := c.Do(headCtx, func(context.Context) error { valid = data.Valid; return nil }); err != nil {
				return err
			}
			status := byte(1)
			if valid {
				status = 0
			}
			if _, err := c.Client.Write([]byte{1, status}); err != nil {
				return err
			}
			if !valid {
				if c.Logger != nil {
					c.Logger.InfoContext(headCtx, "authentication failed")
				}
				return errors.New("authentication failed")
			}
			p.reset(request, 5)
		case handover:
		case greeting, credentials, username, request, address:
			return errors.New("SOCKS5 parser stopped before a complete frame")
		}
	}
	var server *connection.Server
	eager := false
	destination := p.destination()
	if err := c.Do(headCtx, func(context.Context) error {
		c.Data.Server.Address = &destination
		server = c.Data.Server
		eager = c.Data.Options.Str("connection_strategy") == "eager"
		return nil
	}); err != nil {
		return err
	}
	if eager {
		conn, actual, err := c.Pool.Open(headCtx, server, layer.OpenOptions{Reuse: true})
		if err != nil {
			if writeErr := sendReply(c, 4); writeErr != nil {
				return writeErr
			}
			return err
		}
		c.Server = c.Record(conn)
		if err := c.Do(headCtx, func(context.Context) error { c.Data.Server = actual; return nil }); err != nil {
			return err
		}
	}
	return sendReply(c, 0)
}

func sendReply(c *layer.Context, code byte) error {
	_, err := c.Client.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
