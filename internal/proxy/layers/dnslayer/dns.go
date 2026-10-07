// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package dnslayer handles DNS exchanges over packet and length-prefixed stream transports.
package dnslayer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

func init() {
	layer.Register("dns", func(_ *layer.Context, _ hookdata.LayerSpec, _ layer.Layer) (layer.Layer, error) { return New(), nil })
}

// Layer handles DNS request/response matching on one client connection.
// Run owns its protocol state; exported values are constructed with New.
type Layer struct{}

// New returns a DNS layer ready for one Run invocation.
func New() *Layer { return &Layer{} }

// Kind returns the DNS protocol layer kind.
func (*Layer) Kind() hookdata.LayerKind { return "dns" }

type messageEvent struct {
	wire       []byte
	fromClient bool
	err        error
}

type owner struct {
	ctx           context.Context
	c             *layer.Context
	flows         map[int]*flow.DNSFlow
	events        chan messageEvent
	workers       sync.WaitGroup
	interrupts    []func() bool
	serverReading bool
}

// Run handles DNS until either peer closes, input is malformed, or ctx ends.
// Hooks run through the connection runner. DNS values are deep-cloned under Do
// after every hook; network work never holds addon dispatch. The handler owns
// transport closure, while Run interrupts and joins its own read workers.
// Caller cancellation takes precedence over interrupted transport errors.
func (*Layer) Run(ctx context.Context, c *layer.Context) (runErr error) {
	if c == nil || c.Data == nil || c.Hooks == nil || c.Do == nil || c.Client == nil && c.ClientPackets == nil {
		return errors.New("dnslayer: missing connection context or client transport")
	}
	// Capture the caller context before cleanup cancels the derived reader context.
	defer func(caller context.Context) {
		if err := caller.Err(); err != nil {
			runErr = err
		}
	}(ctx)
	ctx, cancel := context.WithCancel(ctx)
	o := &owner{ctx: ctx, c: c, flows: make(map[int]*flow.DNSFlow), events: make(chan messageEvent, 2)}
	if c.ClientPackets != nil {
		c.ClientPackets.StopRecording()
	} else {
		c.Client.StopRecording()
	}
	o.startReader(true, c.Client, c.ClientPackets)
	if c.Server != nil || c.ServerPackets != nil {
		o.startServerReader()
	}
	defer func() {
		cancel()
		o.workers.Wait()
		for _, stop := range o.interrupts {
			stop()
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), layer.TerminalHookTimeout)
		defer stop()
		if err := c.Do(cleanup, func(context.Context) error {
			for _, f := range o.flows {
				f.Resume()
				f.Live = false
			}
			return nil
		}); err != nil {
			o.logger().Error("Finishing DNS flows", "error", err)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-o.events:
			if err := ctx.Err(); err != nil {
				return err
			}
			if event.err != nil {
				if errors.Is(event.err, io.EOF) || errors.Is(event.err, io.ErrUnexpectedEOF) {
					return nil
				}
				if event.wire != nil {
					o.invalid(event.fromClient, event.err)
				}
				return event.err
			}
			now := o.now()
			msg, err := dns.Unpack(event.wire, &now)
			if err != nil {
				o.invalid(event.fromClient, err)
				return err
			}
			f := o.flows[msg.ID]
			if f == nil {
				if err := c.Do(ctx, func(context.Context) error { f = flow.NewDNSFlow(c.Data.Client, c.Data.Server, true); return nil }); err != nil {
					return err
				}
				o.flows[msg.ID] = f
			}
			if event.fromClient {
				err = o.request(f, msg)
			} else {
				err = o.response(f, msg)
			}
			if err != nil {
				return err
			}
		}
	}
}

func (o *owner) startReader(fromClient bool, stream layer.Recorder, packets layer.PacketRecorder) {
	// Keep write interruption active even after this peer's reader sees EOF.
	stop := context.AfterFunc(o.ctx, func() {
		if packets != nil {
			_ = packets.SetDeadline(time.Now())
		} else {
			_ = stream.SetDeadline(time.Now())
		}
	})
	o.interrupts = append(o.interrupts, stop)
	o.workers.Go(func() {
		var buf [65535]byte
		for {
			var wire []byte
			var err error
			if packets != nil {
				var n int
				n, _, err = packets.ReadFrom(buf[:])
				if err == nil {
					wire = slices.Clone(buf[:n])
				}
			} else {
				var prefix [2]byte
				_, err = io.ReadFull(stream, prefix[:])
				if err == nil {
					size := int(binary.BigEndian.Uint16(prefix[:]))
					if size == 0 {
						wire = []byte{}
						err = errors.New("Message length field cannot be zero") //nolint:staticcheck // Preserve the upstream framing diagnostic.
					} else {
						_, err = io.ReadFull(stream, buf[:size])
						if err == nil {
							wire = slices.Clone(buf[:size])
						}
					}
				}
			}
			select {
			case o.events <- messageEvent{wire: wire, fromClient: fromClient, err: err}:
			case <-o.ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	})
}

func (o *owner) startServerReader() {
	if o.serverReading {
		return
	}
	o.serverReading = true
	if o.c.ServerPackets != nil {
		o.c.ServerPackets.StopRecording()
	} else {
		o.c.Server.StopRecording()
	}
	o.startReader(false, o.c.Server, o.c.ServerPackets)
}

func (o *owner) request(f *flow.DNSFlow, msg *dns.Message) error {
	snap, err := o.c.Hooks.FireFunc(o.ctx, func(context.Context) error { f.Request = msg; return nil }, addon.DNSRequestHook{Flow: f})
	if err != nil {
		return err
	}
	if snap != nil && snap.Killed() {
		return errors.New(flow.KilledMessage) //nolint:staticcheck // Preserve the upstream flow-killed diagnostic.
	}
	request, response, problem, err := o.snapshot(f)
	if err != nil {
		return err
	}
	if response != nil {
		return o.response(f, response)
	}
	if problem != "" {
		return o.fail(f, problem)
	}
	var server *connection.Server
	if err := o.c.Do(o.ctx, func(context.Context) error { server = o.c.Data.Server.Clone(); return nil }); err != nil {
		return err
	}
	if server.Address == nil {
		return o.fail(f, "No hook has set a response and there is no upstream server.")
	}
	if o.c.Server == nil && o.c.ServerPackets == nil {
		if err := o.open(server); err != nil {
			return o.fail(f, err.Error())
		}
	}
	return o.send(request, false)
}

func (o *owner) open(server *connection.Server) error {
	var actual *connection.Server
	if server.TransportProtocol == connection.UDP {
		if o.c.OpenPackets == nil || o.c.RecordPackets == nil {
			return errors.New("dnslayer: no upstream packet opener")
		}
		packets, metadata, err := o.c.OpenPackets(o.ctx, server)
		if err != nil {
			return err
		}
		o.c.ServerPackets, actual = o.c.RecordPackets(packets), metadata
	} else {
		if o.c.Pool == nil || o.c.Record == nil {
			return errors.New("dnslayer: no upstream stream pool")
		}
		stream, metadata, err := o.c.Pool.Open(o.ctx, server, layer.OpenOptions{Reuse: true})
		if err != nil {
			return err
		}
		o.c.Server, actual = o.c.Record(stream), metadata
	}
	if err := o.c.Do(o.ctx, func(context.Context) error {
		o.c.Data.Server = actual
		for _, f := range o.flows {
			f.ServerConn = actual
		}
		return nil
	}); err != nil {
		return err
	}
	o.startServerReader()
	return nil
}

func (o *owner) response(f *flow.DNSFlow, msg *dns.Message) error {
	snap, err := o.c.Hooks.FireFunc(o.ctx, func(context.Context) error { f.Response = msg; return nil }, addon.DNSResponseHook{Flow: f})
	if err != nil {
		return err
	}
	if snap != nil && snap.Killed() {
		return errors.New(flow.KilledMessage) //nolint:staticcheck // Preserve the upstream flow-killed diagnostic.
	}
	_, response, _, err := o.snapshot(f)
	if err != nil || response == nil {
		return err
	}
	return o.send(response, true)
}

func (o *owner) fail(f *flow.DNSFlow, reason string) error {
	snap, err := o.c.Hooks.FireFunc(o.ctx, func(context.Context) error { f.Error = flow.NewError(reason); return nil }, addon.DNSErrorHook{Flow: f})
	if err != nil {
		return err
	}
	if snap != nil && snap.Killed() {
		return errors.New(flow.KilledMessage) //nolint:staticcheck // Preserve the upstream flow-killed diagnostic.
	}
	request, _, _, err := o.snapshot(f)
	if err != nil {
		return err
	}
	if request == nil {
		return errors.New("dnslayer: error hook removed the DNS request")
	}
	response, err := request.Fail(dns.ResponseCodeSERVFAIL)
	if err != nil {
		return err
	}
	return o.send(response, true)
}

func (o *owner) snapshot(f *flow.DNSFlow) (request, response *dns.Message, problem string, err error) {
	err = o.c.Do(o.ctx, func(context.Context) error {
		if f.Request != nil {
			request = f.Request.Clone()
		}
		if f.Response != nil {
			response = f.Response.Clone()
		}
		if f.Error != nil {
			problem = f.Error.Msg
		}
		return nil
	})
	return request, response, problem, err
}

func (o *owner) send(msg *dns.Message, toClient bool) error {
	wire, err := dns.Pack(msg)
	if err != nil {
		return err
	}
	stream, packets := o.c.Server, o.c.ServerPackets
	if toClient {
		stream, packets = o.c.Client, o.c.ClientPackets
	}
	if packets != nil {
		n, err := packets.WriteTo(wire, packets.RemoteAddr())
		if err == nil && n != len(wire) {
			err = io.ErrShortWrite
		}
		return err
	}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(wire)))
	for _, data := range [][]byte{prefix[:], wire} {
		for len(data) != 0 {
			n, err := stream.Write(data)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			data = data[n:]
		}
	}
	return nil
}

func (o *owner) now() float64 {
	clock := o.c.Clock
	if clock == nil {
		clock = layer.WallClock
	}
	return float64(clock.Now().UnixNano()) / 1e9
}

func (o *owner) logger() *slog.Logger {
	if o.c.Logger != nil {
		return o.c.Logger
	}
	return slog.Default()
}

func (o *owner) invalid(fromClient bool, cause error) {
	var peer string
	if err := o.c.Do(o.ctx, func(context.Context) error {
		if fromClient {
			peer = o.c.Data.Client.String()
		} else {
			peer = o.c.Data.Server.String()
		}
		return nil
	}); err != nil {
		return
	}
	o.logger().Info(fmt.Sprintf("%s sent an invalid message: %v", peer, cause))
}
