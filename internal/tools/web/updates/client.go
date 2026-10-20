// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package updates

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/filter"
)

const (
	queueCapacity  = 1024
	messageLimit   = 10 << 20
	fragmentLimit  = 1024
	terminalGrace  = 15 * time.Second
	internalReason = "Internal server error."
)

type client struct {
	hub             *Hub
	ws              *gows.Conn
	queue           chan []byte
	wake            chan struct{}
	terminalReady   chan struct{}
	done            chan struct{}
	mu              sync.Mutex
	readMu          sync.Mutex // Extends borrowed-buffer lifetime through copying.
	terminal        bool
	finished        bool
	closeBody       []byte
	terminalAt      time.Time
	peerClosed      bool
	pong            []byte
	pongPending     bool
	highWater       int
	started         uint64
	sent            uint64
	terminalStarted uint64
	outcome         string
	filters         map[string]filter.Expr // Dispatch-owned.
	filterNames     []string
}

func newClient(h *Hub, ws *gows.Conn) *client {
	return &client{hub: h, ws: ws, queue: make(chan []byte, queueCapacity), wake: make(chan struct{}, 1), terminalReady: make(chan struct{}), done: make(chan struct{}), filters: make(map[string]filter.Expr)}
}

func (c *client) signalLocked() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *client) terminate(code gows.CloseCode, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.terminateLocked(gows.AppendCloseBody(nil, code, []byte(reason)))
}

func (c *client) terminateLocked(body []byte) {
	if c.terminal || c.finished {
		return
	}
	c.terminal, c.closeBody, c.terminalAt = true, bytes.Clone(body), time.Now()
	c.outcome = "terminal"
	c.terminalStarted = c.started
	close(c.terminalReady)
	c.signalLocked()
}

func (c *client) enqueue(message []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal || c.finished {
		return
	}
	select {
	case c.queue <- message:
		c.highWater = max(c.highWater, len(c.queue))
		c.signalLocked()
	default:
		c.terminateLocked(gows.AppendCloseBody(nil, gows.CloseInternalServerErr, []byte(internalReason)))
	}
}

func (c *client) abort() {
	c.mu.Lock()
	c.finished = true
	if c.outcome != "close-exchanged" {
		c.outcome = "transport-aborted"
	}
	c.signalLocked()
	c.mu.Unlock()
	// Interrupt a blocked reader without releasing its borrowed buffers, then
	// wait for the application's copy before Abort returns them to the pool.
	_ = c.ws.SetReadDeadline(time.Now())
	c.readMu.Lock()
	_ = c.ws.Abort()
	c.readMu.Unlock()
}

func (c *client) run(ctx context.Context) {
	reader := make(chan error, 1)
	writer := make(chan error, 1)
	var workers sync.WaitGroup
	workers.Go(func() { reader <- c.read() })
	workers.Go(func() { writer <- c.write() })
	defer func() {
		c.mu.Lock()
		outcome, body := c.outcome, bytes.Clone(c.closeBody)
		c.mu.Unlock()
		closeFrame, err := gows.ParseClose(body)
		if err == nil && closeFrame.Code == gows.CloseInternalServerErr && outcome == "transport-aborted" {
			slog.Warn("WebSocket update stream aborted", "local_close_code", 1011, "outcome", outcome)
		}
	}()
	defer workers.Wait()
	defer c.abort()
	terminal := c.terminalReady
	canceled := ctx.Done()
	var timer *time.Timer
	var expires <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	readDone, writeDone := false, false
	for {
		if readDone && writeDone {
			c.mu.Lock()
			if c.peerClosed {
				c.outcome = "close-exchanged"
			} else {
				c.outcome = "close-written"
			}
			c.mu.Unlock()
			return
		}
		select {
		case <-terminal:
			terminal = nil
			c.mu.Lock()
			deadline := c.terminalAt.Add(terminalGrace)
			c.mu.Unlock()
			timer = time.NewTimer(max(time.Until(deadline), 0))
			expires = timer.C
		case err := <-reader:
			reader = nil
			readDone = true
			if err != nil {
				return
			}
		case err := <-writer:
			writer = nil
			writeDone = true
			if err != nil {
				return
			}
		case <-canceled:
			canceled = nil
			c.terminate(gows.CloseGoingAway, "Going away.")
		case <-expires:
			return
		}
	}
}

func (c *client) write() error {
	for {
		c.mu.Lock()
		if c.finished {
			c.mu.Unlock()
			return net.ErrClosed
		}
		if c.terminal {
			body := c.closeBody
			c.mu.Unlock()
			// Backlog is discarded only by this writer, after the current frame.
			for {
				select {
				case <-c.queue:
					continue
				default:
					return c.ws.WriteFrame(gows.OpcodeClose, true, body, false)
				}
			}
		}
		if c.pongPending {
			body := c.pong
			c.pong, c.pongPending = nil, false
			c.mu.Unlock()
			if err := c.ws.WriteFrame(gows.OpcodePong, true, body, false); err != nil {
				return err
			}
			continue
		}
		select {
		case message := <-c.queue:
			c.started++
			// Claiming this frame is linearized with terminal selection. No lock
			// is retained during I/O; overflow may let this one frame finish.
			c.mu.Unlock()
			if err := c.ws.WriteFrame(gows.OpcodeText, true, message, false); err != nil {
				return err
			}
			c.mu.Lock()
			c.sent++
			c.mu.Unlock()
		default:
			c.mu.Unlock()
			<-c.wake
		}
	}
}

func (c *client) read() error {
	var message []byte
	fragments := 0
	for {
		c.readMu.Lock()
		frame, err := c.ws.ReadFrame()
		if err == nil {
			frame.Payload = bytes.Clone(frame.Payload)
		}
		c.readMu.Unlock()
		if err != nil {
			if protocol, ok := errors.AsType[*gows.ProtocolError](err); ok {
				c.terminate(protocol.Code, protocol.Reason)
				return nil
			}
			return err
		}
		switch frame.Header.Opcode {
		case gows.OpcodePing:
			c.mu.Lock()
			if !c.terminal {
				c.pong = bytes.Clone(frame.Payload)
				c.pongPending = true
				c.signalLocked()
			}
			c.mu.Unlock()
			continue
		case gows.OpcodePong:
			continue
		case gows.OpcodeClose:
			c.mu.Lock()
			c.peerClosed = true
			c.terminateLocked(frame.Payload) // Empty stays empty, never reserved 1005.
			c.mu.Unlock()
			return nil
		}
		c.mu.Lock()
		terminal := c.terminal
		c.mu.Unlock()
		if terminal {
			continue
		}
		fragments++
		if fragments > fragmentLimit {
			c.terminate(gows.CloseMessageTooBig, "Too many message fragments.")
			return nil
		}
		c.readMu.Lock()
		payload, complete, err := c.ws.DecodeFrame(frame)
		if err == nil && frame.Compressed {
			payload = bytes.Clone(payload)
		}
		c.readMu.Unlock()
		if err != nil {
			if protocol, ok := errors.AsType[*gows.ProtocolError](err); ok {
				c.terminate(protocol.Code, protocol.Reason)
				return nil
			}
			return err
		}
		if len(payload) > messageLimit-len(message) {
			c.terminate(gows.CloseMessageTooBig, "Message too big.")
			return nil
		}
		message = append(message, payload...)
		if !complete {
			continue
		}
		name, expression, err := parseCommand(message)
		message = message[:0]
		fragments = 0
		var compiled filter.Expr
		if err == nil && expression != "" {
			compiled, err = filter.Parse(expression)
		}
		if err == nil {
			err = c.hub.cfg.Master.Do(context.Background(), func(context.Context) error {
				c.mu.Lock()
				active := !c.terminal && !c.finished
				c.mu.Unlock()
				if active && !c.hub.closed {
					c.updateFilter(name, compiled)
				}
				return nil
			})
		}
		if err != nil {
			c.terminate(gows.CloseInternalServerErr, internalReason)
		}
	}
}

func parseCommand(body []byte) (string, string, error) {
	invalid := errors.New("updates: invalid command")
	if len(body) > messageLimit {
		return "", "", invalid
	}
	var envelope map[string]jsontext.Value
	if json.Unmarshal(body, &envelope, jsontext.AllowDuplicateNames(true)) != nil || envelope == nil {
		return "", "", invalid
	}
	var kind string
	if json.Unmarshal(envelope["type"], &kind) != nil || kind != "flows/updateFilter" {
		return "", "", invalid
	}
	var payload map[string]jsontext.Value
	if json.Unmarshal(envelope["payload"], &payload, jsontext.AllowDuplicateNames(true)) != nil || payload == nil {
		return "", "", invalid
	}
	nameRaw, hasName := payload["name"]
	exprRaw, hasExpr := payload["expr"]
	var name, expr string
	if !hasName || !hasExpr || json.Unmarshal(nameRaw, &name) != nil || json.Unmarshal(exprRaw, &expr) != nil {
		return "", "", invalid
	}
	return name, expr, nil
}

func (c *client) updateFilter(name string, expression filter.Expr) {
	var ids any = jsontext.Value("null")
	if expression == nil {
		delete(c.filters, name)
		c.filterNames = slices.DeleteFunc(c.filterNames, func(existing string) bool { return existing == name })
	} else {
		if _, exists := c.filters[name]; !exists {
			c.filterNames = append(c.filterNames, name)
		}
		c.filters[name] = expression
		matches := make([]string, 0)
		for _, f := range c.hub.cfg.View.Flows() {
			if filter.Match(expression, f) {
				matches = append(matches, f.Common().ID)
			}
		}
		ids = matches
	}
	c.send("flows/filterUpdate", map[string]any{"name": name, "matching_flow_ids": ids})
}
