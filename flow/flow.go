// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package flow defines mitmproxy's flows: one HTTP transaction, TCP
// session, UDP session or DNS query together with the client and server
// connections it ran over.
//
// Every flow type implements [Flow]. Its serialised state matches
// mitmproxy's flow format [FormatVersion] key for key, and [FromState]
// builds the right flow type from a state dictionary. Older formats are
// migrated by the flow file reader before they reach this package.
package flow

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow/state"
)

// FormatVersion is the flow format version this package reads and writes.
const FormatVersion = 21

// KilledMessage is the error message of a flow that was killed.
const KilledMessage = "Connection killed."

// ErrNotKillable is returned by Kill for a flow that is not live or was
// already killed.
var ErrNotKillable = errors.New("flow is not killable")

// Flow is implemented by *HTTPFlow, *TCPFlow, *UDPFlow and *DNSFlow.
//
// Flows hold a mutex and must not be copied by value; use [Flow.Copy].
type Flow interface {
	// Common returns the fields every flow type shares.
	Common() *Base
	// Type returns the flow type: "http", "tcp", "udp" or "dns".
	Type() string
	// TimestampStart returns when the flow started: the request's start
	// for HTTP flows and the client connection's start otherwise.
	TimestampStart() float64
	// GetState returns the flow's serialised state. Byte values in it may
	// share memory with the flow; copy the state with state.CopyMap before
	// modifying either.
	GetState() *state.Map
	// SetState replaces the flow's fields with those in the state,
	// consuming it. On error the flow is left unchanged. The client and
	// server connection objects are updated in place, so references to
	// them stay valid.
	SetState(m *state.Map) error
	// Copy returns an independent copy of the flow with a new ID. The
	// copy is not live.
	Copy() Flow
	// Backup saves the current state so that Revert can restore it. It
	// does nothing when a backup already exists.
	Backup()
	// Revert restores the state saved by Backup and drops the backup. It
	// does nothing when there is no backup.
	Revert() error
	// Modified reports whether the flow differs from its backup.
	Modified() bool
}

// Error is an error that affected a flow outside normal protocol
// communication, such as an interrupted connection, a timeout or a
// protocol violation. An HTTP error response is not an Error.
type Error struct {
	// Msg describes the error.
	Msg string
	// Timestamp is when the error happened.
	Timestamp float64
}

// NewError returns an Error that happened now.
func NewError(msg string) *Error {
	return &Error{Msg: msg, Timestamp: state.Now()}
}

// Error returns the message.
func (e *Error) Error() string {
	return e.Msg
}

// GetState returns e's serialised state.
func (e *Error) GetState() *state.Map {
	m := state.NewMap(2)
	m.Set("msg", e.Msg)
	m.Set("timestamp", e.Timestamp)
	return m
}

// ErrorFromState returns an Error built from m, consuming m.
func ErrorFromState(m *state.Map) (*Error, error) {
	d := state.NewDecoder(m, "Error")
	e := &Error{Msg: d.String("msg"), Timestamp: d.Float("timestamp")}
	if err := d.Finish(); err != nil {
		return nil, err
	}
	return e, nil
}

// Base holds the fields every flow type shares. It is embedded in each
// flow type.
type Base struct {
	// ID uniquely identifies the flow.
	ID string
	// ClientConn is the client that connected to the proxy.
	ClientConn *connection.Client
	// ServerConn is the server the proxy connected to. Flows that never
	// open a server connection, for example replayed responses, still
	// have one, with no start timestamp.
	ServerConn *connection.Server
	// Error is a connection or protocol error that affected the flow.
	Error *Error
	// IsReplay is "request" when the proxy replayed the request to the
	// server, "response" when server replay produced the response, and
	// nil otherwise.
	IsReplay *string
	// Marked is a non-empty marker, a character or an emoji name such as
	// ":grapes:", when the user marked the flow.
	Marked string
	// Metadata holds addon data, in insertion order. Values must be state
	// values (see the state package) to survive serialisation.
	Metadata *state.Map
	// Comment is a user comment.
	Comment string
	// TimestampCreated is when the flow was created. Unlike the start
	// timestamp it does not change when the flow is replayed.
	TimestampCreated float64
	// Live reports whether the flow belongs to an active connection. Flows
	// loaded from disk or already completed are not live.
	Live bool

	mu          sync.Mutex
	intercepted bool
	// resume is closed to release WaitForResume callers. It is nil until
	// a caller waits.
	resume chan struct{}
	backup *state.Map
}

func newBase(client *connection.Client, server *connection.Server, live bool) Base {
	return Base{
		ID:               state.NewID(),
		ClientConn:       client,
		ServerConn:       server,
		Metadata:         state.NewMap(0),
		TimestampCreated: state.Now(),
		Live:             live,
	}
}

// Common returns b, so that every flow type satisfies [Flow.Common].
func (b *Base) Common() *Base {
	return b
}

// clientStart is the start timestamp of the client connection, or 0 when
// it is unknown.
func (b *Base) clientStart() float64 {
	if b.ClientConn == nil || b.ClientConn.TimestampStart == nil {
		return 0
	}
	return *b.ClientConn.TimestampStart
}

// Intercepted reports whether the flow is paused, waiting for the user to
// resume or kill it.
func (b *Base) Intercepted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.intercepted
}

// Intercept pauses the flow until Resume or Kill is called.
func (b *Base) Intercept() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.interceptLocked()
}

func (b *Base) interceptLocked() {
	if b.intercepted {
		return
	}
	b.intercepted = true
}

// Resume continues an intercepted flow and releases WaitForResume callers.
func (b *Base) Resume() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.resumeLocked()
}

func (b *Base) resumeLocked() {
	if !b.intercepted {
		return
	}
	b.intercepted = false
	if b.resume != nil {
		close(b.resume)
		b.resume = nil
	}
}

// WaitForResume blocks while the flow is intercepted. It returns nil once
// the flow is resumed or killed, or the context's error when ctx is done
// first.
func (b *Base) WaitForResume(ctx context.Context) error {
	b.mu.Lock()
	if !b.intercepted {
		b.mu.Unlock()
		return nil
	}
	if b.resume == nil {
		b.resume = make(chan struct{})
	}
	ch := b.resume
	b.mu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Killable reports whether the flow can be killed: it is live and has not
// been killed already.
func (b *Base) Killable() bool {
	return b.Live && (b.Error == nil || b.Error.Msg != KilledMessage)
}

// Kill stops the flow: its current message is not forwarded. It sets the
// flow's error to [KilledMessage] and ends interception.
//
// Unlike upstream, Kill also releases WaitForResume callers. Upstream
// leaves a task waiting on a killed intercepted flow blocked until its
// connection is torn down; in Go that would leak the goroutine.
func (b *Base) Kill() error {
	if !b.Killable() {
		return ErrNotKillable
	}
	b.Error = NewError(KilledMessage)
	b.Live = false
	b.Resume()
	return nil
}

// putState writes the shared keys, from version to backup, in upstream's
// order.
func (b *Base) putState(m *state.Map, typ string) {
	m.Set("version", int64(FormatVersion))
	m.Set("type", typ)
	m.Set("id", b.ID)
	if b.Error != nil {
		m.Set("error", b.Error.GetState())
	} else {
		m.Set("error", nil)
	}
	m.Set("client_conn", b.client().GetState())
	m.Set("server_conn", b.server().GetState())
	m.Set("intercepted", b.Intercepted())
	m.Set("is_replay", state.Opt(b.IsReplay))
	m.Set("marked", b.Marked)
	metadata := state.CopyMap(b.Metadata)
	if metadata == nil {
		metadata = state.NewMap(0)
	}
	m.Set("metadata", metadata)
	m.Set("comment", b.Comment)
	m.Set("timestamp_created", b.TimestampCreated)
	b.mu.Lock()
	backup := state.CopyMap(b.backup)
	b.mu.Unlock()
	m.Set("backup", state.OptDict(backup))
}

func (b *Base) client() *connection.Client {
	if b.ClientConn == nil {
		return &connection.Client{}
	}
	return b.ClientConn
}

func (b *Base) server() *connection.Server {
	if b.ServerConn == nil {
		return &connection.Server{}
	}
	return b.ServerConn
}

// baseState is the decoded shared state, kept apart until the whole flow
// state has decoded so that a failed SetState changes nothing.
type baseState struct {
	id               string
	err              *Error
	client           connection.Client
	server           connection.Server
	intercepted      bool
	isReplay         *string
	marked           string
	metadata         *state.Map
	comment          string
	timestampCreated float64
	backup           *state.Map
}

// readState decodes the shared keys for a flow of type typ.
func (b *Base) readState(d *state.Decoder, typ string) *baseState {
	var s baseState
	if v := d.Int("version"); d.Err() == nil && v != FormatVersion {
		d.Fail(fmt.Errorf("flow format version %d, expected %d", v, FormatVersion))
	}
	if t := d.String("type"); d.Err() == nil && t != typ {
		d.Fail(fmt.Errorf("flow type %q, expected %q", t, typ))
	}
	s.id = d.String("id")
	if e := d.OptDict("error"); e != nil {
		var err error
		if s.err, err = ErrorFromState(e); err != nil {
			d.Fail(fmt.Errorf("field %q: %w", "error", err))
		}
	}
	if c := d.Dict("client_conn"); c != nil {
		s.client.State = b.client().State
		if err := s.client.SetState(c); err != nil {
			d.Fail(fmt.Errorf("field %q: %w", "client_conn", err))
		}
	}
	if c := d.Dict("server_conn"); c != nil {
		s.server.State = b.server().State
		if err := s.server.SetState(c); err != nil {
			d.Fail(fmt.Errorf("field %q: %w", "server_conn", err))
		}
	}
	s.intercepted = d.Bool("intercepted")
	s.isReplay = d.OptString("is_replay")
	s.marked = d.String("marked")
	s.metadata = d.Dict("metadata")
	s.comment = d.String("comment")
	s.timestampCreated = d.Float("timestamp_created")
	// Upstream reads backup with a default and stores it unvalidated.
	if d.Has("backup") {
		if v := d.Any("backup"); v != nil {
			bk, err := state.AsDict(v)
			if err != nil {
				d.Fail(fmt.Errorf("field %q: %w", "backup", err))
			}
			s.backup = bk
		}
	}
	return &s
}

// apply commits decoded shared state. Connections are updated in place.
func (b *Base) apply(s *baseState) {
	b.ID = s.id
	b.Error = s.err
	if b.ClientConn == nil {
		b.ClientConn = &connection.Client{}
	}
	*b.ClientConn = s.client
	if b.ServerConn == nil {
		b.ServerConn = &connection.Server{}
	}
	*b.ServerConn = s.server
	b.IsReplay = s.isReplay
	b.Marked = s.marked
	b.Metadata = s.metadata
	b.Comment = s.comment
	b.TimestampCreated = s.timestampCreated
	b.mu.Lock()
	defer b.mu.Unlock()
	b.backup = s.backup
	// Restoring an intercepted state pauses the flow and restoring a
	// non-intercepted one resumes it, so that waiters are never stranded
	// on a flow that no longer reports itself as intercepted.
	if s.intercepted {
		b.interceptLocked()
	} else {
		b.resumeLocked()
	}
}

// backupFrom saves a deep copy of the current state unless a backup
// exists. The copy keeps later in-place edits of byte slices out of it.
func (b *Base) backupFrom(f Flow) {
	b.mu.Lock()
	has := b.backup != nil
	b.mu.Unlock()
	if has {
		return
	}
	snapshot := state.CopyMap(f.GetState())
	b.mu.Lock()
	if b.backup == nil {
		b.backup = snapshot
	}
	b.mu.Unlock()
}

// revert restores f from the backup and drops it.
func (b *Base) revert(f Flow) error {
	b.mu.Lock()
	bk := state.CopyMap(b.backup)
	b.mu.Unlock()
	if bk == nil {
		return nil
	}
	if err := f.SetState(bk); err != nil {
		return err
	}
	b.mu.Lock()
	b.backup = nil
	b.mu.Unlock()
	return nil
}

// modified compares the backup with f's current state as Python's != does.
func (b *Base) modified(f Flow) bool {
	b.mu.Lock()
	has := b.backup != nil
	b.mu.Unlock()
	if !has {
		return false
	}
	current := f.GetState()
	b.mu.Lock()
	defer b.mu.Unlock()
	return !state.Equal(b.backup, current)
}

// copyFlow implements Copy: the state with a fresh ID, decoded into a new
// flow that is not live.
func copyFlow(f Flow) Flow {
	s := state.CopyMap(f.GetState())
	s.Set("id", state.NewID())
	c, err := FromState(s)
	if err != nil {
		// A flow's own state always decodes; failure means a bug in a
		// GetState or SetState implementation.
		panic(fmt.Sprintf("flow: copy of a %s flow failed: %v", f.Type(), err))
	}
	c.Common().Live = false
	return c
}

// FromState builds a flow of the type named by the "type" key, consuming
// m.
func FromState(m *state.Map) (Flow, error) {
	v, _ := m.Get("type")
	typ, _ := v.(string)
	var f Flow
	switch typ {
	case "http":
		f = &HTTPFlow{}
	case "tcp":
		f = &TCPFlow{}
	case "udp":
		f = &UDPFlow{}
	case "dns":
		f = &DNSFlow{}
	default:
		return nil, fmt.Errorf("unknown flow type: %v", v)
	}
	if err := f.SetState(m); err != nil {
		return nil, err
	}
	return f, nil
}
