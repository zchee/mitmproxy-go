// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build h2load

package httplayer

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// Accounting observes transport bytes only; the existing framer remains the validator.
// Only a frame header and counters survive a read, never response body data.
type loadPayloadReader struct {
	peer        *loadHTTP2Peer
	source      io.Reader
	header      [9]byte
	headerBytes int
	remaining   int
	padding     int
	padLength   bool
	data        bool
	stream      uint32
	wire        int64
	actual      map[uint32]int64
	progress    map[uint32]int64
}

func (r *loadPayloadReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	if n > 0 {
		r.peer.mu.Lock()
		r.account(p[:n])
		r.peer.mu.Unlock()
	}
	return n, err
}

func (r *loadPayloadReader) account(p []byte) {
	for len(p) > 0 {
		if r.headerBytes < len(r.header) {
			n := copy(r.header[r.headerBytes:], p)
			r.headerBytes += n
			r.wire += int64(n)
			p = p[n:]
			if r.headerBytes < len(r.header) {
				continue
			}
			r.remaining = int(r.header[0])<<16 | int(r.header[1])<<8 | int(r.header[2])
			r.stream = binary.BigEndian.Uint32(r.header[5:]) & 0x7fffffff
			r.data = http2.FrameType(r.header[3]) == http2.FrameData
			r.padLength = r.data && http2.Flags(r.header[4]).Has(http2.FlagDataPadded)
			r.padding = 0
		}
		if r.remaining == 0 {
			r.headerBytes = 0
			continue
		}
		if len(p) == 0 {
			break
		}
		if r.padLength {
			r.padding = int(p[0])
			r.padLength = false
			r.remaining--
			r.wire++
			p = p[1:]
			continue
		}
		n := min(len(p), r.remaining)
		payload := min(n, max(r.remaining-r.padding, 0))
		r.wire += int64(n)
		if r.data && payload > 0 {
			r.actual[r.stream] += int64(payload)
			r.progress[r.stream] = r.wire - int64(n-payload)
		}
		r.remaining -= n
		p = p[n:]
		if r.remaining == 0 {
			r.headerBytes = 0
		}
	}
}

type loadTypedCause struct {
	Type    string          `json:"type"`
	Message string          `json:"message"`
	Wrapped *loadTypedCause `json:"wrapped"`
}

func loadCause(err error) *loadTypedCause {
	if err == nil {
		return nil
	}
	return &loadTypedCause{Type: fmt.Sprintf("%T", err), Message: err.Error(), Wrapped: loadCause(errors.Unwrap(err))}
}

type loadPeerSnapshot struct {
	Failure           *loadTypedCause `json:"failure"`
	Done              bool            `json:"done"`
	ReaderStarted     bool            `json:"reader_started"`
	Context           *loadTypedCause `json:"context"`
	ConnectionCredit  int64           `json:"connection_credit"`
	InitialCredit     int64           `json:"initial_credit"`
	StreamCredit      *int64          `json:"stream_credit"`
	ProgressBytes     *int64          `json:"progress_bytes"`
	ActualBytes       *int64          `json:"actual_bytes"`
	LastPayloadOffset *int64          `json:"last_payload_offset"`
	WireBytes         *int64          `json:"wire_bytes"`
}

type loadDirectReceipt struct {
	Phase             string            `json:"phase"`
	Stream            *uint32           `json:"stream"`
	ExpectedBytes     int64             `json:"expected_bytes"`
	ActualBytes       *int64            `json:"actual_bytes"`
	ValidatedBytes    *int64            `json:"validated_bytes"`
	LastPayloadOffset *int64            `json:"last_payload_offset"`
	ElapsedNS         *int64            `json:"elapsed_ns"`
	Outcome           string            `json:"outcome"`
	Cause             *loadTypedCause   `json:"cause"`
	Client            *loadPeerSnapshot `json:"client"`
	Origin            *loadPeerSnapshot `json:"origin"`
}

type loadDirectTerminal struct {
	mu             sync.Mutex
	receipt        loadDirectReceipt
	client, origin *loadHTTP2Peer
	cause          error
	published      bool
	path           string
	root           string
}

func (s *loadDirectTerminal) fail(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cause == nil {
		s.cause = err
	}
}

func loadSnapshotLocked(p *loadHTTP2Peer, stream *uint32) *loadPeerSnapshot {
	if p == nil {
		return nil
	}
	state := &loadPeerSnapshot{Failure: loadCause(p.failure), Context: loadCause(p.ctx.Err()), ConnectionCredit: p.connCredit, InitialCredit: p.initialCredit, ReaderStarted: p.readerStarted}
	select {
	case <-p.done:
		state.Done = true
	default:
	}
	if stream != nil {
		state.ProgressBytes = new(p.received[*stream])
		if credit, ok := p.streamCredit[*stream]; ok {
			state.StreamCredit = new(credit)
		}
		if p.payload != nil {
			state.ActualBytes = new(p.payload.actual[*stream])
			state.LastPayloadOffset = new(p.payload.progress[*stream])
		}
	}
	if p.payload != nil {
		state.WireBytes = new(p.payload.wire)
	}
	return state
}

func (s *loadDirectTerminal) snapshot() loadDirectReceipt {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Failure publication and paired snapshots always acquire client before origin.
	if s.client != nil {
		s.client.mu.Lock()
		defer s.client.mu.Unlock()
	}
	if s.origin != nil {
		s.origin.mu.Lock()
		defer s.origin.mu.Unlock()
	}
	r := s.receipt
	r.Client = loadSnapshotLocked(s.client, r.Stream)
	r.Origin = loadSnapshotLocked(s.origin, r.Stream)
	cause := s.cause
	for _, p := range []*loadHTTP2Peer{s.client, s.origin} {
		if p != nil && p.failure != nil && (cause == nil || errors.Is(cause, context.DeadlineExceeded)) {
			cause = p.failure
			r.Outcome = "protocol-failure"
		}
	}
	r.Cause = loadCause(cause)
	if r.Client != nil {
		r.ActualBytes = r.Client.ActualBytes
		r.ValidatedBytes = r.Client.ProgressBytes
		r.LastPayloadOffset = r.Client.LastPayloadOffset
	}
	return r
}

var loadDirectSidecarSequence atomic.Uint64

func (s *loadDirectTerminal) publish() error {
	r := s.snapshot()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.published {
		return errors.New("direct terminal sidecar already published")
	}
	s.published = true
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return err
	}
	for range 8 {
		name := fmt.Sprintf("direct-terminal-%d-%d-%s.json", os.Getpid(), loadDirectSidecarSequence.Add(1), rand.Text()[:16])
		path := filepath.Join(s.root, name)
		// The privileged producer and unprivileged artifact collector share this file.
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		s.path = file.Name()
		return errors.Join(json.MarshalWrite(file, r), file.Sync(), file.Close())
	}
	return errors.New("direct terminal sidecar name collisions exhausted")
}

func readLoadDirectReceipt(root string) (loadDirectReceipt, error) {
	var receipt loadDirectReceipt
	paths, err := filepath.Glob(filepath.Join(root, "direct-terminal-*.json"))
	if err != nil {
		return receipt, err
	}
	if len(paths) != 1 {
		return receipt, fmt.Errorf("direct sidecar count = %d, want 1", len(paths))
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		return receipt, err
	}
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(data, &fields); err != nil {
		return receipt, err
	}
	for _, name := range []string{"phase", "stream", "expected_bytes", "actual_bytes", "validated_bytes", "last_payload_offset", "elapsed_ns", "outcome", "cause", "client", "origin"} {
		if _, ok := fields[name]; !ok {
			return receipt, fmt.Errorf("direct sidecar missing field %s", name)
		}
	}
	if err := json.Unmarshal(data, &receipt, json.RejectUnknownMembers(true)); err != nil {
		return receipt, err
	}
	if receipt.Phase == "" || receipt.Outcome == "" || receipt.ExpectedBytes <= 0 {
		return receipt, errors.New("incomplete direct sidecar")
	}
	if receipt.Cause != nil && (receipt.Cause.Type == "" || receipt.Cause.Message == "") {
		return receipt, errors.New("direct sidecar lacks typed cause")
	}
	if receipt.Outcome == "success" && (receipt.Cause != nil || receipt.ActualBytes == nil || receipt.ValidatedBytes == nil || *receipt.ActualBytes != receipt.ExpectedBytes || *receipt.ValidatedBytes != receipt.ExpectedBytes) {
		return receipt, errors.New("contradictory successful direct sidecar")
	}
	if receipt.Outcome != "success" && receipt.Cause == nil {
		return receipt, errors.New("failed direct sidecar lacks original cause")
	}
	return receipt, nil
}

type loadDirectOptions struct {
	listen      func() (net.Listener, error)
	clientConn  func(net.Conn) net.Conn
	originConn  func(net.Conn) net.Conn
	response    func(*loadHTTP2Peer, uint32, int64) error
	wait        time.Duration
	beforeClose func(*loadDirectTerminal)
}

func awaitLoadDirect(ctx context.Context, client, origin *loadHTTP2Peer, duration time.Duration) (uint32, bool, error) {
	check := func() error {
		for _, peer := range []*loadHTTP2Peer{client, origin} {
			peer.mu.Lock()
			err := peer.failure
			peer.mu.Unlock()
			if err != nil {
				return err
			}
			select {
			case <-peer.done:
				return errors.New("netem peer ended before measured completion")
			case <-peer.ctx.Done():
				return peer.ctx.Err()
			default:
			}
		}
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case id := <-client.finished:
		return id, true, check()
	case <-client.failed:
	case <-origin.failed:
	case <-client.done:
	case <-origin.done:
	case <-client.ctx.Done():
	case <-origin.ctx.Done():
	case <-ctx.Done():
	case <-timer.C:
		select {
		case id := <-client.finished:
			return id, true, check()
		default:
		}
		return 0, false, check()
	}
	if err := check(); err != nil {
		return 0, false, err
	}
	return 0, false, ctx.Err()
}
