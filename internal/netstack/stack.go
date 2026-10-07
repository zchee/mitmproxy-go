// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

var (
	// ErrStackClosed reports injection into a stopped stack and wraps net.ErrClosed.
	ErrStackClosed = fmt.Errorf("IP stack closed: %w", net.ErrClosed)
	// ErrInvalidPacket reports a structurally invalid or oversized IP packet.
	ErrInvalidPacket = errors.New("invalid IP packet")
	// ErrQueueFull reports exhaustion of the bounded packet admission queue.
	ErrQueueFull = errors.New("IP packet admission queue full")
)

type inboundPacket struct {
	bytes     []byte
	extraInfo map[string]any
}

// Stack owns an arbitrary-destination IP engine and its bounded packet and accept queues.
// Methods are safe for concurrent use. Call Close to release its workers and endpoints.
// Cancellation of the constructor context also shuts the stack down.
type Stack struct {
	ctx    context.Context
	cancel context.CancelFunc
	engine *ipEngine
	input  chan inboundPacket
	output chan []byte
	tcp    chan *Stream
	udp    chan layer.PacketTransport
	mu     sync.RWMutex
	closed bool
	done   chan struct{}
}

// New creates an IPv4/IPv6 stack. It returns an error if engine initialization fails.
// The caller owns the stack and must close it when its packet source stops.
func New(ctx context.Context) (*Stack, error) {
	return newStack(ctx, nil)
}

// Inject copies an IP packet and its optional tunnel metadata before returning.
// Metadata uses the upstream keys: original_src/original_dst (netip.AddrPort),
// pid (uint32), process_name/remote_endpoint (string). Nil metadata is allowed.
// Admission never waits for a packet or flow consumer. Errors match ErrStackClosed,
// ErrInvalidPacket or ErrQueueFull. Malformed transport payloads are discarded by
// the network engine without creating a connection.
func (s *Stack) Inject(packet []byte, extraInfo map[string]any) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.ctx.Err() != nil {
		return ErrStackClosed
	}
	packet, err := checkedIPPacket(packet)
	if err != nil {
		return err
	}
	info, err := copyExtraInfo(extraInfo)
	if err != nil {
		return fmt.Errorf("packet metadata: %w", ErrInvalidPacket)
	}
	p := inboundPacket{bytes: slices.Clone(packet), extraInfo: info}
	select {
	case s.input <- p:
		return nil
	default:
		return ErrQueueFull
	}
}

// Outbound returns raw IP packets ready for reinjection. The receiver owns each slice.
// The bounded queue drops packets if the consumer stalls; no stream waits for it.
// The channel closes when the stack stops.
func (s *Stack) Outbound() <-chan []byte { return s.output }

// TCPConns returns accepted TCP streams after their handshake completes.
// The receiver owns each stream. The channel closes when the stack stops.
func (s *Stack) TCPConns() <-chan *Stream { return s.tcp }

// UDPConns returns independently owned transports for fixed IP/port tuples.
// Each dynamic transport also implements GetExtraInfo(string) (any, bool).
// The channel closes when the stack stops.
func (s *Stack) UDPConns() <-chan layer.PacketTransport { return s.udp }

// Close idempotently stops admission, cancels tuples, joins workers and closes queues.
func (s *Stack) Close() error {
	s.cancel()
	<-s.done
	return nil
}

func (s *Stack) run() {
	var output sync.WaitGroup
	output.Go(func() {
		for {
			packet := s.engine.readPacket(s.ctx)
			if packet == nil {
				return
			}
			select {
			case s.output <- packet:
			default:
			}
		}
	})
	for {
		select {
		case <-s.ctx.Done():
			s.mu.Lock()
			s.closed = true
			s.mu.Unlock()
			s.engine.close()
			for len(s.input) > 0 {
				<-s.input
			}
			output.Wait()
			close(s.output)
			close(s.tcp)
			close(s.udp)
			close(s.done)
			return
		case packet := <-s.input:
			if reply := s.engine.inject(packet.bytes); reply != nil {
				select {
				case s.output <- reply:
				default:
				}
			}
		}
	}
}

func copyExtraInfo(info map[string]any) (map[string]any, error) {
	if len(info) > 16 {
		return nil, ErrInvalidPacket
	}
	out := make(map[string]any, len(info))
	bytes := 0
	for key, value := range info {
		switch key {
		case "original_src", "original_dst":
			if _, ok := value.(netip.AddrPort); !ok {
				return nil, ErrInvalidPacket
			}
		case "pid":
			if _, ok := value.(uint32); !ok {
				return nil, ErrInvalidPacket
			}
		case "process_name", "remote_endpoint":
			if _, ok := value.(string); !ok {
				return nil, ErrInvalidPacket
			}
		}
		bytes += len(key)
		switch v := value.(type) {
		case nil, bool, int, uint32, uint64, netip.Addr, netip.AddrPort:
			out[key] = v
		case string:
			bytes += len(v)
			out[key] = v
		case []byte:
			bytes += len(v)
			if bytes > 65536 {
				return nil, ErrInvalidPacket
			}
			out[key] = slices.Clone(v)
		default:
			return nil, ErrInvalidPacket
		}
		if bytes > 65536 {
			return nil, ErrInvalidPacket
		}
	}
	return out, nil
}
