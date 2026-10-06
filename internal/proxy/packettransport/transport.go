// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package packettransport demultiplexes a shared UDP socket into bounded,
// packet-preserving connections. TupleConn is transport state, not a UDP flow.
package packettransport

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// Listener owns a shared socket and demultiplexes its fixed local/remote tuples.
// Closing a TupleConn evicts only that tuple; closing Listener evicts all tuples.
// Its methods may be called concurrently.
type Listener struct {
	mu            sync.Mutex
	socket        net.PacketConn
	ctx           context.Context
	cancel        context.CancelFunc
	tuples        map[string]*TupleConn
	accept        chan *TupleConn
	overflow      chan struct{}
	writes        chan *packetWrite
	readDone      chan struct{}
	writeDone     chan struct{}
	err           error
	queuedPackets int
	queuedBytes   int
	writePackets  int
	writeBytes    int
	active        *packetWrite
	stop          func() bool
}

type packetWrite struct {
	conn    *TupleConn
	payload []byte
	result  chan writeResult
	err     error
}

func (l *Listener) releaseWriteLocked(job *packetWrite) []byte {
	payload := job.payload
	job.payload = nil
	if _, ok := job.conn.pending[job]; ok {
		delete(job.conn.pending, job)
		l.writePackets--
		l.writeBytes -= len(payload)
		job.conn.writePackets--
		job.conn.writeBytes -= len(payload)
	}
	return payload
}

type writeResult struct {
	n   int
	err error
}

// NewListener starts demultiplexing socket and assumes ownership of it.
// Cancellation closes the socket, wakes operations and evicts all tuples.
// socket must be non-nil; each Listener owns exactly one fixed local address.
func NewListener(ctx context.Context, socket net.PacketConn) *Listener {
	ctx, cancel := context.WithCancel(ctx)
	l := &Listener{socket: socket, ctx: ctx, cancel: cancel, tuples: make(map[string]*TupleConn), accept: make(chan *TupleConn, layer.ListenerPacketQueueCapacity), overflow: make(chan struct{}, 1), writes: make(chan *packetWrite, layer.ListenerPacketQueueCapacity), readDone: make(chan struct{}), writeDone: make(chan struct{})}
	l.stop = context.AfterFunc(ctx, func() { l.fail(errors.Join(net.ErrClosed, ctx.Err())) })
	if udp, ok := socket.(*net.UDPConn); ok {
		if err := ConfigureSocketBuffers(udp); err != nil {
			l.fail(errors.Join(net.ErrClosed, err))
		}
	}
	go l.readLoop()
	go l.writeLoop()
	return l
}

// ConfigureSocketBuffers sets receive and send buffers to twice the maximum payload.
// macOS rejects otherwise legal datagrams larger than its default send buffer.
func ConfigureSocketBuffers(socket *net.UDPConn) error {
	if err := socket.SetReadBuffer(2 * layer.MaxUDPPacketBytes); err != nil {
		return err
	}
	return socket.SetWriteBuffer(2 * layer.MaxUDPPacketBytes)
}

// Accept returns the next new tuple, including its first datagram in its queue.
// ctx cancellation stops this accept only. ErrPacketOverflow reports rejected
// tuple admission when the bounded accept queue is full.
func (l *Listener) Accept(ctx context.Context) (*TupleConn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	l.mu.Lock()
	err := l.err
	l.mu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.ctx.Done():
		l.mu.Lock()
		err := l.err
		l.mu.Unlock()
		return nil, errors.Join(net.ErrClosed, l.ctx.Err(), err)
	case <-l.overflow:
		return nil, layer.ErrPacketOverflow
	case conn := <-l.accept:
		return conn, nil
	}
}

// LocalAddr returns the shared listener's address.
func (l *Listener) LocalAddr() net.Addr { return l.socket.LocalAddr() }

// Close stops socket I/O and waits for the listener's workers to release state.
// It is idempotent and does not wait for any flow owner or addon hook.
func (l *Listener) Close() error {
	l.fail(net.ErrClosed)
	l.stop()
	<-l.readDone
	<-l.writeDone
	for {
		select {
		case <-l.accept:
		default:
			return nil
		}
	}
}

func (l *Listener) fail(err error) {
	l.mu.Lock()
	if l.err != nil {
		l.mu.Unlock()
		return
	}
	l.err = err
	for _, conn := range l.tuples {
		l.finishLocked(conn, err)
	}
	l.cancel()
	l.mu.Unlock()
	_ = l.socket.Close()
}

func (l *Listener) readLoop() {
	defer close(l.readDone)
	buf := make([]byte, layer.MaxUDPPacketBytes+1)
	for {
		n, addr, err := l.socket.ReadFrom(buf)
		if err != nil {
			l.fail(errors.Join(net.ErrClosed, err, l.ctx.Err()))
			return
		}
		l.mu.Lock()
		if l.err != nil {
			l.mu.Unlock()
			return
		}
		key := addr.Network() + "\x00" + addr.String()
		conn := l.tuples[key]
		if conn == nil {
			ctx, cancel := context.WithCancelCause(l.ctx)
			conn = &TupleConn{listener: l, key: key, peer: cloneAddr(addr), ctx: ctx, cancel: cancel, wake: make(chan struct{})}
			l.tuples[key] = conn
			select {
			case l.accept <- conn:
			default:
				l.finishLocked(conn, layer.ErrPacketOverflow)
				select {
				case l.overflow <- struct{}{}:
				default:
				}
				l.mu.Unlock()
				continue
			}
		}
		l.enqueueLocked(conn, buf[:n])
		l.mu.Unlock()
	}
}

func (l *Listener) enqueueLocked(conn *TupleConn, payload []byte) bool {
	if conn.err != nil {
		return false
	}
	if len(payload) > layer.MaxUDPPacketBytes || len(conn.packets)+conn.writePackets >= layer.PacketQueueCapacity || conn.bytes+conn.writeBytes+len(payload) > layer.PacketQueueBytes || l.queuedPackets+l.writePackets >= layer.ListenerPacketQueueCapacity || l.queuedBytes+l.writeBytes+len(payload) > layer.ListenerPacketQueueBytes {
		l.finishLocked(conn, layer.ErrPacketOverflow)
		return false
	}
	conn.packets = append(conn.packets, slices.Clone(payload))
	conn.bytes += len(payload)
	l.queuedPackets++
	l.queuedBytes += len(payload)
	conn.notifyLocked()
	return true
}

func (l *Listener) finishLocked(conn *TupleConn, err error) {
	if conn.err != nil {
		return
	}
	conn.err = errors.Join(net.ErrClosed, err)
	l.queuedPackets -= len(conn.packets)
	l.queuedBytes -= conn.bytes
	conn.packets = nil
	conn.bytes = 0
	for job := range conn.pending {
		job.err = conn.err
		l.releaseWriteLocked(job)
	}
	if l.tuples[conn.key] == conn {
		delete(l.tuples, conn.key)
	}
	conn.cancel(conn.err)
	if l.active != nil && l.active.conn == conn {
		_ = l.socket.SetWriteDeadline(time.Now())
	}
	conn.notifyLocked()
}

func (l *Listener) writeLoop() {
	defer close(l.writeDone)
	for {
		select {
		case job := <-l.writes:
			l.mu.Lock()
			err := job.err
			if err == nil {
				err = job.conn.operationErrorLocked(job.conn.writeDeadline)
			}
			payload := l.releaseWriteLocked(job)
			if err == nil {
				err = l.socket.SetWriteDeadline(job.conn.writeDeadline)
			}
			l.active = job
			l.mu.Unlock()
			n := 0
			if err == nil {
				n, err = l.socket.WriteTo(payload, job.conn.peer)
			}
			l.mu.Lock()
			l.active = nil
			if job.conn.err != nil {
				err = job.conn.err
			}
			l.mu.Unlock()
			job.result <- writeResult{n, err}
		case <-l.ctx.Done():
			for {
				select {
				case job := <-l.writes:
					l.mu.Lock()
					l.releaseWriteLocked(job)
					l.mu.Unlock()
					job.result <- writeResult{err: net.ErrClosed}
				default:
					return
				}
			}
		}
	}
}

// TupleConn is an internal packet transport for one fixed local/remote tuple.
// A serialized socket writer applies deadlines only to its current tuple;
// changing another tuple's deadline cannot affect the active socket operation.
// No TCP stream or half-close operations are implemented.
type TupleConn struct {
	listener      *Listener
	key           string
	peer          net.Addr
	ctx           context.Context
	cancel        context.CancelCauseFunc
	packets       [][]byte
	bytes         int
	wake          chan struct{}
	readDeadline  time.Time
	writeDeadline time.Time
	writePackets  int
	writeBytes    int
	pending       map[*packetWrite]struct{}
	err           error
}

var _ layer.PacketTransport = (*TupleConn)(nil)

// Context is canceled when this tuple closes, overflows or the listener ends.
func (c *TupleConn) Context() context.Context { return c.ctx }

// LocalAddr returns the shared socket's fixed local address.
func (c *TupleConn) LocalAddr() net.Addr { return c.listener.LocalAddr() }

// RemoteAddr returns a copy of the tuple's fixed remote address.
func (c *TupleConn) RemoteAddr() net.Addr { return cloneAddr(c.peer) }

// ReadFrom consumes one datagram, including empty payloads. Truncated bytes
// are discarded. Closing, cancellation and deadlines wake blocked reads.
func (c *TupleConn) ReadFrom(p []byte) (int, net.Addr, error) {
	l := c.listener
	for {
		l.mu.Lock()
		if err := c.operationErrorLocked(c.readDeadline); err != nil {
			l.mu.Unlock()
			return 0, nil, err
		}
		if len(c.packets) > 0 {
			packet := c.packets[0]
			c.packets[0] = nil
			c.packets = c.packets[1:]
			c.bytes -= len(packet)
			l.queuedPackets--
			l.queuedBytes -= len(packet)
			l.mu.Unlock()
			return copy(p, packet), c.RemoteAddr(), nil
		}
		wake, deadline := c.wake, c.readDeadline
		l.mu.Unlock()
		waitPacket(wake, c.ctx.Done(), deadline)
	}
}

// WriteTo sends one bounded datagram to the fixed peer. A different addr is an
// error; nil selects the fixed peer. The socket writer is bounded and does not
// retain the caller's buffer after this method returns.
func (c *TupleConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr != nil && (addr.Network() != c.peer.Network() || addr.String() != c.peer.String()) {
		return 0, &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: errors.New("packet peer differs from fixed tuple")}
	}
	l := c.listener
	l.mu.Lock()
	if err := c.operationErrorLocked(c.writeDeadline); err != nil {
		l.mu.Unlock()
		return 0, err
	}
	if len(p) > layer.MaxUDPPacketBytes || len(c.packets)+c.writePackets >= layer.PacketQueueCapacity || c.bytes+c.writeBytes+len(p) > layer.PacketQueueBytes || l.queuedPackets+l.writePackets >= layer.ListenerPacketQueueCapacity || l.queuedBytes+l.writeBytes+len(p) > layer.ListenerPacketQueueBytes {
		l.finishLocked(c, layer.ErrPacketOverflow)
		l.mu.Unlock()
		return 0, layer.ErrPacketOverflow
	}
	job := &packetWrite{conn: c, payload: slices.Clone(p), result: make(chan writeResult, 1)}
	if c.pending == nil {
		c.pending = make(map[*packetWrite]struct{})
	}
	c.pending[job] = struct{}{}
	l.writePackets++
	l.writeBytes += len(p)
	c.writePackets++
	c.writeBytes += len(p)
	select {
	case l.writes <- job:
	default:
		l.finishLocked(c, layer.ErrPacketOverflow)
		l.mu.Unlock()
		return 0, layer.ErrPacketOverflow
	}
	l.mu.Unlock()
	for {
		l.mu.Lock()
		if err := c.operationErrorLocked(c.writeDeadline); err != nil {
			job.err = err
			l.releaseWriteLocked(job)
			l.mu.Unlock()
			return 0, err
		}
		wake, deadline := c.wake, c.writeDeadline
		l.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case result := <-job.result:
			if timer != nil {
				timer.Stop()
			}
			return result.n, result.err
		case <-wake:
		case <-c.ctx.Done():
		case <-timeout:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (c *TupleConn) operationErrorLocked(deadline time.Time) error {
	if c.err != nil {
		return c.err
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return &net.OpError{Op: "packet", Net: "udp", Addr: c.peer, Err: os.ErrDeadlineExceeded}
	}
	return nil
}

func waitPacket(wake, done <-chan struct{}, deadline time.Time) {
	var timer *time.Timer
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		timer = time.NewTimer(time.Until(deadline))
		timeout = timer.C
		defer timer.Stop()
	}
	select {
	case <-wake:
	case <-done:
	case <-timeout:
	}
}

func (c *TupleConn) notifyLocked() { close(c.wake); c.wake = make(chan struct{}) }

// Close evicts this tuple and discards its queued inbound datagrams. It never
// closes the shared listener, and subsequent tuple reuse creates a new flow.
func (c *TupleConn) Close() error {
	c.listener.mu.Lock()
	defer c.listener.mu.Unlock()
	c.listener.finishLocked(c, net.ErrClosed)
	return nil
}

// SetDeadline sets this tuple's read and write deadlines atomically.
func (c *TupleConn) SetDeadline(t time.Time) error {
	c.listener.mu.Lock()
	defer c.listener.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.readDeadline = t
	c.writeDeadline = t
	if l := c.listener; l.active != nil && l.active.conn == c {
		if err := l.socket.SetWriteDeadline(t); err != nil {
			return err
		}
	}
	c.notifyLocked()
	return nil
}

// SetReadDeadline changes only this tuple's read deadline. Zero disables it.
func (c *TupleConn) SetReadDeadline(t time.Time) error {
	c.listener.mu.Lock()
	defer c.listener.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.readDeadline = t
	c.notifyLocked()
	return nil
}

// SetWriteDeadline changes only this tuple's write deadline. Zero disables it.
func (c *TupleConn) SetWriteDeadline(t time.Time) error {
	c.listener.mu.Lock()
	defer c.listener.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.writeDeadline = t
	if l := c.listener; l.active != nil && l.active.conn == c {
		if err := l.socket.SetWriteDeadline(t); err != nil {
			return err
		}
	}
	c.notifyLocked()
	return nil
}

func cloneAddr(addr net.Addr) net.Addr {
	if udp, ok := addr.(*net.UDPAddr); ok {
		clone := *udp
		clone.IP = slices.Clone(udp.IP)
		return &clone
	}
	return addr
}
